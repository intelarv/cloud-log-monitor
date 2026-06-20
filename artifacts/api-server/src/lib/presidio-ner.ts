import type { PhiHit } from "./redact";
import { type NerProvider, type NerEntityCategory, nerHit } from "./ner";

// ---------------------------------------------------------------------------
// Presidio Stage-2 NER provider (self-hosted, real open-source model).
//
// The three providers in cloud-ner.ts are cloud SaaS NER endpoints (AWS
// Comprehend / GCP DLP / Azure Language) — they recall the open-class names +
// addresses Stage-1 can't precision-match, but require a cloud account + BAA.
// This provider is the credential-account-free production option the decision
// log (docs/ARCHITECTURE.md §11, Appendix A) names first: Microsoft Presidio,
// a real spaCy/transformer-backed NER engine, reached over HTTP.
//
// Why HTTP, not in-process: a real NER model needs heavyweight Python deps +
// downloaded model weights. Running that in-process would (a) be incompatible
// with this Node/TS service and (b) OOM the dev sandbox — and it must never
// touch the offline eval gate. So Presidio runs as its OWN service (the
// official `presidio-analyzer` container) and this provider is a thin HTTP
// client. No SDK at all — it uses global `fetch` — so there is nothing to
// lazy-load; the only thing that turns it on is `NER_PROVIDER=presidio` +
// `NER_PRESIDIO_ENDPOINT`. The default `none`/NoopNerProvider path is
// untouched, so the credential-free eval gate stays byte-identical.
//
// PHI posture (threat_model §Information Disclosure) is identical to the cloud
// providers: Presidio reads the same already-trust-boundaried log payload the
// Stage-1 detectors see; the returned offsets are masked by the same
// redactInline path; only the redacted projection is persisted. The analyzer
// is operator-hosted (in-cluster / on-prem), so the payload never leaves the
// deployment's trust zone — which is exactly why it can be enabled without a
// cloud BAA. Transport security (TLS to the analyzer) is the operator's
// responsibility, same as the broker/object-store seams.
// ---------------------------------------------------------------------------

/** Presidio Analyzer `/analyze` recognizer-result shape (the fields we use).
 *  Offsets are Python `str` (codepoint) indices into the input text. */
interface PresidioResult {
  entity_type?: string;
  start?: number;
  end?: number;
  score?: number;
}

/** Minimal `fetch` surface, injectable for tests (no network). */
export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}>;

export interface PresidioNerOptions {
  /** Base URL of the Presidio Analyzer service, e.g. http://presidio:3000 */
  endpoint: string;
  /** Analyzer language code (default "en"). */
  language?: string;
  /** Minimum recognizer confidence to keep a span (default 0.5). Presidio
   *  scores 0..1; the threshold is the precision knob for an open-class model. */
  scoreThreshold?: number;
  /** Per-call timeout in ms (default 5000). */
  timeoutMs?: number;
  /** Injectable fetch (tests). Defaults to global fetch. */
  fetchImpl?: FetchLike;
}

/** Presidio entity types → the coarse person/address categories the Stage-1
 *  detectors cannot precision-match. PERSON and LOCATION are Presidio's default
 *  recognizers for those classes; everything else (SSN, email, credit card …)
 *  is already covered by Stage-1 regex, so the merge dedups any overlap. */
function mapPresidioType(t: string | undefined): NerEntityCategory | null {
  if (t === "PERSON") return "person";
  if (t === "LOCATION") return "address";
  return null;
}

/** The entity types we ask the analyzer for — narrowing the request to the two
 *  open-class categories the seam covers keeps cost down and avoids pulling in
 *  identifiers Stage-1 already owns. */
const REQUESTED_ENTITIES = ["PERSON", "LOCATION"] as const;

/** Convert a Python/Presidio codepoint offset to a JS UTF-16 string index.
 *  Presidio indexes by Unicode codepoint (Python `str`); JS `String.slice`
 *  indexes by UTF-16 code unit. They agree for BMP text but diverge once an
 *  astral character (emoji, some CJK-ext) appears, which would mis-slice — and
 *  a mis-sliced PHI span could leave raw bytes unredacted. `codepoints` is the
 *  text expanded to a codepoint array once per call. */
function codepointToUtf16(codepoints: string[], cpIndex: number): number {
  // Clamp defensively; the analyzer should never return out-of-range offsets.
  if (cpIndex <= 0) return 0;
  if (cpIndex >= codepoints.length) {
    return codepoints.join("").length;
  }
  let units = 0;
  for (let i = 0; i < cpIndex; i++) units += codepoints[i]!.length;
  return units;
}

export class PresidioNerProvider implements NerProvider {
  readonly name = "presidio";
  private readonly endpoint: string;
  private readonly language: string;
  private readonly scoreThreshold: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: FetchLike;

  constructor(opts: PresidioNerOptions) {
    // Trim a trailing slash so `${endpoint}/analyze` is well-formed.
    this.endpoint = opts.endpoint.replace(/\/+$/, "");
    this.language = opts.language?.trim() || "en";
    this.scoreThreshold =
      opts.scoreThreshold == null ? 0.5 : opts.scoreThreshold;
    this.timeoutMs = opts.timeoutMs == null ? 5000 : opts.timeoutMs;
    const f = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
    if (!f) {
      throw new Error(
        "NER_PROVIDER=presidio requires a global fetch (Node 18+) or an injected fetchImpl.",
      );
    }
    this.fetchImpl = f;
  }

  async detect(text: string): Promise<PhiHit[]> {
    if (text.length === 0) return [];

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res: Awaited<ReturnType<FetchLike>>;
    try {
      res = await this.fetchImpl(`${this.endpoint}/analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          text,
          language: this.language,
          entities: REQUESTED_ENTITIES,
          score_threshold: this.scoreThreshold,
        }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      // Loud, actionable failure — never a silent plaintext fallback (a silent
      // empty result would let un-redacted names through). The message carries
      // ONLY the endpoint + HTTP status — never the response body: an analyzer
      // error page can echo request-derived content (possibly raw PHI), and
      // this error is logged by the ingest path (`logger.error({ err })`), so
      // echoing the body would write PHI to application logs (threat_model
      // §Information Disclosure: "PHI MUST NOT appear in application logs").
      throw new Error(
        `Presidio analyzer ${this.endpoint}/analyze returned HTTP ${res.status}`,
      );
    }

    const parsed = (await res.json()) as unknown;
    if (!Array.isArray(parsed)) return [];

    const codepoints = Array.from(text);
    const hits: PhiHit[] = [];
    for (const r of parsed as PresidioResult[]) {
      const cat = mapPresidioType(r.entity_type);
      if (!cat || r.start == null || r.end == null) continue;
      if (r.score != null && r.score < this.scoreThreshold) continue;
      const start = codepointToUtf16(codepoints, r.start);
      const end = codepointToUtf16(codepoints, r.end);
      if (end <= start) continue;
      hits.push(nerHit(cat, start, end, text.slice(start, end)));
    }
    return hits;
  }
}
