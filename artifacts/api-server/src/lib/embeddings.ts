import { createHash } from "node:crypto";
import { scanForPhi } from "./redact";

// ---------------------------------------------------------------------------
// Embedder interface
// ---------------------------------------------------------------------------
//
// The hybrid-search pipeline depends only on this interface. The cloud-aware
// factory in `embedder-config.ts` selects the concrete implementation at boot
// based on EMBEDDING_PROVIDER (featurehash / bedrock / vertex / azure-openai /
// tei). The table schema, the backfill code, and the search code stay
// identical so long as `dim` matches the column type.
//
// Threat model invariant: embeddings are computed from **redacted text only**
// (see `findings_redacted` view + threat_model.md §Info Disclosure). The
// `PhiGuardEmbedder` wrapper enforces this in code so a future caller cannot
// accidentally embed raw evidence — it is always wrapped around the inner
// embedder by `createEmbedder` regardless of provider.
export interface Embedder {
  readonly version: string;
  readonly dim: number;
  embed(text: string): Promise<number[]>;
}

// ---------------------------------------------------------------------------
// FeatureHashEmbedder — dev / Replit default
// ---------------------------------------------------------------------------
//
// A deterministic feature-hashing embedder ("hashing trick"). For every
// (lowercased) word token and character trigram in the input, we compute a
// stable hash, fold it into a fixed-dim bucket, and ±1-weight it based on a
// secondary hash bit. The resulting vector is L2-normalized.
//
// Properties this gives us:
//   - Deterministic (same text → same vector across processes and restarts).
//   - Cheap (no network, no model load).
//   - Cosine similarity ≈ Jaccard-ish similarity over shared tokens/trigrams.
//   - No semantic generalization (synonyms don't match) — that's why FTS is
//     half of the hybrid: BM25 does literal lexical matching, the vector
//     half adds fuzzy-token / sub-word overlap. In production, the vector
//     half does the heavy semantic lifting (Bedrock/Vertex/Azure/TEI).
//
// The embedder version string encodes the dim so a dim change forces a
// re-embed via the existing `embedder_version` check in backfill.
export class FeatureHashEmbedder implements Embedder {
  readonly version: string;
  readonly dim: number;

  constructor(opts: { dim?: number } = {}) {
    this.dim = opts.dim ?? 256;
    this.version = `featurehash-v1@dev:${this.dim}`;
  }

  async embed(text: string): Promise<number[]> {
    const vec = new Float64Array(this.dim);
    const cleaned = text.toLowerCase();

    // Word tokens.
    const tokens = cleaned.match(/[a-z0-9_]+/g) ?? [];
    for (const tok of tokens) this.addFeature(vec, `w:${tok}`, 1.0);

    // Character trigrams over the cleaned text (with sentinels so the
    // boundary trigrams carry signal too).
    const padded = ` ${cleaned} `;
    for (let i = 0; i + 3 <= padded.length; i++) {
      const tri = padded.slice(i, i + 3);
      this.addFeature(vec, `t:${tri}`, 0.5);
    }

    // L2 normalize so cosine similarity is well-defined and bounded in [-1,1].
    let sumSq = 0;
    for (let i = 0; i < this.dim; i++) sumSq += vec[i]! * vec[i]!;
    const norm = Math.sqrt(sumSq);
    const out = new Array<number>(this.dim);
    if (norm === 0) {
      // Degenerate case (empty/whitespace input). Return zero vector.
      for (let i = 0; i < this.dim; i++) out[i] = 0;
      return out;
    }
    for (let i = 0; i < this.dim; i++) out[i] = vec[i]! / norm;
    return out;
  }

  private addFeature(vec: Float64Array, feature: string, weight: number): void {
    // Use SHA-256 for stable, well-distributed bucketing across Node versions.
    const h = createHash("sha256").update(feature).digest();
    // First 4 bytes → bucket index; next byte's low bit → sign.
    const bucket =
      ((h[0]! << 24) | (h[1]! << 16) | (h[2]! << 8) | h[3]!) >>> 0;
    const sign = (h[4]! & 1) === 0 ? 1 : -1;
    vec[bucket % this.dim]! += sign * weight;
  }
}

// ---------------------------------------------------------------------------
// PhiGuardEmbedder — defense-in-depth wrapper
// ---------------------------------------------------------------------------
//
// Refuses to embed any text containing PHI/PII/secrets per scanForPhi. The
// pipeline already feeds redacted text only, but a future caller could
// regress this — the guard turns that regression into an immediate test
// failure / route error rather than silently storing PHI-derived vectors.
//
// Threat model: pgvector is a searchable hot tier; PHI MUST NOT land here.
// Applied to every provider (cloud or local) by `createEmbedder` —
// outbound text to Bedrock/Vertex/Azure/TEI is *also* PHI-scanned before
// being shipped over the wire (defense against accidental disclosure to a
// third-party model endpoint).
export class PhiGuardEmbedder implements Embedder {
  readonly version: string;
  readonly dim: number;

  constructor(private readonly inner: Embedder) {
    this.version = `phi-guard+${inner.version}`;
    this.dim = inner.dim;
  }

  async embed(text: string): Promise<number[]> {
    const hits = scanForPhi(text);
    if (hits.length > 0) {
      throw new Error(
        `PhiGuardEmbedder: refusing to embed text with ${hits.length} ` +
          `PHI/PII/secret hit(s) (detectors: ${hits.map((h) => h.detector).join(",")}). ` +
          `Embeddings must be computed from redacted text only.`,
      );
    }
    return this.inner.embed(text);
  }
}

// pgvector wire format. The driver accepts a string of the form "[0.1,0.2,…]"
// cast to `vector`; this serializer keeps the precision compact and ASCII.
//
// SAFETY: `Number.prototype.toFixed` on a finite Number always returns
// `/^-?[0-9]+(\.[0-9]+)?$/` — no SQL metacharacters can be produced. Non-finite
// inputs are coerced to "0". We additionally validate the final string against
// a strict allow-list before returning so any future refactor that breaks the
// invariant fails loudly instead of silently enabling SQL injection through
// the `${literal}::vector` interpolation in search.ts.
const VECTOR_LITERAL_RE = /^\[-?[0-9]+(\.[0-9]+)?(,-?[0-9]+(\.[0-9]+)?)*\]$/;

export function toPgVectorLiteral(v: readonly number[]): string {
  const out = `[${v.map((x) => (Number.isFinite(x) ? x.toFixed(6) : "0")).join(",")}]`;
  if (!VECTOR_LITERAL_RE.test(out)) {
    throw new Error("toPgVectorLiteral: produced non-numeric literal (refusing to interpolate)");
  }
  return out;
}
