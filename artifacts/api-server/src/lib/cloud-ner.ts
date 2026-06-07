import type { PhiHit } from "./redact";
import { type NerProvider, nerHit } from "./ner";

// ---------------------------------------------------------------------------
// Cloud Stage-2 NER providers (lazy, optional).
//
// Each provider is a thin client that lazy-loads its cloud SDK the first time
// `detect()` runs — exactly the posture of cloud-embedders.ts / cloud-search.ts.
// A dev or eval environment that uses NoopNerProvider never pays the import
// cost, and an operator who selects a provider but hasn't installed the SDK
// gets a loud, actionable runtime error instead of a silent plaintext fallback.
//
// PHI posture (threat_model §Information Disclosure): NER reads the same
// already-trust-boundaried log payload the Stage-1 detectors see. The text is
// sent to a BAA-eligible cloud NER endpoint (AWS Comprehend / GCP DLP / Azure
// Language under HIPAA), the returned offsets are masked by the same
// redactInline path, and only the redacted projection is ever persisted. Each
// provider maps its native entity types to the coarse person/address categories
// the Stage-1 detectors cannot precision-match; SSN/email/etc. are left to the
// Stage-1 regex (the merge in redact.ts dedups any overlap).
// ---------------------------------------------------------------------------

// Aliasing the dynamic import through a variable hides the specifier from the TS
// static analyzer so these SDKs aren't required for typecheck or the dev bundle.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

// ---------------------------------------------------------------------------
// AWS Comprehend — DetectPiiEntities. BAA-eligible under AWS HIPAA.
// Entity types: NAME, ADDRESS (+ many already covered by Stage-1 regex).
// Offsets are UTF-8 codepoint indices into the input, matching JS string slice.
// ---------------------------------------------------------------------------
export class AwsComprehendNerProvider implements NerProvider {
  readonly name = "aws-comprehend";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private clientPromise: Promise<any> | null = null;

  constructor(
    private readonly opts: { region: string; languageCode: string },
  ) {}

  private async getClient(): Promise<{
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    send: (cmd: unknown) => Promise<any>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    Command: new (input: unknown) => any;
  }> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        let mod: {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ComprehendClient: new (cfg: unknown) => any;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          DetectPiiEntitiesCommand: new (input: unknown) => any;
        };
        try {
          mod = (await loadOptional("@aws-sdk/client-comprehend")) as typeof mod;
        } catch {
          throw new Error(
            "NER_PROVIDER=aws-comprehend requires the optional '@aws-sdk/client-comprehend' dependency. " +
              "Run `pnpm --filter @workspace/api-server add @aws-sdk/client-comprehend`.",
          );
        }
        const client = new mod.ComprehendClient({ region: this.opts.region });
        return {
          send: (cmd: unknown) => client.send(cmd),
          Command: mod.DetectPiiEntitiesCommand,
        };
      })();
    }
    return this.clientPromise;
  }

  async detect(text: string): Promise<PhiHit[]> {
    if (text.length === 0) return [];
    const { send, Command } = await this.getClient();
    const out = await send(
      new Command({ Text: text, LanguageCode: this.opts.languageCode }),
    );
    const hits: PhiHit[] = [];
    for (const e of (out?.Entities ?? []) as Array<{
      Type?: string;
      BeginOffset?: number;
      EndOffset?: number;
    }>) {
      const cat = mapAwsType(e.Type);
      if (!cat || e.BeginOffset == null || e.EndOffset == null) continue;
      hits.push(nerHit(cat, e.BeginOffset, e.EndOffset, text.slice(e.BeginOffset, e.EndOffset)));
    }
    return hits;
  }
}

function mapAwsType(t: string | undefined): "person" | "address" | null {
  if (t === "NAME") return "person";
  if (t === "ADDRESS") return "address";
  return null;
}

// ---------------------------------------------------------------------------
// GCP DLP — inspectContent. BAA-eligible under Google Cloud HIPAA.
// InfoTypes: PERSON_NAME, STREET_ADDRESS. DLP returns byte offsets, which we
// translate to JS string indices.
// ---------------------------------------------------------------------------
export class GcpDlpNerProvider implements NerProvider {
  readonly name = "gcp-dlp";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private clientPromise: Promise<any> | null = null;

  constructor(private readonly opts: { projectId: string }) {}

  private async getClient(): Promise<{
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    inspect: (req: unknown) => Promise<any>;
    parent: string;
  }> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        let mod: {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          DlpServiceClient: new () => any;
        };
        try {
          mod = (await loadOptional("@google-cloud/dlp")) as typeof mod;
        } catch {
          throw new Error(
            "NER_PROVIDER=gcp-dlp requires the optional '@google-cloud/dlp' dependency. " +
              "Run `pnpm --filter @workspace/api-server add @google-cloud/dlp`.",
          );
        }
        const client = new mod.DlpServiceClient();
        return {
          inspect: (req: unknown) => client.inspectContent(req),
          parent: `projects/${this.opts.projectId}/locations/global`,
        };
      })();
    }
    return this.clientPromise;
  }

  async detect(text: string): Promise<PhiHit[]> {
    if (text.length === 0) return [];
    const { inspect, parent } = await this.getClient();
    const [res] = await inspect({
      parent,
      inspectConfig: {
        infoTypes: [{ name: "PERSON_NAME" }, { name: "STREET_ADDRESS" }],
        includeQuote: true,
      },
      item: { value: text },
    });
    const hits: PhiHit[] = [];
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    const bytes = enc.encode(text);
    for (const f of (res?.result?.findings ?? []) as Array<{
      infoType?: { name?: string };
      location?: { byteRange?: { start?: number | string; end?: number | string } };
    }>) {
      const cat = mapGcpType(f.infoType?.name);
      const br = f.location?.byteRange;
      if (!cat || br?.start == null || br?.end == null) continue;
      const bStart = Number(br.start);
      const bEnd = Number(br.end);
      // Byte offsets → string indices via decoding the prefix slices.
      const start = dec.decode(bytes.slice(0, bStart)).length;
      const end = dec.decode(bytes.slice(0, bEnd)).length;
      hits.push(nerHit(cat, start, end, text.slice(start, end)));
    }
    return hits;
  }
}

function mapGcpType(t: string | undefined): "person" | "address" | null {
  if (t === "PERSON_NAME") return "person";
  if (t === "STREET_ADDRESS") return "address";
  return null;
}

// ---------------------------------------------------------------------------
// Azure AI Language — PII recognition. BAA-eligible under Azure HIPAA.
// Categories: Person, Address. Returns character offset + length.
// ---------------------------------------------------------------------------
export class AzureLanguageNerProvider implements NerProvider {
  readonly name = "azure-language";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private clientPromise: Promise<any> | null = null;

  constructor(
    private readonly opts: { endpoint: string; apiKey: string; language: string },
  ) {}

  private async getClient(): Promise<{
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    recognize: (docs: unknown) => Promise<any>;
  }> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        let mod: {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          TextAnalyticsClient: new (endpoint: string, cred: unknown) => any;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          AzureKeyCredential: new (key: string) => any;
        };
        try {
          mod = (await loadOptional("@azure/ai-text-analytics")) as typeof mod;
        } catch {
          throw new Error(
            "NER_PROVIDER=azure-language requires the optional '@azure/ai-text-analytics' dependency. " +
              "Run `pnpm --filter @workspace/api-server add @azure/ai-text-analytics`.",
          );
        }
        const client = new mod.TextAnalyticsClient(
          this.opts.endpoint,
          new mod.AzureKeyCredential(this.opts.apiKey),
        );
        return {
          recognize: (docs: unknown) =>
            client.recognizePiiEntities(docs, this.opts.language),
        };
      })();
    }
    return this.clientPromise;
  }

  async detect(text: string): Promise<PhiHit[]> {
    if (text.length === 0) return [];
    const { recognize } = await this.getClient();
    const results = await recognize([text]);
    const hits: PhiHit[] = [];
    for (const doc of (results ?? []) as Array<{
      error?: unknown;
      entities?: Array<{ category?: string; offset?: number; length?: number }>;
    }>) {
      if (doc.error || !doc.entities) continue;
      for (const e of doc.entities) {
        const cat = mapAzureType(e.category);
        if (!cat || e.offset == null || e.length == null) continue;
        const start = e.offset;
        const end = e.offset + e.length;
        hits.push(nerHit(cat, start, end, text.slice(start, end)));
      }
    }
    return hits;
  }
}

function mapAzureType(t: string | undefined): "person" | "address" | null {
  if (t === "Person") return "person";
  if (t === "Address") return "address";
  return null;
}
