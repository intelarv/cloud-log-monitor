import type { Embedder } from "./embeddings";

// Aliasing the dynamic import through a variable hides the module specifier
// from the TS static analyzer, so optional cloud SDKs aren't required for
// typecheck. The catch site upgrades a missing dep into a clear runtime error.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

// ---------------------------------------------------------------------------
// Cloud-specific embedder implementations.
//
// Each class is a thin client that:
//   1. Reads its config from the constructor (env parsing happens in
//      embedder-config.ts — these classes do no env access themselves).
//   2. Lazy-loads any heavy SDK dependency the first time `embed()` is called,
//      so dev environments that use FeatureHashEmbedder never pay the import
//      cost and operators in clouds that don't use the SDK don't have to
//      install it.
//   3. Validates that the returned vector's dim matches the configured target
//      dim (cloud APIs sometimes silently ignore the dim parameter on older
//      model versions — explicit check turns that into a loud error).
//
// PHI guard wraps every one of these in createEmbedder — outbound text to a
// third-party model endpoint is PHI-scanned at the wrapper before it ever
// reaches the wire. See threat_model.md §Info Disclosure.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AWS Bedrock — Amazon Titan Text Embeddings v2 (256 / 512 / 1024-dim).
//
// Why this model: BAA-eligible under AWS HIPAA, Matryoshka so 256 native
// matches our column dim, normalize=true means we can compare directly under
// cosine without renormalizing.
//
// Auth: standard AWS SDK credential chain (IRSA on EKS, env, instance role).
// Region: AWS_REGION env or constructor override.
// ---------------------------------------------------------------------------
export class BedrockTitanEmbedder implements Embedder {
  readonly version: string;
  readonly dim: number;
  private clientPromise: Promise<BedrockBindings> | null = null;

  constructor(
    private readonly opts: {
      model: string;
      dim: number;
      region: string;
    },
  ) {
    if (![256, 512, 1024].includes(opts.dim)) {
      throw new Error(
        `Bedrock Titan v2 supports dim ∈ {256, 512, 1024}, got ${opts.dim}`,
      );
    }
    this.dim = opts.dim;
    this.version = `bedrock:${opts.model}:${opts.dim}`;
  }

  private async getClient(): Promise<BedrockBindings> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          // Dynamic import keeps the SDK out of the dev/Replit bundle.
          // Hidden from the static analyzer so missing-dep is a runtime, not
          // typecheck, failure — keeping the SDK truly optional.
          const id = "@aws-sdk/client-bedrock-runtime";
          mod = await loadOptional(id);
        } catch {
          throw new Error(
            "Bedrock embedder selected but @aws-sdk/client-bedrock-runtime " +
              "is not installed. Run: pnpm --filter @workspace/api-server add @aws-sdk/client-bedrock-runtime",
          );
        }
        const client = new mod.BedrockRuntimeClient({ region: this.opts.region });
        return {
          send: (cmd: unknown): Promise<{ body: Uint8Array }> =>
            client.send(cmd) as Promise<{ body: Uint8Array }>,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          InvokeModelCommand: mod.InvokeModelCommand as new (args: any) => unknown,
        };
      })();
    }
    return this.clientPromise;
  }

  async embed(text: string): Promise<number[]> {
    const { send, InvokeModelCommand } = await this.getClient();
    const body = JSON.stringify({
      inputText: text,
      dimensions: this.dim,
      normalize: true,
    });
    const cmd = new InvokeModelCommand({
      modelId: this.opts.model,
      body,
      accept: "application/json",
      contentType: "application/json",
    });
    const resp = await send(cmd);
    const decoded = JSON.parse(Buffer.from(resp.body).toString("utf8")) as {
      embedding: number[];
    };
    if (!Array.isArray(decoded.embedding) || decoded.embedding.length !== this.dim) {
      throw new Error(
        `Bedrock returned ${decoded.embedding?.length ?? 0}-dim vector, expected ${this.dim}`,
      );
    }
    return decoded.embedding;
  }
}

interface BedrockBindings {
  send: (cmd: unknown) => Promise<{ body: Uint8Array }>;
  InvokeModelCommand: new (args: {
    modelId: string;
    body: string;
    accept: string;
    contentType: string;
  }) => unknown;
}

// ---------------------------------------------------------------------------
// GCP Vertex AI — text-embedding-005 / gemini-embedding-001.
//
// Why this model: BAA-eligible under Google Cloud HIPAA, supports Matryoshka
// outputDimensionality for text-embedding-004+ and gemini-embedding-001 so
// the column dim is operator-tunable without retraining.
//
// Auth: Application Default Credentials via google-auth-library (Workload
// Identity on GKE, ADC file in dev, service-account in env).
// ---------------------------------------------------------------------------
export class VertexAIEmbedder implements Embedder {
  readonly version: string;
  readonly dim: number;
  private authPromise: Promise<VertexAuth> | null = null;

  constructor(
    private readonly opts: {
      model: string;
      dim: number;
      project: string;
      location: string;
    },
  ) {
    this.dim = opts.dim;
    this.version = `vertex:${opts.model}:${opts.dim}`;
  }

  private async getAuth(): Promise<VertexAuth> {
    if (!this.authPromise) {
      this.authPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          const id = "google-auth-library";
          mod = await loadOptional(id);
        } catch {
          throw new Error(
            "Vertex embedder selected but google-auth-library is not " +
              "installed. Run: pnpm --filter @workspace/api-server add google-auth-library",
          );
        }
        const auth = new mod.GoogleAuth({
          scopes: ["https://www.googleapis.com/auth/cloud-platform"],
        });
        return {
          getAccessToken: async (): Promise<string> => {
            const t = (await auth.getAccessToken()) as string | null | undefined;
            if (!t) throw new Error("Vertex: failed to obtain access token");
            return t;
          },
        };
      })();
    }
    return this.authPromise;
  }

  async embed(text: string): Promise<number[]> {
    const auth = await this.getAuth();
    const token = await auth.getAccessToken();
    const url =
      `https://${this.opts.location}-aiplatform.googleapis.com/v1/projects/` +
      `${this.opts.project}/locations/${this.opts.location}/publishers/google/models/` +
      `${this.opts.model}:predict`;
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        instances: [{ content: text }],
        parameters: { outputDimensionality: this.dim },
      }),
    });
    if (!resp.ok) {
      throw new Error(
        `Vertex embed failed: ${resp.status} ${await resp.text()}`,
      );
    }
    const json = (await resp.json()) as {
      predictions?: Array<{ embeddings?: { values?: number[] } }>;
    };
    const vec = json.predictions?.[0]?.embeddings?.values;
    if (!vec || vec.length !== this.dim) {
      throw new Error(
        `Vertex returned ${vec?.length ?? 0}-dim vector, expected ${this.dim}`,
      );
    }
    return vec;
  }
}

interface VertexAuth {
  getAccessToken: () => Promise<string>;
}

// ---------------------------------------------------------------------------
// Azure OpenAI — text-embedding-3-small / -3-large via Azure deployment.
//
// Why this model: BAA-eligible under Azure HIPAA, supports `dimensions`
// (Matryoshka) so 256 matches our column dim. Pure fetch — no SDK dep.
//
// Auth: api-key header. Endpoint and deployment name are operator-supplied.
// ---------------------------------------------------------------------------
export class AzureOpenAIEmbedder implements Embedder {
  readonly version: string;
  readonly dim: number;

  constructor(
    private readonly opts: {
      model: string;
      dim: number;
      endpoint: string;
      apiKey: string;
      deployment: string;
      apiVersion: string;
    },
  ) {
    this.dim = opts.dim;
    this.version = `azure-openai:${opts.model}:${opts.dim}`;
  }

  async embed(text: string): Promise<number[]> {
    const base = this.opts.endpoint.replace(/\/$/, "");
    const url =
      `${base}/openai/deployments/${this.opts.deployment}/embeddings?` +
      `api-version=${encodeURIComponent(this.opts.apiVersion)}`;
    // Only text-embedding-3-* models accept `dimensions`; ada-002 rejects it.
    const body: Record<string, unknown> = { input: text };
    if (this.opts.model.startsWith("text-embedding-3")) {
      body["dimensions"] = this.dim;
    }
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "api-key": this.opts.apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new Error(
        `Azure OpenAI embed failed: ${resp.status} ${await resp.text()}`,
      );
    }
    const json = (await resp.json()) as {
      data?: Array<{ embedding?: number[] }>;
    };
    const vec = json.data?.[0]?.embedding;
    if (!vec || vec.length !== this.dim) {
      throw new Error(
        `Azure OpenAI returned ${vec?.length ?? 0}-dim vector, expected ${this.dim}`,
      );
    }
    return vec;
  }
}

// ---------------------------------------------------------------------------
// Hugging Face Text Embeddings Inference (cloud-agnostic, self-hosted).
//
// Why this model: works as a sidecar in any cluster (EKS/GKE/AKS/on-prem).
// The actual embedding model is chosen at TEI server-launch time (e.g.
// nomic-embed-text-v1.5, Qwen3-Embedding-0.6B, embeddinggemma-300m,
// bge-small-en-v1.5). The client just POSTs text and gets a vector back, so
// switching models doesn't touch this code. No PHI leaves the cluster.
//
// Auth: usually none in-cluster; if TEI is behind an auth proxy, set
// TEI_BEARER_TOKEN.
// ---------------------------------------------------------------------------
export class TextEmbeddingsInferenceEmbedder implements Embedder {
  readonly version: string;
  readonly dim: number;

  constructor(
    private readonly opts: {
      endpoint: string;
      dim: number;
      modelName: string; // for the version string only; TEI server picks the actual model
      bearerToken?: string;
    },
  ) {
    this.dim = opts.dim;
    this.version = `tei:${opts.modelName}:${opts.dim}`;
  }

  async embed(text: string): Promise<number[]> {
    const base = this.opts.endpoint.replace(/\/$/, "");
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.opts.bearerToken) {
      headers["Authorization"] = `Bearer ${this.opts.bearerToken}`;
    }
    const resp = await fetch(`${base}/embed`, {
      method: "POST",
      headers,
      body: JSON.stringify({ inputs: text, normalize: true }),
    });
    if (!resp.ok) {
      throw new Error(`TEI embed failed: ${resp.status} ${await resp.text()}`);
    }
    // TEI returns [[...]] (array of vectors, one per input).
    const json = (await resp.json()) as number[][];
    const vec = json[0];
    if (!vec || vec.length !== this.dim) {
      throw new Error(
        `TEI returned ${vec?.length ?? 0}-dim vector, expected ${this.dim} ` +
          `(check the TEI server's model dim matches EMBEDDING_DIM)`,
      );
    }
    return vec;
  }
}
