import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ALL_LLM_PROVIDERS,
  createLlmRuntime,
  isLlmProvider,
  loadLlmRuntimeConfigFromEnv,
} from "./llm-runtime-config";
import {
  AzureOpenAILlmRuntime,
  BedrockLlmRuntime,
  PhiGuardLlmRuntime,
  VertexLlmRuntime,
} from "./cloud-llm-runtimes";

describe("loadLlmRuntimeConfigFromEnv", () => {
  it("defaults to gemini-replit with no env", () => {
    const cfg = loadLlmRuntimeConfigFromEnv({});
    expect(cfg.provider).toBe("gemini-replit");
    expect(cfg.defaultModelId).toBeNull();
  });

  it("DEPLOYMENT_TARGET=aws → bedrock + claude haiku default", () => {
    const cfg = loadLlmRuntimeConfigFromEnv({ DEPLOYMENT_TARGET: "aws" });
    expect(cfg.provider).toBe("bedrock");
    expect(cfg.defaultModelId).toMatch(/claude/);
  });

  it("DEPLOYMENT_TARGET=gcp → vertex + gemini default", () => {
    const cfg = loadLlmRuntimeConfigFromEnv({ DEPLOYMENT_TARGET: "gcp" });
    expect(cfg.provider).toBe("vertex");
    expect(cfg.defaultModelId).toBe("gemini-2.5-flash");
  });

  it("DEPLOYMENT_TARGET=azure → azure-openai (no default model — uses deployment name)", () => {
    const cfg = loadLlmRuntimeConfigFromEnv({ DEPLOYMENT_TARGET: "azure" });
    expect(cfg.provider).toBe("azure-openai");
    expect(cfg.defaultModelId).toBeNull();
  });

  it("LLM_PROVIDER wins over DEPLOYMENT_TARGET", () => {
    const cfg = loadLlmRuntimeConfigFromEnv({
      DEPLOYMENT_TARGET: "aws",
      LLM_PROVIDER: "vertex",
    });
    expect(cfg.provider).toBe("vertex");
  });

  it("LLM_DEFAULT_MODEL overrides provider default", () => {
    const cfg = loadLlmRuntimeConfigFromEnv({
      LLM_PROVIDER: "bedrock",
      LLM_DEFAULT_MODEL: "anthropic.claude-3-5-sonnet-20241022-v2:0",
    });
    expect(cfg.defaultModelId).toBe("anthropic.claude-3-5-sonnet-20241022-v2:0");
  });

  it("rejects unknown LLM_PROVIDER", () => {
    expect(() =>
      loadLlmRuntimeConfigFromEnv({ LLM_PROVIDER: "openai-cloud" }),
    ).toThrow(/not a known provider/);
  });

  it("isLlmProvider matches the exported registry", () => {
    for (const p of ALL_LLM_PROVIDERS) expect(isLlmProvider(p)).toBe(true);
    expect(isLlmProvider("nope")).toBe(false);
  });
});

describe("createLlmRuntime", () => {
  it("gemini-replit → null (keeps module default)", () => {
    const rt = createLlmRuntime(
      { provider: "gemini-replit", defaultModelId: null },
      {},
    );
    expect(rt).toBeNull();
  });

  it("bedrock → PhiGuard wrapping BedrockLlmRuntime", () => {
    const rt = createLlmRuntime(
      { provider: "bedrock", defaultModelId: "anthropic.claude-3-5-haiku-20241022-v1:0" },
      { AWS_REGION: "us-west-2" },
    );
    expect(rt).toBeInstanceOf(PhiGuardLlmRuntime);
    // PhiGuard exposes `inner` only as private; we assert via instanceof on
    // the construction path (the constructor only accepts an LlmAgentRuntime).
    expect(rt).toBeTruthy();
  });

  it("vertex requires GCP_PROJECT_ID", () => {
    expect(() =>
      createLlmRuntime({ provider: "vertex", defaultModelId: "gemini-2.5-flash" }, {}),
    ).toThrow(/GCP_PROJECT_ID/);
  });

  it("vertex → PhiGuard wrapping VertexLlmRuntime", () => {
    const rt = createLlmRuntime(
      { provider: "vertex", defaultModelId: "gemini-2.5-flash" },
      { GCP_PROJECT_ID: "p", GCP_LOCATION: "us-central1" },
    );
    expect(rt).toBeInstanceOf(PhiGuardLlmRuntime);
  });

  it("azure-openai requires endpoint + key + deployment", () => {
    expect(() =>
      createLlmRuntime({ provider: "azure-openai", defaultModelId: null }, {}),
    ).toThrow(/AZURE_OPENAI_ENDPOINT/);
  });

  it("azure-openai → PhiGuard wrapping AzureOpenAILlmRuntime", () => {
    const rt = createLlmRuntime(
      { provider: "azure-openai", defaultModelId: null },
      {
        AZURE_OPENAI_ENDPOINT: "https://x.openai.azure.com",
        AZURE_OPENAI_API_KEY: "k",
        AZURE_OPENAI_DEPLOYMENT: "gpt4o",
      },
    );
    expect(rt).toBeInstanceOf(PhiGuardLlmRuntime);
  });
});

describe("PhiGuardLlmRuntime", () => {
  it("refuses to send prompts containing PHI/secrets", async () => {
    let called = false;
    const inner = {
      generate: async () => {
        called = true;
        return { text: "x", approxOutputTokens: 1, modelId: "m" };
      },
    };
    const guarded = new PhiGuardLlmRuntime(inner);
    await expect(
      guarded.generate({
        systemPrompt: "you are a helpful agent",
        userPrompt: "the ssn is 123-45-6789",
        modelId: "m",
      }),
    ).rejects.toThrow(/PHI guard.*ssn/);
    expect(called).toBe(false);
  });

  it("passes clean prompts through", async () => {
    const inner = {
      generate: async () => ({ text: "ok", approxOutputTokens: 2, modelId: "m" }),
    };
    const guarded = new PhiGuardLlmRuntime(inner);
    const out = await guarded.generate({
      systemPrompt: "you are a helpful agent",
      userPrompt: "list critical findings",
      modelId: "m",
    });
    expect(out.text).toBe("ok");
  });
});

describe("VertexLlmRuntime", () => {
  afterEach(() => vi.restoreAllMocks());

  it("POSTs to the regional generateContent endpoint and extracts text + tokens", async () => {
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toContain("us-central1-aiplatform.googleapis.com");
      expect(String(url)).toContain(":generateContent");
      expect(init?.method).toBe("POST");
      const body = JSON.parse(String(init?.body));
      expect(body.contents[0].parts[0].text).toBe("hi");
      return new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: "hello" }] } }],
          usageMetadata: { candidatesTokenCount: 7 },
        }),
        { status: 200 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const rt = new VertexLlmRuntime({
      project: "proj",
      location: "us-central1",
      defaultModelId: "gemini-2.5-flash",
    });
    // Inject a fake auth so the SDK isn't loaded.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (rt as any).authPromise = Promise.resolve({
      getAccessToken: async () => "tok",
    });
    const out = await rt.generate({
      systemPrompt: "sys",
      userPrompt: "hi",
      modelId: "",
    });
    expect(out.text).toBe("hello");
    expect(out.approxOutputTokens).toBe(7);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("AzureOpenAILlmRuntime", () => {
  afterEach(() => vi.restoreAllMocks());

  it("POSTs to the deployment chat/completions endpoint with api-key header", async () => {
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toContain("/openai/deployments/dep/chat/completions");
      expect(String(url)).toContain("api-version=");
      const headers = init?.headers as Record<string, string>;
      expect(headers["api-key"]).toBe("secret-key");
      return new Response(
        JSON.stringify({
          choices: [{ message: { content: "azure-says-hi" } }],
          usage: { completion_tokens: 11 },
        }),
        { status: 200 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const rt = new AzureOpenAILlmRuntime({
      endpoint: "https://x.openai.azure.com",
      apiKey: "secret-key",
      deployment: "dep",
      apiVersion: "2024-08-01-preview",
    });
    const out = await rt.generate({
      systemPrompt: "sys",
      userPrompt: "hi",
      modelId: "",
    });
    expect(out.text).toBe("azure-says-hi");
    expect(out.approxOutputTokens).toBe(11);
  });
});

describe("BedrockLlmRuntime", () => {
  it("builds a Converse command and extracts text + outputTokens", async () => {
    const sendCalls: unknown[] = [];
    const fakeBindings = {
      send: async (cmd: unknown) => {
        sendCalls.push(cmd);
        return {
          output: {
            message: { content: [{ text: "claude-says-hi" }] },
          },
          usage: { outputTokens: 13 },
        };
      },
      ConverseCommand: class {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        constructor(public args: any) {}
      },
    };
    const rt = new BedrockLlmRuntime({
      region: "us-east-1",
      defaultModelId: "anthropic.claude-3-5-haiku-20241022-v1:0",
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (rt as any).clientPromise = Promise.resolve(fakeBindings);
    const out = await rt.generate({
      systemPrompt: "sys",
      userPrompt: "hi",
      modelId: "",
    });
    expect(out.text).toBe("claude-says-hi");
    expect(out.approxOutputTokens).toBe(13);
    expect(sendCalls).toHaveLength(1);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const cmd = sendCalls[0] as any;
    expect(cmd.args.modelId).toBe("anthropic.claude-3-5-haiku-20241022-v1:0");
    expect(cmd.args.system[0].text).toBe("sys");
    expect(cmd.args.messages[0].content[0].text).toBe("hi");
  });

  it("throws clear error when no model id can be resolved", async () => {
    const rt = new BedrockLlmRuntime({ region: "us-east-1" });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (rt as any).clientPromise = Promise.resolve({
      send: async () => ({}),
      ConverseCommand: class {},
    });
    await expect(
      rt.generate({ systemPrompt: "s", userPrompt: "u", modelId: "" }),
    ).rejects.toThrow(/no model id resolved/);
  });

  it("operator default wins over caller's modelId (so Triage's Gemini constant doesn't reach Bedrock)", async () => {
    const sendCalls: unknown[] = [];
    const rt = new BedrockLlmRuntime({
      region: "us-east-1",
      defaultModelId: "anthropic.claude-3-5-haiku-20241022-v1:0",
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (rt as any).clientPromise = Promise.resolve({
      send: async (cmd: unknown) => {
        sendCalls.push(cmd);
        return {
          output: { message: { content: [{ text: "ok" }] } },
          usage: { outputTokens: 3 },
        };
      },
      ConverseCommand: class {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        constructor(public args: any) {}
      },
    });
    const out = await rt.generate({
      systemPrompt: "s",
      userPrompt: "u",
      modelId: "gemini-2.5-flash", // caller hint, should be ignored
    });
    expect(out.modelId).toBe("anthropic.claude-3-5-haiku-20241022-v1:0");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((sendCalls[0] as any).args.modelId).toBe(
      "anthropic.claude-3-5-haiku-20241022-v1:0",
    );
  });
});
