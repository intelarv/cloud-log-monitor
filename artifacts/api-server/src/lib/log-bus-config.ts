// Env-driven LogBus selection (mirrors embedder-config.ts / search-config.ts).
//
// Precedence: `LOG_BUS_PROVIDER` explicit > default `memory`. There is NO
// `DEPLOYMENT_TARGET` shortcut — moving log transport onto a real broker is
// always an explicit operational decision (it needs broker addresses), exactly
// like SEARCH_PROVIDER / RAW_EVIDENCE_PROVIDER. With nothing set, the bus is
// the in-process `InMemoryLogBus`, so dev and the credential-free eval gate are
// byte-identical.

import { logger } from "./logger";
import { InMemoryLogBus, logBus, type LogBus } from "./log-bus";
import {
  BrokeredLogBus,
  createKafkaDriver,
  createNatsDriver,
  type KafkaSasl,
  type NatsAuth,
} from "./cloud-log-bus";

export type LogBusProvider = "memory" | "kafka" | "nats";

export type LogBusConfig =
  | { provider: "memory" }
  | {
      provider: "kafka";
      brokers: string[];
      clientId: string;
      groupId: string;
      topic: string;
      ssl: boolean;
      sasl?: KafkaSasl;
    }
  | {
      provider: "nats";
      servers: string[];
      stream: string;
      subject: string;
      durable: string;
      tls: boolean;
      auth?: NatsAuth;
    };

type Env = Record<string, string | undefined>;

function csv(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function boolEnv(raw: string | undefined): boolean {
  if (!raw) return false;
  const v = raw.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

const KAFKA_SASL_MECHANISMS = ["plain", "scram-sha-256", "scram-sha-512"] as const;

/** Parse + validate the LogBus config from env. Throws (never silently falls
 *  back) when a non-default provider is selected but its required env is
 *  missing — matching the embedder/search factories so a misconfigured broker
 *  fails fast at boot instead of silently degrading to in-memory. */
export function loadLogBusConfigFromEnv(env: Env = process.env): LogBusConfig {
  const raw = env["LOG_BUS_PROVIDER"]?.trim().toLowerCase();
  if (!raw || raw === "memory") return { provider: "memory" };

  if (raw === "kafka") {
    const brokers = csv(env["KAFKA_BROKERS"]);
    if (brokers.length === 0) {
      throw new Error("LOG_BUS_PROVIDER=kafka requires KAFKA_BROKERS (CSV)");
    }
    let sasl: KafkaSasl | undefined;
    const mechRaw = env["KAFKA_SASL_MECHANISM"]?.trim().toLowerCase();
    if (mechRaw) {
      if (!(KAFKA_SASL_MECHANISMS as readonly string[]).includes(mechRaw)) {
        throw new Error(
          `KAFKA_SASL_MECHANISM must be one of ${KAFKA_SASL_MECHANISMS.join("|")}`,
        );
      }
      const username = env["KAFKA_SASL_USERNAME"];
      const password = env["KAFKA_SASL_PASSWORD"];
      if (!username || !password) {
        throw new Error(
          "KAFKA_SASL_MECHANISM requires KAFKA_SASL_USERNAME + KAFKA_SASL_PASSWORD",
        );
      }
      sasl = { mechanism: mechRaw as KafkaSasl["mechanism"], username, password };
    }
    return {
      provider: "kafka",
      brokers,
      clientId: env["KAFKA_CLIENT_ID"]?.trim() || "phi-audit",
      groupId: env["KAFKA_CONSUMER_GROUP"]?.trim() || "phi-audit-ingest",
      topic: env["KAFKA_TOPIC"]?.trim() || "raw.logs",
      ssl: boolEnv(env["KAFKA_SSL"]),
      ...(sasl ? { sasl } : {}),
    };
  }

  if (raw === "nats") {
    const servers = csv(env["NATS_SERVERS"]);
    if (servers.length === 0) {
      throw new Error("LOG_BUS_PROVIDER=nats requires NATS_SERVERS (CSV)");
    }
    let auth: NatsAuth | undefined;
    const token = env["NATS_TOKEN"]?.trim();
    const username = env["NATS_USERNAME"]?.trim();
    const password = env["NATS_PASSWORD"]?.trim();
    const credsPath = env["NATS_CREDS"]?.trim();
    if (token) auth = { token };
    else if (credsPath) auth = { credsPath };
    else if (username || password) {
      if (!username || !password) {
        throw new Error("NATS_USERNAME and NATS_PASSWORD must be set together");
      }
      auth = { username, password };
    }
    return {
      provider: "nats",
      servers,
      stream: env["NATS_STREAM"]?.trim() || "RAW_LOGS",
      subject: env["NATS_SUBJECT"]?.trim() || "raw.logs",
      durable: env["NATS_DURABLE"]?.trim() || "phi-audit-ingest",
      tls: boolEnv(env["NATS_TLS"]),
      ...(auth ? { auth } : {}),
    };
  }

  throw new Error(
    `Unknown LOG_BUS_PROVIDER "${raw}" (expected memory|kafka|nats)`,
  );
}

/** Construct a `LogBus` from a parsed config. The brokered impls are inert
 *  until `start()` (no SDK load, no connection at construction). */
export function createLogBus(cfg: LogBusConfig): LogBus {
  switch (cfg.provider) {
    case "memory":
      return new InMemoryLogBus();
    case "kafka":
      return new BrokeredLogBus(
        createKafkaDriver({
          brokers: cfg.brokers,
          clientId: cfg.clientId,
          groupId: cfg.groupId,
          topic: cfg.topic,
          ssl: cfg.ssl,
          ...(cfg.sasl ? { sasl: cfg.sasl } : {}),
        }),
        `kafka(${cfg.topic})`,
      );
    case "nats":
      return new BrokeredLogBus(
        createNatsDriver({
          servers: cfg.servers,
          stream: cfg.stream,
          subject: cfg.subject,
          durable: cfg.durable,
          tls: cfg.tls,
          ...(cfg.auth ? { auth: cfg.auth } : {}),
        }),
        `nats(${cfg.subject})`,
      );
  }
}

// ----- Registry ---------------------------------------------------------

let active: LogBus | null = null;

/** The process-wide bus. Lazily defaults to the in-memory singleton so any
 *  caller (e.g. the admin replay route) works even if boot init was skipped
 *  — preserves the pre-broker behavior exactly. */
export function getLogBus(): LogBus {
  return active ?? logBus;
}

export function setLogBus(bus: LogBus): void {
  active = bus;
}

/** Test-only: clear the registry so each test starts from the default. */
export function resetLogBusForTests(): void {
  active = null;
}

/** Boot entry point: parse env, construct, register, and return the bus.
 *  Does NOT call `start()` — the caller subscribes handlers first, then
 *  starts (so a brokered consume loop sees the registered handler set). */
export function initLogBusFromEnv(env: Env = process.env): LogBus {
  const cfg = loadLogBusConfigFromEnv(env);
  const bus = createLogBus(cfg);
  setLogBus(bus);
  logger.info({ provider: cfg.provider }, "log bus selected");
  return bus;
}
