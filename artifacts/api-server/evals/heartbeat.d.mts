// Type declarations for the pure-ESM eval-gate heartbeat / dead-man's switch
// (heartbeat.mjs). The runtime module must stay plain ESM so a CronJob can run
// it with `node` directly; these types let the TS unit test import it.

import type { SendResult, Severity, Outcome } from "./notify.d.mts";

export const DEFAULT_MAX_AGE_MINUTES: number;

export const DEFAULT_PING_TIMEOUT_MS: number;

export function gateName(env?: Record<string, string | undefined>): string;

export function parseMaxAgeMinutes(env?: Record<string, string | undefined>): number;

export function externalPingUrl(env?: Record<string, string | undefined>): string | null;

export interface ExternalPingConfig {
  configured: boolean;
  valid: boolean;
  url: string | null;
  reason: string | null;
}

export function validateExternalPing(env?: Record<string, string | undefined>): ExternalPingConfig;

export type PingStyle = "healthchecks" | "cronitor";

export type PingStage = "start" | "success" | "fail";

export function pingStyle(env?: Record<string, string | undefined>): PingStyle;

export function buildPingUrl(baseUrl: string, stage?: PingStage, style?: PingStyle): string;

export function parsePingTimeoutMs(env?: Record<string, string | undefined>): number;

export interface PingResult {
  pinged: boolean;
  stage: PingStage;
  skipped?: boolean;
  misconfigured?: boolean;
  reason?: string;
  ok?: boolean;
  status?: number;
  error?: string;
}

export function pingExternalHeartbeat(opts?: {
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  stage?: PingStage;
}): Promise<PingResult>;

export function ageMinutes(lastSuccessAt: string | null | undefined, now?: number): number | null;

export function isStale(
  lastSuccessAt: string | null | undefined,
  maxAgeMinutes: number,
  now?: number,
): boolean;

export function buildHeartbeatText(opts: {
  name: string;
  lastSuccessAt: string | null | undefined;
  maxAgeMinutes: number;
  now?: number;
}): string;

export interface HeartbeatPayload {
  kind: "eval_gate_heartbeat_missing";
  severity: Severity;
  gateName: string;
  lastSuccessAt: string | null;
  ageMinutes: number | null;
  maxAgeMinutes: number;
  occurredAt: string;
}

export function buildHeartbeatPayload(opts: {
  name: string;
  lastSuccessAt: string | null | undefined;
  maxAgeMinutes: number;
  now?: number;
}): HeartbeatPayload;

export interface HeartbeatResult {
  stale: boolean;
  skipped: boolean;
  sent: SendResult[];
  severity: Severity;
  ageMinutes: number | null;
  maxAgeMinutes: number;
}

export function evaluateHeartbeat(opts?: {
  env?: Record<string, string | undefined>;
  name?: string;
  lastSuccessAt?: string | null;
  maxAgeMinutes?: number;
  now?: number;
  fetchImpl?: typeof fetch;
}): Promise<HeartbeatResult>;

export function recordHeartbeat(opts?: {
  env?: Record<string, string | undefined>;
  evalsDir?: string;
  outcome?: Outcome;
  exitCode?: number;
  fetchImpl?: typeof fetch;
}): Promise<{ recorded: boolean; gateName: string; outcome: Outcome; ping: PingResult }>;

export function startHeartbeat(opts?: {
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
}): Promise<{ gateName: string; ping: PingResult }>;

export function checkHeartbeat(opts?: {
  env?: Record<string, string | undefined>;
  now?: number;
  fetchImpl?: typeof fetch;
}): Promise<HeartbeatResult>;
