// Type declarations for the pure-ESM nightly Temporal integration-gate notifier
// (temporal-notify.mjs). The runtime module must stay plain ESM so the GitHub
// Actions workflow can run it with `node` directly; these types let the TS unit
// test import it.

import type { SendResult, Severity } from "./notify.d.mts";

export function gateName(env?: Record<string, string | undefined>): string;

export function buildTemporalText(opts?: {
  name: string;
  exitCode: number;
  now?: number;
}): string;

export interface TemporalPayload {
  kind: "temporal_integration_failure";
  severity: Severity;
  gateName: string;
  exitCode: number;
  occurredAt: string;
}

export function buildTemporalPayload(opts?: {
  name: string;
  exitCode: number;
  now?: number;
}): TemporalPayload;

export function parseExitCode(argv?: string[]): number;

export interface TemporalNotifyResult {
  skipped: boolean;
  sent: SendResult[];
  severity: Severity;
  exitCode: number;
}

export function notifyTemporalGate(opts?: {
  env?: Record<string, string | undefined>;
  exitCode: number;
  name?: string;
  fetchImpl?: typeof fetch;
  now?: number;
}): Promise<TemporalNotifyResult>;
