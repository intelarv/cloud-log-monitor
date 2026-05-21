import { createHash } from "node:crypto";
import type { Actor } from "./schema/ledger";

export const CANARY_TOKEN = "REPLIT_M0_CANARY_TOKEN_a8x42q";
export const GENESIS_PREV_HASH = "0".repeat(64);

export function canonicalJSON(value: unknown): string {
  if (value === null || value === undefined) return JSON.stringify(value ?? null);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(canonicalJSON).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k]))
      .join(",") +
    "}"
  );
}

export interface LedgerInput {
  ts: Date;
  tenantId: string | null;
  actor: Actor;
  eventType: string;
  subjectType?: string;
  subjectId?: string;
  payload: Record<string, unknown>;
}

export function computeLedgerHash(prevHash: string, input: LedgerInput): string {
  const body = {
    ts: input.ts.toISOString(),
    tenant_id: input.tenantId,
    actor: input.actor,
    event_type: input.eventType,
    subject_type: input.subjectType ?? null,
    subject_id: input.subjectId ?? null,
    payload: input.payload,
  };
  return createHash("sha256")
    .update(prevHash)
    .update(canonicalJSON(body))
    .digest("hex");
}
