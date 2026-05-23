// Application-level alert emitter.
//
// docs/ARCHITECTURE.md §25 specifies WHICH ledger event types are alertable
// and at what severity; this module is the dev/production hook that turns
// those rules into a structured stderr line. In production a Vector / Fluent
// Bit / OTel log shipper picks up `alert=true` lines and routes them to
// PagerDuty / Slack / Opsgenie per the channel-router rules in §291.
//
// Why structured stderr instead of an in-process PagerDuty client:
//
//   1. Dev has no PagerDuty creds and shouldn't need them — alerts are
//      visible in the workflow log immediately.
//   2. The alerter must not block the ledger write path with a network
//      call; a log line is non-blocking.
//   3. The log scraper is the single chokepoint where prod can apply
//      dedup / throttle / on-call rotation without changing app code.
//
// Severity vocabulary matches PagerDuty Events API v2 so log routing rules
// can be one-to-one. `info` is intentionally absent — anything worth an
// `info` belongs in the ledger only, not the alert stream.

import { logger } from "./logger";
import type { LedgerEntry } from "@workspace/db";

export type AlertSeverity = "critical" | "high" | "warning";

/** Alertable ledger event types and their severities.
 *
 *  Maintenance rule: any NEW ledger event type that represents a
 *  security-relevant condition MUST either be added to this table OR be
 *  explicitly annotated `// not-alertable: <reason>` at the call site of
 *  `appendLedger`. The §25 review checklist enforces this.
 */
export const ALERT_RULES: Record<string, AlertSeverity> = {
  // M0/M1: prompt-injection signal. A canary token appearing in tool args
  // proves an agent acted on attacker-controlled instructions. Critical
  // regardless of which agent triggered it.
  "agent.canary_in_tool_args": "critical",
  // M1.6: any other tool-arg policy violation (oversize, PHI-in-args,
  // malformed id). High — could be benign Zod-bypass or could be a probe.
  "agent.tool_args_policy_violation": "high",
  // M1.7: a user tried to approve their own break-glass grant. Insider
  // threat signal; the rule itself prevented disclosure, but the attempt
  // is a strong indicator. Critical because the attempt implies awareness
  // of the bypass surface.
  "break_glass.approval_denied_self_approval": "critical",
  // M1.7.1: an analyst typed PHI / secrets / canary into a free-text field
  // (justification, approval_note, step-up reason). High — most likely
  // careless analyst, but a hostile insider would look identical until
  // patterns emerge in aggregate.
  "policy.text_field_rejected": "high",
  // M1.6: every break-glass raw-PHI read. Warning (not critical) because
  // these are legitimate by design; the value is in being able to grep
  // the alert stream for "who looked at PHI in the last 24h" without
  // SQL access. Frequency anomalies are detected downstream by the log
  // shipper, not here.
  "break_glass.raw_phi_accessed": "warning",
  // M0: ledger chain mismatch detected at boot. Critical — the integrity
  // claim is dead until resolved. (The boot path already logger.error's
  // and refuses to listen; this rule covers the case where a future
  // periodic verifier finds it post-startup.)
  "ledger.chain_invalid": "critical",
  // M0: analyst typed PHI/secrets directly into the chat input. Same
  // severity rationale as `policy.text_field_rejected` — could be
  // careless, could be hostile, indistinguishable on a single event.
  "chat.input_phi_refused": "high",
  // M0: the LLM produced PHI/secrets in its response and the output scan
  // tripped. Per ARCHITECTURE.md §23.1 this is "a finding about the agent,
  // not a leak" — the safe-refusal path prevented the disclosure, but a
  // model that produces PHI is a model that has either been prompt-injected
  // or has training-data contamination. Either way, critical.
  "agent.output_phi_detected": "critical",
  // M2: an external notarization checkpoint disagreed with the live ledger.
  // Critical — either someone with writer access has rewritten a ledger
  // row a checkpoint pinned (exactly the threat §23.2 second-half exists
  // to detect) OR a checkpoint signature itself was forged. Either is a
  // top-of-page incident.
  "ledger.checkpoint_mismatch": "critical",
  // M3: the ingest pipeline's defense-in-depth rescan found PHI/secrets
  // surviving in a redacted snippet that was about to land in the
  // searchable hot tier. The pipeline falls back to a fully-opaque
  // placeholder before insert so nothing actually leaks, but this means
  // either a detector regex regressed or the redactor walk has a bug —
  // either is a top-of-page incident because subsequent records would
  // leak silently if the fallback weren't there.
  "ingest.redaction_regression": "critical",
  // M3: a log source delivered a record that failed trust-boundary
  // validation (oversized provenance fields, disallowed charset, oversized
  // payload). The record is dropped before processing, but the drop itself
  // is auditable — a misbehaving or compromised log shipper is operationally
  // interesting. Warning, not critical: most occurrences are
  // misconfiguration, not attack; threshold/aggregation lives downstream
  // in the log shipper per §25.
  "ingest.malformed_record": "warning",
} as const;

/** Event types that are legitimately emitted at high volume or as part of a
 *  normal flow and intentionally do NOT alert. Every event type passed to
 *  `appendLedger` must appear in EITHER `ALERT_RULES` or this set — the
 *  §25.4 mechanical guard (see `event-type-coverage.test.ts`) enforces
 *  this so a new ledger event cannot be added without a documented
 *  alerting decision.
 */
export const NOT_ALERTABLE: ReadonlySet<string> = new Set([
  // Per-request chat events — too high-volume to page on; auditable
  // through the ledger.
  "chat.user_turn",
  "chat.agent_turn",
  // Successful step-up — legitimate by definition. (No `auth.login_success`
  // event today — login routes log but don't ledger; if that changes, the
  // §25.4 coverage test will require a decision.)
  "auth.step_up_granted",
  // Single step-up failure — alerted only on threshold (rolling 3/5min).
  "auth.step_up_failed",
  // Legitimate break-glass flow events. The `break_glass.raw_phi_accessed`
  // event IS the security-relevant one (warning-level above); grant +
  // approval are gated by step-up + the two-person rule.
  "break_glass.granted",
  "break_glass.approved",
  // Finding lifecycle — the notifier handles severity-based routing per
  // §291; not in scope of the alert hook.
  "finding.created",
  // Ledger bootstrap. Fires once.
  "ledger.genesis",
  // M2: each successful notarization checkpoint creation. Routine signal
  // (one row per cadence tick when the ledger changes); auditable via the
  // ledger and `GET /api/admin/ledger/checkpoints`. Mismatch is the event
  // worth paging on, not creation.
  "ledger.checkpoint_created",
]);

/** In-memory rolling counters for threshold-based alerts.
 *
 *  Used today only for `auth.step_up_failed`: a single failure is noise
 *  (analyst typo), but ≥3 within 5 minutes from the same actor is a
 *  brute-force signal worth paging on. Per-process state — fine for a
 *  single-instance dev/demo, replaced by Redis or a streaming aggregator
 *  in §25 production deployments.
 */
const STEP_UP_FAIL_WINDOW_MS = 5 * 60 * 1000;
const STEP_UP_FAIL_THRESHOLD = 3;
const stepUpFailures = new Map<string, number[]>();

function recordStepUpFailure(actorKey: string): number {
  const now = Date.now();
  const cutoff = now - STEP_UP_FAIL_WINDOW_MS;
  const arr = (stepUpFailures.get(actorKey) ?? []).filter((t) => t >= cutoff);
  arr.push(now);
  stepUpFailures.set(actorKey, arr);
  return arr.length;
}

/** Emit a structured alert line to stderr.
 *
 *  Payload shape is intentionally flat + small — log shippers pattern-match
 *  on `alert=true` first, then dispatch on `event_type`/`severity`. The
 *  ledger payload itself is NOT included here: it may carry detector names
 *  or finding ids that are safe to log, but anything sensitive lives in
 *  the ledger row and is referenced by `ledger_seq`.
 */
function emitAlert(args: {
  severity: AlertSeverity;
  eventType: string;
  tenantId: string | null;
  ledgerSeq: number;
  ledgerHash: string;
  subjectType?: string | null;
  subjectId?: string | null;
  extra?: Record<string, unknown>;
}): void {
  logger.warn(
    {
      alert: true,
      alert_severity: args.severity,
      event_type: args.eventType,
      tenant_id: args.tenantId,
      ledger_seq: args.ledgerSeq,
      ledger_hash: args.ledgerHash,
      subject_type: args.subjectType ?? null,
      subject_id: args.subjectId ?? null,
      ...args.extra,
    },
    `ALERT ${args.severity}: ${args.eventType}`,
  );
}

/** Hook fired by `appendLedger` after a successful insert. Looks the event
 *  type up in `ALERT_RULES` and emits if matched. For `auth.step_up_failed`
 *  applies the rolling-window threshold (so a single typo doesn't page).
 */
export function maybeEmitAlertFromLedger(entry: LedgerEntry): void {
  const severity = ALERT_RULES[entry.eventType];
  if (severity) {
    emitAlert({
      severity,
      eventType: entry.eventType,
      tenantId: entry.tenantId,
      ledgerSeq: entry.seq,
      ledgerHash: entry.hash,
      subjectType: entry.subjectType,
      subjectId: entry.subjectId,
    });
    return;
  }

  // Threshold rule: step-up failure bursts. Single failure is logged in
  // the ledger but only pages once the count crosses the threshold inside
  // the rolling window. Key on `actor.id` (the OIDC sub or per-IP key the
  // auth route used) so we measure per-attacker, not globally.
  if (entry.eventType === "auth.step_up_failed") {
    const actor = entry.actor as { id?: string };
    const key = actor?.id ?? "unknown";
    const count = recordStepUpFailure(key);
    if (count >= STEP_UP_FAIL_THRESHOLD) {
      emitAlert({
        severity: "high",
        eventType: "auth.step_up_failed.threshold",
        tenantId: entry.tenantId,
        ledgerSeq: entry.seq,
        ledgerHash: entry.hash,
        extra: {
          actor_id: key,
          failures_in_window: count,
          window_seconds: STEP_UP_FAIL_WINDOW_MS / 1000,
        },
      });
    }
  }
}

// Test-only: reset the rolling-window counters. Production code must not
// call this — alert thresholds reset naturally on process restart.
export function __resetAlertStateForTest(): void {
  stepUpFailures.clear();
}
