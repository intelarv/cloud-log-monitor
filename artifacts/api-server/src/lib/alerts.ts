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
  // HITL: a human confirmed a remediation proposal (step-up gated). Warning,
  // for the same reason as break-glass reads — it is a legitimate, authorized
  // action, but it is the moment a proposed write becomes authorized to act,
  // so it belongs in the alert stream as an audit signal ("who authorized what
  // remediation in the last 24h") without needing SQL access.
  "remediation.confirmed": "warning",
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
  // M5: a specialist agent (Triage or Verifier) errored mid-run. Warning,
  // not critical — the finding row itself is still in the ledger and the
  // supervisor marked the row 'failed' so it's surfaced in the dashboard;
  // operators replay after fixing root cause. Repeated failures are the
  // signal worth paging on, detected downstream.
  "agent.review_failed": "warning",
  // M5: cost-budget circuit breaker tripped. Architect-flagged: threat_model
  // §DoS ("LLM cost circuit breaker MUST emit an alert and MUST be ledgered")
  // requires this to be alertable, not silent. Warning, not critical — a
  // single skip is the breaker working as designed; sustained skips mean
  // an upstream sender storm or a wrongly-tuned budget. Threshold/pattern
  // detection lives downstream.
  "agent.review_skipped_budget": "warning",
  // M6: outbound notification was blocked because the envelope rescan
  // tripped the PHI detector. Critical — the envelope shape is already
  // allow-listed metadata (no payload bodies), so a hit here means
  // either (a) a future field addition let content leak through, or
  // (b) a tenant id / subject id is itself classified PHI. Either way
  // the channel system did its job by hard-failing the send, but the
  // condition needs immediate triage. Threat_model §Information
  // Disclosure "Notification PHI guard".
  "channel.send_blocked_phi": "critical",
  // M6: adapter returned non-2xx, timed out, or threw. Warning, not
  // critical — a single Slack 429 or webhook 503 is noise; the failure
  // event itself is auditable in the ledger and operators replay or
  // re-route after pattern detection downstream. Loop-safe because
  // `dispatchAlertFromLedger` filters `channel.*` event types at the
  // top of the hook.
  "channel.send_failed": "warning",
  // M6: per-channel sliding-window rate limit tripped (default 30/min).
  // Warning — usually a storm signal (chain-invalid flapping, ingest
  // burst) that the operator wants visibility into without paging on
  // every dropped notification.
  "channel.send_throttled": "warning",
  // M8: a pull-based log source (CloudWatch / Cloud Logging / Azure
  // Monitor) failed to fetch a batch. Warning, not critical — transient
  // upstream / credential / quota errors are expected and the adapter
  // backs off and retries. Sustained failures or auth errors are the
  // pageable pattern, detected downstream from the alert stream.
  // Loop-safe because this event is emitted from the source loop, never
  // from the alert dispatcher itself.
  "ingest.source_error": "warning",
  // M8 (reaper): a pull-based log source's checkpoint cursor has not advanced
  // within the operator-configured stall threshold (INGEST_SOURCE_STALL_AFTER_MS).
  // Warning, not high: an idle source with no new logs is indistinguishable
  // from a wedged poller at the checkpoint level, so this is a "look at it"
  // signal rather than a confirmed outage — sustained stalls across many
  // sources are the pageable pattern, detected downstream from the alert
  // stream. Edge-triggered (emitted once per stall episode, re-armed when the
  // cursor advances again) so a perpetually-idle source does not storm the
  // alert channel every cadence. Inert unless the reaper is opted in. Loop-safe:
  // emitted from the reaper job, never the alert dispatcher. Payload carries the
  // source name + idle duration + policy threshold only (no PHI).
  "ingest.source_stalled": "warning",
  // M8 (DLQ): a raw.logs record failed to process after the bounded per-record
  // retry and was dead-lettered (metadata-only marker persisted + record ACKed
  // so a real broker stops redelivering the poison message). High, not warning:
  // a dropped log record in a compliance system is a potentially-missed PHI
  // detection an operator must triage proactively — but not critical, since no
  // disclosure or ledger-integrity loss occurs and the drop is itself
  // ledgered/auditable. Inert unless the DLQ is opted in (INGEST_DEAD_LETTER_ENABLED);
  // with it off the pipeline rethrows exactly as before. Loop-safe: emitted from
  // the ingest pipeline, never the alert dispatcher. Payload carries source
  // provenance + error name + attempt count + payload hash only (no raw PHI).
  "ingest.dead_lettered": "high",
  // M10.2/M10.3: an external WORM raw-evidence write (`store.put`) failed at
  // ingest. The finding still commits (the leak IS recorded), but its raw
  // PHI did NOT land in durable storage and `raw_evidence_ref` stays NULL.
  // High, not warning: for a compliance system, raw evidence silently not
  // reaching the WORM tier is a degraded durable-capture condition that an
  // operator must triage proactively — losing the raw payload is permanent
  // for that occurrence, and today it would otherwise only surface
  // reactively at break-glass read time as `raw_unresolved`. Not critical:
  // no disclosure or ledger-integrity loss, and a single transient object-
  // store blip is recoverable on the next occurrence's write. Inert when no
  // external store is configured (the inline DB store can't fail this way).
  // Loop-safe: emitted from the ingest path, never the alert dispatcher.
  "ingest.raw_evidence_store_failed": "high",
  // Paired recovery for `ingest.raw_evidence_store_failed`: an external WORM
  // raw-evidence `store.put` succeeded again after a preceding failure for the
  // same provider+tenant, so durable raw-PHI capture to the WORM tier is
  // restored. Warning (the lowest severity — `info` is intentionally absent):
  // good news rather than an incident, but on-call needs the paired signal to
  // know the degraded condition cleared instead of guessing whether it is still
  // ongoing. NO PHI: payload carries finding id + provider + source only.
  // Emitted only when a failure was previously latched (steady-state success
  // never alerts) and inert when no external store is configured. Loop-safe:
  // emitted from the ingest path, never the alert dispatcher.
  "ingest.raw_evidence_store_recovered": "warning",
  // M10.2/M10.3 (read path): a break-glass raw-PHI read could NOT resolve the
  // external WORM ref (store outage / misconfig / malformed ref) and fell back
  // to the legacy inline `raw_evidence` copy. The analyst still saw the raw
  // payload (no disclosure or audit gap — the access is ledgered either way),
  // but the durable WORM tier is failing READS, which today is only discoverable
  // by inspecting ledger payloads after the fact. High, not warning: a
  // compliance system running in degraded durable-read mode is an operational
  // condition on-call must triage proactively (it usually means the same outage
  // is also dropping ingest WRITES); not critical because no PHI leaked and the
  // read still succeeded from the inline mirror. Inert outside a mixed-state
  // migration window (DB store never sets fallbackUsed). Loop-safe: emitted from
  // the break-glass read handler, never the alert dispatcher. Payload carries
  // finding id + store name + reason only (no raw PHI).
  "break_glass.raw_fallback_used": "high",
  // T001 (cross-cloud A2A mTLS): an mTLS-required A2A request arrived without a
  // verified client certificate and was refused 403 at the outermost transport
  // layer (before shared-secret / caller-identity). Warning, not critical: this
  // is most often a misconfigured peer or a benign probe, and the refusal
  // already prevented any action — but for a HIPAA system a transport-auth
  // failure on the agent plane is security-relevant and must be non-repudiable
  // (threat_model §Repudiation / §Spoofing — "A2A caller identity"). Sustained
  // refusals are the pageable pattern, detected downstream from the alert
  // stream. Loop-safe: emitted only from the transport middleware, never from
  // the alert dispatcher. Inert unless A2A_REQUIRE_MTLS is set. Payload carries
  // the fixed agent route + a static reason only (no PHI, no request headers).
  "a2a.transport_rejected": "warning",
  // Tiered storage: a raw-evidence tiering migration (aging inline raw PHI out
  // of the hot findings.raw_evidence column into the external WORM store)
  // failed at put/get/verify for one finding. Warning, not high: unlike the
  // ingest write-failure event (raw permanently lost for that occurrence), the
  // tiering job preserves the inline copy on any failure and retries next
  // cadence, so nothing is lost — but a compliance system should still surface
  // proactively that hot→WORM migration is degraded (it usually means the same
  // object-store outage is also failing ingest writes). Inert unless an
  // external store + RAW_EVIDENCE_TIER_AGE_DAYS are configured. Loop-safe:
  // emitted from the tiering job, never the alert dispatcher. Payload carries
  // finding id + provider only (no raw PHI, no object URIs).
  "raw_evidence.tier_failed": "warning",
  // Memory eviction: a per-tenant eviction sweep over the finding_embeddings
  // derived cache failed. The embeddings are left intact on any failure and the
  // job retries next cadence, so retrieval recall is unaffected — but a
  // persistent failure means the vector cache is growing unbounded against the
  // configured cap, which is worth surfacing. Inert unless
  // MEMORY_MAX_EMBEDDINGS_PER_TENANT is set. Loop-safe: emitted from the
  // eviction job, never the alert dispatcher. Payload carries counts + policy
  // params only (no finding ids, no PHI).
  "memory.evict_failed": "warning",
  // Opt-in consolidation summarizer (MEMORY_CONSOLIDATION_SUMMARY) failed for a
  // group/tenant — empty LLM output, PHI detected in output (hard-failed write),
  // or a per-tenant error. The successful path (memory.summarized) is routine.
  "memory.summary_failed": "warning",
  // Supervisor durable engine (WORKFLOW_ENGINE=temporal): a finding's
  // Triage->Verifier review was dropped before it could run — either the
  // pre-start buffer overflowed during the engine's async startup window
  // (reason `prestart_buffer_overflow`) or a non-idempotency `startWorkflow`
  // call failed and dispatch has no retry (reason `start_workflow_failed`).
  // High, not warning: for a compliance system a dropped review means a
  // finding silently never got its verdict — an operator must replay it
  // proactively (same reasoning as `ingest.dead_lettered`). Not critical: no
  // disclosure or ledger-integrity loss, the finding row itself is durable,
  // and the drop is itself ledgered/auditable. Inert unless the temporal
  // engine is selected (the default in-process engine never buffers or starts
  // workflows). Loop-safe: emitted from the engine, never the alert
  // dispatcher. Payload carries the finding id + a static reason (+ buffer cap
  // / error name) only — no PHI.
  "supervisor.review_dropped": "high",
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
  // Chat working-memory rolling-summary events. Routine + best-effort: a
  // summary refresh is normal, and a failure just keeps the prior summary for
  // that turn (no data loss, no PHI leak), so neither pages on-call.
  "chat.memory_summarized",
  "chat.memory_summary_failed",
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
  // Early revocation of a grant before its TTL elapses (requester withdrawing
  // their own grant, or an operator cutting one off). A legitimate lifecycle
  // action that *reduces* exposure; the raw-PHI read it gates is the
  // alertable event. Auditable in the ledger like grant/approve.
  "break_glass.revoked",
  // HITL remediation lifecycle. An agent drafting a *proposal* is inert (it
  // executes nothing — the human confirm endpoint is the gate), and a human
  // rejecting a proposal *reduces* exposure. The security-relevant event is
  // `remediation.confirmed` (warning-level above), where a proposal becomes
  // authorized to act. Both are auditable in the ledger like the rest of the
  // lifecycle.
  "remediation.proposed",
  "remediation.rejected",
  // Finding lifecycle — the notifier handles severity-based routing per
  // §291; not in scope of the alert hook.
  "finding.created",
  // A finding transitioned to a resolved/closed state (resolved or
  // false_positive). A routine triage outcome that *reduces* exposure (it also
  // auto-revokes the finding's active break-glass grants); auditable in the
  // ledger like the rest of the finding lifecycle. The auto-revoke it triggers
  // is ledgered separately as `break_glass.revoked`.
  "finding.resolved",
  // A finding was reopened (transitioned from a closed state back to "open"),
  // typically because it was closed in error. A routine triage correction;
  // unlike resolve it does NOT touch break-glass access. Auditable in the
  // ledger like the rest of the finding lifecycle.
  "finding.reopened",
  // An operator manually requested a re-run of a finding's Triage->Verifier
  // review (reset to pending + re-enqueue). A routine triage action over the
  // redacted projection — no disclosure and no authorized write; the LLM cost
  // it incurs is already gated downstream by the per-tenant budget breaker
  // (`agent.review_skipped_budget`, warning above). Auditable in the ledger
  // like the rest of the finding/agent lifecycle.
  "agent.re_review_requested",
  // Ledger bootstrap. Fires once.
  "ledger.genesis",
  // M2: each successful notarization checkpoint creation. Routine signal
  // (one row per cadence tick when the ledger changes); auditable via the
  // ledger and `GET /api/admin/ledger/checkpoints`. Mismatch is the event
  // worth paging on, not creation.
  "ledger.checkpoint_created",
  // M5: per-finding agent review steps. High-volume on bulk replay
  // (one of each per new finding); auditable in the ledger; the failure
  // event (`agent.review_failed`, warning above) is the alertable one.
  "agent.triage_complete",
  "agent.verifier_complete",
  // M6: every successful channel send is ledgered (per-access audit
  // trail per threat_model §Repudiation), but high-volume — one row per
  // outbound alert per channel. The failure / blocked / throttled
  // events are the alertable ones above.
  "channel.send_succeeded",
  // M8: per-source lifecycle markers. One row each on start/stop is
  // operationally useful in the ledger (proves a source was running
  // during an investigation window) but routine — not pageable.
  "ingest.source_started",
  "ingest.source_stopped",
  // Tiered storage: a finding's inline raw PHI was successfully aged out of
  // the hot findings.raw_evidence column into the external WORM store. A
  // routine lifecycle action that *reduces* exposure (raw leaves the hot
  // tier); auditable in the ledger like the rest of the finding lifecycle.
  // The failure event (raw_evidence.tier_failed, warning above) is the
  // alertable one.
  "raw_evidence.tiered",
  // Memory eviction: low-importance embeddings were pruned from the
  // finding_embeddings derived cache to honor MEMORY_MAX_EMBEDDINGS_PER_TENANT
  // and the consolidation policy. A routine maintenance action that only
  // affects the vector retrieval cache (the findings audit record and the
  // lexical/BM25 leg are untouched); auditable in the ledger. The failure
  // event (memory.evict_failed, warning above) is the alertable one.
  "memory.evicted",
  // Opt-in consolidation summarizer wrote/refreshed one or more group summaries
  // (MEMORY_CONSOLIDATION_SUMMARY). Routine maintenance; payload carries counts +
  // model_id only (no finding ids, no summary text, no PHI). The failure event
  // (memory.summary_failed, warning above) is the alertable one.
  "memory.summarized",
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
