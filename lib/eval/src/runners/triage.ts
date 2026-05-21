/**
 * Triage eval runner.
 *
 * STATUS: skeleton. The Triage Agent does not exist yet (lands in M4).
 * Same pattern as the chat runner: SKIP every case until target wired.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadTriageCases } from "../load.js";
import type { TriageCase, CaseResult, RunReport } from "../types.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPORTS = join(HERE, "..", "..", "reports");

interface TriageDecision {
  action: "dedup" | "create" | "verify" | "error";
  severity?: "low" | "medium" | "high" | "critical";
  finding_id?: string;
  escalate?: boolean;
  route_to_verifier?: boolean;
  tool_calls: Array<{ name: string; args: unknown }>;
}

async function invokeTriageAgent(
  _case: TriageCase,
): Promise<{ available: false; reason: string } | { available: true; decision: TriageDecision }> {
  return { available: false, reason: "Triage Agent not built yet (lands in M4)" };
}

function evaluate(c: TriageCase, d: TriageDecision): CaseResult {
  const failures: string[] = [];
  const metrics: Record<string, number | string | boolean> = {};

  if (d.action !== c.expected.action) {
    failures.push(`action mismatch: got ${d.action}, expected ${c.expected.action}`);
  }
  metrics.action = d.action;

  if (c.expected.severity && d.severity !== c.expected.severity) {
    failures.push(`severity mismatch: got ${d.severity}, expected ${c.expected.severity}`);
  }
  if (c.expected.finding_id && d.finding_id !== c.expected.finding_id) {
    failures.push(`finding_id mismatch: got ${d.finding_id}, expected ${c.expected.finding_id}`);
  }
  if (c.expected.route_to_verifier !== undefined && d.route_to_verifier !== c.expected.route_to_verifier) {
    failures.push(`route_to_verifier mismatch: got ${d.route_to_verifier}, expected ${c.expected.route_to_verifier}`);
  }
  if (c.expected.escalate !== undefined && d.escalate !== c.expected.escalate) {
    failures.push(`escalate mismatch: got ${d.escalate}, expected ${c.expected.escalate}`);
  }

  if (c.expected.no_tool_calls_outside_allowlist) {
    const allow = new Set(["lookup_cluster", "create_finding", "attach_evidence_to_finding", "enqueue_for_verification"]);
    for (const tc of d.tool_calls) {
      if (!allow.has(tc.name)) failures.push(`out-of-allowlist tool call: ${tc.name}`);
    }
  }
  metrics.tool_calls = d.tool_calls.length;

  return { case_id: c.id, passed: failures.length === 0, failures, metrics, duration_ms: 0 };
}

async function main() {
  const cases = loadTriageCases();
  const results: CaseResult[] = [];
  let skipped = 0;
  for (const c of cases) {
    const t0 = Date.now();
    const out = await invokeTriageAgent(c);
    if (!out.available) {
      results.push({
        case_id: c.id,
        passed: false,
        failures: [`SKIPPED: ${out.reason}`],
        metrics: { skipped: true },
        duration_ms: Date.now() - t0,
      });
      skipped++;
      continue;
    }
    const r = evaluate(c, out.decision);
    r.duration_ms = Date.now() - t0;
    results.push(r);
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed && !r.metrics.skipped).length;
  const report: RunReport = {
    suite: "triage",
    total: cases.length,
    passed,
    failed,
    hard_failures: results
      .filter((r) => r.failures.some((f) => /critical|out-of-allowlist/.test(f)))
      .map((r) => r.case_id),
    results,
    generated_at: new Date().toISOString(),
  };

  mkdirSync(REPORTS, { recursive: true });
  const out = join(REPORTS, `triage-${Date.now()}.json`);
  writeFileSync(out, JSON.stringify(report, null, 2));
  console.log(`triage eval: ${passed}/${cases.length} passed, ${skipped} skipped, ${failed} failed`);
  console.log(`report: ${out}`);
  if (failed > 0) process.exit(1);
}

void main();
