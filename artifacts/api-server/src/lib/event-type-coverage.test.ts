// §25.4 mechanical guard. Every event type passed to `appendLedger` MUST
// either appear in `ALERT_RULES` (will page / warn) or in `NOT_ALERTABLE`
// (legitimate-flow allow-list). A new event type with no documented
// alerting decision fails this test — the review surface is enforced
// here, not in code review.
//
// Implementation: scan all source files in this package for
// `eventType: "<literal>"` occurrences and the synthesized
// `auth.step_up_failed.threshold` (emitted from alerts.ts itself, never
// persisted) is treated specially.

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { ALERT_RULES, NOT_ALERTABLE } from "./alerts";

// Scan our own server source AND the shared db package's seed/setup
// modules — `finding.created` and `ledger.genesis` are emitted from
// `lib/db/src/seed.ts`, so they only count as live if we look there too.
const SCAN_ROOTS = [
  join(__dirname, ".."),
  join(__dirname, "..", "..", "..", "..", "lib", "db", "src"),
];

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      out.push(...walk(p));
    } else if (
      st.isFile() &&
      p.endsWith(".ts") &&
      !p.endsWith(".test.ts") &&
      !p.endsWith(".d.ts") &&
      // Drizzle schema defines `eventType: text("event_type")` — the
      // string is the column name, not a ledger event type.
      !p.includes(`${"/"}schema${"/"}`)
    ) {
      out.push(p);
    }
  }
  return out;
}

function collectEventTypes(): Map<string, string[]> {
  // event_type -> file paths where it appears. Matches:
  //   eventType: "literal"
  //   eventType: cond ? "literal_a" : "literal_b"
  //   eventType:\n  cond ? "a" : "b"
  // by extracting *all* double-quoted string literals in the `eventType:`
  // value expression (everything up to the next top-level comma or `}`).
  //
  // KNOWN LIMITATIONS (intentional — keep the codebase to this style):
  //   - single-quoted strings are NOT matched (codebase uses double quotes);
  //   - template literals (`...`), const refs (FOO_EVT), and indirection
  //     through helpers are NOT matched — a future indirection like
  //     `eventType: makeEvt(...)` would slip past this guard;
  //   - non-`eventType:` property names are not scanned (so renaming the
  //     field would silently bypass the guard).
  // If any of those start showing up in the codebase, migrate this scanner
  // to an AST walk (ts-morph) scoped to `appendLedger({ eventType: ... })`.
  const map = new Map<string, string[]>();
  // `[\s\S]*?` to span newlines; lazy stop at first comma/`}` not preceded
  // by a quote (the value expressions we care about don't contain those
  // tokens inside string literals in this codebase).
  const re = /eventType:\s*([\s\S]*?)(?=,\s*\w+:|,?\s*\})/g;
  const strRe = /"([^"]+)"/g;
  const files = SCAN_ROOTS.flatMap((r) => walk(r));
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const valueExpr = m[1]!;
      let s: RegExpExecArray | null;
      strRe.lastIndex = 0;
      while ((s = strRe.exec(valueExpr)) !== null) {
        const t = s[1]!;
        const arr = map.get(t) ?? [];
        arr.push(file);
        map.set(t, arr);
      }
    }
  }
  return map;
}

describe("§25.4: ledger event-type alert coverage", () => {
  const eventTypes = collectEventTypes();

  it("scan found at least the M1 events (sanity)", () => {
    // Defends the test itself — if the regex breaks, this fails loudly
    // instead of vacuously passing.
    expect(eventTypes.has("chat.agent_turn")).toBe(true);
    expect(eventTypes.has("break_glass.raw_phi_accessed")).toBe(true);
    expect(eventTypes.has("policy.text_field_rejected")).toBe(true);
  });

  // Synthetic event types emitted by the alerter itself (never persisted
  // as ledger entries) — they ARE alerts, with severity hard-coded at the
  // emit site, so the coverage rule doesn't apply.
  const SYNTHETIC: ReadonlySet<string> = new Set([
    "auth.step_up_failed.threshold",
  ]);

  it("every emitted event type has a documented alerting decision", () => {
    const undocumented: string[] = [];
    for (const [eventType] of eventTypes) {
      if (eventType === "noop") continue;
      if (SYNTHETIC.has(eventType)) continue;
      const alertable = Object.prototype.hasOwnProperty.call(
        ALERT_RULES,
        eventType,
      );
      const allowlisted = NOT_ALERTABLE.has(eventType);
      if (!alertable && !allowlisted) undocumented.push(eventType);
    }
    expect(
      undocumented,
      `New ledger event type(s) found with no §25 alert decision: ${undocumented.join(", ")}. ` +
        `Add to ALERT_RULES (will alert) or NOT_ALERTABLE (legitimate flow) in artifacts/api-server/src/lib/alerts.ts.`,
    ).toEqual([]);
  });

  it("ALERT_RULES and NOT_ALERTABLE are disjoint", () => {
    const overlap = Object.keys(ALERT_RULES).filter((k) =>
      NOT_ALERTABLE.has(k),
    );
    expect(overlap, `event types in both sets: ${overlap.join(", ")}`).toEqual(
      [],
    );
  });

  // `ledger.chain_invalid` is reserved for a future periodic verifier
  // (see ALERT_RULES comment in alerts.ts). Allow as a known-future entry
  // until the verifier lands. TODO(M1.8): remove once the verifier emits it.
  const FUTURE: ReadonlySet<string> = new Set(["ledger.chain_invalid"]);

  it("every ALERT_RULES entry is actually emitted somewhere (no dead rules)", () => {
    // A rule for an event that no code emits is a docs lie — flag it so
    // §25.2 stays honest.
    const dead: string[] = [];
    for (const k of Object.keys(ALERT_RULES)) {
      if (SYNTHETIC.has(k)) continue;
      if (!eventTypes.has(k)) dead.push(k);
    }
    const trulyDead = dead.filter((d) => !FUTURE.has(d));
    expect(
      trulyDead,
      `ALERT_RULES entries with no emitter: ${trulyDead.join(", ")}`,
    ).toEqual([]);
  });

  it("every NOT_ALERTABLE entry is actually emitted somewhere (no stale allow-list)", () => {
    // Symmetric to the ALERT_RULES dead-rule check: a stale NOT_ALERTABLE
    // entry weakens documentation integrity by claiming "we considered
    // this and decided not to alert" for an event nothing emits.
    const dead: string[] = [];
    for (const k of NOT_ALERTABLE) {
      if (SYNTHETIC.has(k)) continue;
      if (!eventTypes.has(k)) dead.push(k);
    }
    const trulyDead = dead.filter((d) => !FUTURE.has(d));
    expect(
      trulyDead,
      `NOT_ALERTABLE entries with no emitter: ${trulyDead.join(", ")}`,
    ).toEqual([]);
  });
});
