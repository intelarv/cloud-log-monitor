import { format, formatDistanceToNow } from "date-fns";

// Defensive timestamp formatting shared across the dashboard.
//
// Every ledger/finding row carries a server-supplied `ts`/`*_at` string. A
// malformed, missing, or partial value (a corrupt ledger row, a half-written
// finding, an unexpected null from a future API change) would otherwise make
// date-fns `format`/`formatDistanceToNow` throw "Invalid time value" — and
// because these are called inline during render, a single bad row would
// white-screen the entire page for a compliance analyst. These helpers degrade
// to a readable placeholder instead of throwing, so one bad value never takes
// down the whole view.

const PLACEHOLDER = "unknown time";

function parse(ts: unknown): Date | null {
  if (typeof ts !== "string") return null;
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Absolute timestamp (default `yyyy-MM-dd HH:mm:ss`). Pass a date-fns format
// string to override (e.g. `HH:mm:ss` for a time-only display).
export function safeTimestamp(ts: unknown, fmt = "yyyy-MM-dd HH:mm:ss"): string {
  const d = parse(ts);
  return d ? format(d, fmt) : PLACEHOLDER;
}

// Relative timestamp (e.g. "3 minutes ago").
export function safeRelativeTime(ts: unknown): string {
  const d = parse(ts);
  return d ? formatDistanceToNow(d, { addSuffix: true }) : PLACEHOLDER;
}
