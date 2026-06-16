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

// Compact relative timestamp for tight, repeated inline labels (e.g. the stacked
// break-glass access-change banners) where the verbose date-fns phrasing ("less
// than a minute ago") is too long. Accepts either an epoch-ms number (how the
// banner captures its transition time) or an ISO string. Returns "just now",
// "12 sec ago", "2 min ago", "3 hr ago", "1 day ago". `now` is injectable so the
// formatting is pure and unit-testable without faking the clock; a future
// timestamp (clock skew) clamps to "just now" rather than rendering a negative
// duration. Degrades to the shared placeholder on a malformed value.
export function compactRelativeTime(ts: unknown, now: number = Date.now()): string {
  const ms = typeof ts === "number" ? ts : parse(ts)?.getTime();
  if (ms === undefined || Number.isNaN(ms)) return PLACEHOLDER;
  const diffSec = Math.round((now - ms) / 1000);
  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec} sec ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr} hr ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay} day${diffDay === 1 ? "" : "s"} ago`;
}
