// Type declarations for the pure-ESM nightly eval-gate notifier (notify.mjs).
// The runtime module must stay plain ESM so the shell entrypoint can run it
// with `node` directly; these types let the TS unit test import it.

export type Severity = "warning" | "high" | "critical";

export type Outcome = "failed" | "warned" | "clean";

export type NotifyOn = "fail" | "warn" | "always";

export interface EvalChannel {
  kind: "slack" | "webhook" | "pagerduty";
  url?: string;
  secret?: string;
  routingKey?: string;
  eventsUrl?: string;
  dedupKey?: string;
  minSeverity: Severity;
}

export interface SuiteSummary {
  score?: number;
  baseline?: number;
  floor?: number;
  deltaPt?: number;
  status?: string;
}

export interface GateSummary {
  ok: boolean;
  executionFailure?: boolean;
  failures?: string[];
  warnings?: string[];
  suites?: Record<string, SuiteSummary>;
  floor?: { active: boolean; value: number | null };
  ts?: string;
}

export type TrendDirection = "up" | "down" | "flat" | "new";

export interface Trend {
  direction: TrendDirection;
  deltaPt: number;
  prev: number | null;
}

export type Trends = Record<string, Trend>;

export interface HistoryRun {
  ts: string;
  ok: boolean;
  outcome: Outcome;
  /** Suites that were failing this run (absent on records that predate it). */
  failed?: string[];
  scores: Record<string, number>;
}

export interface SendResult {
  channel: string;
  ok: boolean;
  statusCode?: number;
  dedupKey?: string;
  action?: "trigger" | "resolve" | "recovery";
  err?: string;
}

export interface NotifyResult {
  skipped: boolean;
  sent: SendResult[];
  outcome?: Outcome;
  severity?: Severity;
}

export function parseChannels(env?: Record<string, string | undefined>): EvalChannel[];

export function selectForSeverity(
  channels: EvalChannel[],
  severity?: Severity,
): EvalChannel[];

export function classifyOutcome(summary: GateSummary | undefined): Outcome;

export function parseNotifyOn(env?: Record<string, string | undefined>): NotifyOn;

export function shouldNotify(notifyOn: NotifyOn, outcome: Outcome): boolean;

export function loadSummary(evalsDir?: string): GateSummary;

export function historyLimit(env?: Record<string, string | undefined>): number;

export function extractScores(summary: GateSummary | undefined): Record<string, number>;

export function loadHistory(evalsDir?: string): HistoryRun[];

export function previousScores(history: HistoryRun[]): Record<string, number> | null;

export function previousRun(history: HistoryRun[]): HistoryRun | null;

export function failingSuites(summary: GateSummary | undefined): string[];

export function recoveryNotifyEnabled(env?: Record<string, string | undefined>): boolean;

export function recoveryMuteConfig(env?: Record<string, string | undefined>): {
  threshold: number;
  windowMinutes: number;
};

export function countRecentRecoveries(
  history: HistoryRun[],
  windowMinutes: number,
  now?: number,
): number;

export function isRecoveryFlapping(
  history: HistoryRun[],
  env?: Record<string, string | undefined>,
  now?: number,
): boolean;

export function failingStreakStart(history: HistoryRun[]): string | null;

export function fmtDuration(ms: number): string;

export function detectRecovery(
  outcome: Outcome,
  currentSuites?: Record<string, SuiteSummary>,
  prevRun?: HistoryRun | null,
): string[] | null;

export interface RecoveryNoteOpts {
  failingSince?: string | null;
  now?: number;
}

export function buildRecoveryText(
  summary: GateSummary,
  recovered?: string[],
  opts?: RecoveryNoteOpts,
): string;

export function buildRecoverySlackMessage(
  summary: GateSummary,
  recovered?: string[],
  fallback?: string,
  opts?: RecoveryNoteOpts,
): SlackMessage;

export function computeTrends(
  currentSuites?: Record<string, SuiteSummary>,
  prevScores?: Record<string, number> | null,
): Trends;

export function fmtTrend(trend?: Trend): string;

export function recordRunHistory(opts?: {
  evalsDir?: string;
  summary?: GateSummary;
  maxEntries?: number;
  now?: Date;
}): HistoryRun[];

export function buildSummaryText(
  summary: GateSummary,
  opts?: { exitCode?: number; outcome?: Outcome; severity?: Severity; trends?: Trends },
): string;

export interface SlackMessage {
  text: string;
  attachments: Array<{ color: string; blocks: unknown[] }>;
}

export function buildSlackMessage(
  summary: GateSummary,
  opts?: { exitCode?: number; outcome?: Outcome; severity?: Severity; trends?: Trends },
): SlackMessage;

export function signWebhookBody(secret: string, timestampSec: number, body: string): string;

export function defaultPagerDutyDedupKey(): string;

export function defaultHeartbeatDedupKey(): string;

export function resolveHeartbeat(opts?: {
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
}): Promise<{ sent: SendResult[] }>;

export function postToChannels(opts: {
  env?: Record<string, string | undefined>;
  severity?: Severity;
  text: string;
  payload: unknown;
  fetchImpl?: typeof fetch;
}): Promise<{ skipped: boolean; sent: SendResult[] }>;

export function notifyEvalGate(opts?: {
  env?: Record<string, string | undefined>;
  evalsDir?: string;
  summary?: GateSummary;
  history?: HistoryRun[];
  fetchImpl?: typeof fetch;
  exitCode?: number;
  now?: number;
}): Promise<NotifyResult>;
