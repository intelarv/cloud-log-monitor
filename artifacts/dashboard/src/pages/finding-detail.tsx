import React from "react";
import Layout from "../components/layout";
import {
  useGetFinding,
  useGetFindingRaw,
  useGetFindingHistory,
  useGetFindingReviewHistory,
  useListBreakGlassGrants,
  getGetFindingQueryKey,
  getGetFindingHistoryQueryKey,
  getGetFindingReviewHistoryQueryKey,
  getListBreakGlassGrantsQueryKey,
} from "@workspace/api-client-react";
import type { ReviewAttempt, BreakGlassGrant } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useParams, Link } from "wouter";
import { SeverityBadge, StatusBadge } from "../components/severity-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ArrowLeft, ShieldAlert, Lock, Unlock, AlertTriangle, ExternalLink, Bot, CheckCircle2, XCircle, Clock, HelpCircle, CheckCheck, RotateCcw, RefreshCw, History, KeyRound, Eye, Ban, ShieldQuestion, PlusCircle, X, Loader2 } from "lucide-react";
import { safeTimestamp, compactRelativeTime } from "../lib/format";
import BreakGlassModal from "../components/break-glass-modal";
import ResolveFindingModal from "../components/resolve-finding-modal";
import ReopenFindingModal from "../components/reopen-finding-modal";
import ReReviewFindingModal from "../components/re-review-finding-modal";
import { ApiError } from "@workspace/api-client-react";

// While an agent review is queued or running, poll the finding + review-history
// queries so the Triage/Verifier verdicts land on their own once the supervisor
// finishes the re-run. Polling stops the moment the status reaches a terminal
// state (completed/failed/skipped) to avoid wasted requests.
const REVIEW_POLL_INTERVAL_MS = 3000;

// While the analyst has a break-glass grant on this finding that is still in
// flight (awaiting a second-person approval) or currently active, poll their
// grants so an approve/revoke performed *by someone else* (on the admin page)
// surfaces here without a manual reload. Polling stops once the grant reaches a
// terminal state (revoked / expired / none) — the live notice has already fired.
const BREAK_GLASS_POLL_INTERVAL_MS = 5000;

function isReviewActive(status: string | null | undefined): boolean {
  return status === "pending" || status === "in_progress";
}

export type GrantStatus = "pending" | "active" | "revoked" | "expired" | "none";

// Reduce a grant row to the lifecycle state the analyst cares about. Revoked
// takes precedence over expiry (an explicit cut-off), and a pending second
// approval takes precedence over the active window it has not yet entered.
export function grantStatus(grant: BreakGlassGrant | null | undefined): GrantStatus {
  if (!grant) return "none";
  if (grant.revoked_at) return "revoked";
  if (grant.pending_approval) return "pending";
  if (Date.parse(grant.expires_at) <= Date.now()) return "expired";
  return "active";
}

// The only transitions worth a live notice: a pending grant becoming active
// (someone approved it), or a pending/active grant being cut off (revoked or
// expired). Everything else — initial observation, no change, re-grant — is
// silent. Keeping this pure makes the notice logic unit-testable.
export type GrantTransition = "approved" | "revoked" | "expired" | null;

// One entry in the persistent, stacked access-change history. `id` is a stable
// per-entry key/dismiss target (the same transition kind can recur, so the kind
// alone is not unique); `notice` is the transition it represents; `at` is the
// epoch-ms wall-clock time the transition was observed (captured on the
// grant-poll transition) so each stacked entry can render a relative timestamp,
// making the order of a rapid approve→revoke→re-grant burst unambiguous.
export type AccessChangeEntry = { id: number; notice: Exclude<GrantTransition, null>; at: number };

export function grantTransition(prev: GrantStatus | null, next: GrantStatus): GrantTransition {
  if (prev === null || prev === next) return null;
  if (prev === "pending" && next === "active") return "approved";
  if ((prev === "pending" || prev === "active") && next === "revoked") return "revoked";
  if ((prev === "pending" || prev === "active") && next === "expired") return "expired";
  return null;
}

// How close to auto-expiry the unlocked-evidence card switches from a calm
// countdown to a "heads up, wrap up" warning. Exported so the threshold is a
// single source of truth shared by the component and its tests.
export const EXPIRY_WARNING_THRESHOLD_MS = 30_000;

// Format a remaining-duration in milliseconds as `M:SS`, clamped at zero so a
// just-lapsed grant never renders a negative timer. Pure, so the countdown math
// is unit-testable without fake timers.
export function formatRemaining(ms: number): string {
  const totalSeconds = Math.max(0, Math.ceil(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${seconds.toString().padStart(2, "0")}`;
}

// Unlocked raw-evidence panel. While a break-glass grant is active the analyst
// otherwise only saw a static "Expires HH:mm:ss" timestamp; this drives a live,
// once-per-second countdown of the time remaining on the grant and, in the final
// EXPIRY_WARNING_THRESHOLD_MS before auto-expiry, surfaces a non-intrusive inline
// notice so they can wrap up (or re-request) instead of being cut off mid-read.
// A malformed expiry falls back to the absolute timestamp rather than a broken
// timer. The grant itself still auto-expires server-side; this is display only.
function UnlockedEvidence({ rawEvidence, onReRequest }: { rawEvidence: any; onReRequest?: () => void }) {
  const expiryMs = React.useMemo(() => Date.parse(rawEvidence?.grant_expires_at), [rawEvidence?.grant_expires_at]);
  const hasExpiry = !Number.isNaN(expiryMs);

  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    if (!hasExpiry) return;
    setNow(Date.now());
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, [hasExpiry, expiryMs]);

  const remaining = hasExpiry ? expiryMs - now : null;
  const expired = remaining !== null && remaining <= 0;
  const expiring = remaining !== null && remaining > 0 && remaining <= EXPIRY_WARNING_THRESHOLD_MS;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20">
          RAW PHI/PII UNLOCKED
        </Badge>
        {remaining === null ? (
          <span className="text-xs text-muted-foreground">
            Expires {safeTimestamp(rawEvidence.grant_expires_at, "HH:mm:ss")}
          </span>
        ) : (
          <span
            className={`text-xs font-mono tabular-nums ${
              expiring || expired ? "text-destructive font-semibold" : "text-muted-foreground"
            }`}
            role="timer"
            aria-live="off"
          >
            {expired ? "Access expired" : `Access expires in ${formatRemaining(remaining)}`}
          </span>
        )}
      </div>
      {expiring && (
        <div
          role="status"
          className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive"
        >
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          <span className="flex-1">
            Emergency access expires in {formatRemaining(remaining!)} — wrap up or re-request before raw evidence
            re-locks.
          </span>
          {onReRequest && (
            <Button
              type="button"
              size="sm"
              variant="destructive"
              className="h-7 shrink-0 px-2 text-xs"
              onClick={onReRequest}
            >
              <KeyRound className="h-3.5 w-3.5 mr-1" /> Re-request access
            </Button>
          )}
        </div>
      )}
      <pre className="p-4 bg-muted/50 rounded-md overflow-x-auto text-xs font-mono border border-destructive/20 text-foreground whitespace-pre-wrap">
        {JSON.stringify(rawEvidence.raw_evidence, null, 2)}
      </pre>
    </div>
  );
}

// Visual + copy config for the persistent access-change banner. Approved is a
// positive (access-granted) state; revoked/expired are destructive (access cut
// off) states and must be visually distinct from approval.
const ACCESS_NOTICE_CONFIG: Record<
  Exclude<GrantTransition, null>,
  { title: string; description: string; Icon: typeof CheckCircle2; destructive: boolean }
> = {
  approved: {
    title: "Break-glass access approved",
    description:
      "Your emergency access for this finding was just approved — raw evidence is now available.",
    Icon: CheckCircle2,
    destructive: false,
  },
  revoked: {
    title: "Break-glass access revoked",
    description:
      "Your emergency access for this finding was cut off — raw evidence is no longer available.",
    Icon: Ban,
    destructive: true,
  },
  expired: {
    title: "Break-glass access expired",
    description:
      "Your emergency access for this finding has expired — raw evidence is no longer available.",
    Icon: Clock,
    destructive: true,
  },
};

// Persistent inline banner for an access change made by another analyst. It
// stays on the page until explicitly dismissed (unlike the ~5s toast), so a
// mid-investigation revocation/expiry can't be missed. Destructive states use
// `role="alert"` (assertive) and the calm approval uses `role="status"`.
export function AccessChangeBanner({
  notice,
  at,
  onDismiss,
}: {
  notice: Exclude<GrantTransition, null>;
  at: number;
  onDismiss: () => void;
}) {
  const cfg = ACCESS_NOTICE_CONFIG[notice];
  const { Icon } = cfg;

  // Re-render on a slow cadence so the captured-at time keeps reading correctly
  // ("just now" → "1 min ago") while the persistent banner stays on screen,
  // even after grant polling has stopped (terminal state) and nothing else
  // would otherwise re-render the page.
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div
      role={cfg.destructive ? "alert" : "status"}
      data-testid="break-glass-access-banner"
      data-variant={cfg.destructive ? "destructive" : "approved"}
      className={`flex items-start gap-3 rounded-lg border px-4 py-3 ${
        cfg.destructive
          ? "border-destructive/40 bg-destructive/10 text-destructive"
          : "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
      }`}
    >
      <Icon className="h-5 w-5 shrink-0 mt-0.5" />
      <div className="flex-1">
        <h3 className="font-semibold leading-tight">{cfg.title}</h3>
        <p className="text-sm mt-0.5 opacity-90">{cfg.description}</p>
        <p
          className="text-xs mt-1 opacity-70"
          data-testid="break-glass-access-time"
          title={safeTimestamp(new Date(at).toISOString())}
        >
          {compactRelativeTime(at, now)}
        </p>
      </div>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="h-7 w-7 shrink-0 hover:bg-transparent"
        onClick={onDismiss}
        aria-label="Dismiss break-glass access notice"
      >
        <X className="h-4 w-4" />
      </Button>
    </div>
  );
}

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: finding, isLoading } = useGetFinding(id!, {
    query: {
      enabled: !!id,
      queryKey: getGetFindingQueryKey(id!),
      refetchInterval: (query) =>
        isReviewActive(query.state.data?.agent_review_status) ? REVIEW_POLL_INTERVAL_MS : false,
      // Stop the poll while the tab is hidden: an analyst who has tabbed away
      // isn't watching the live review, and a backgrounded finding-detail page
      // should not keep hitting the API every few seconds. react-query resumes
      // the interval (and fires an immediate catch-up refetch) on refocus.
      refetchIntervalInBackground: false,
    },
  });

  const [showBreakGlass, setShowBreakGlass] = React.useState(false);
  const [showResolve, setShowResolve] = React.useState(false);
  const [showReopen, setShowReopen] = React.useState(false);
  const [showReReview, setShowReReview] = React.useState(false);
  const [rawEvidence, setRawEvidence] = React.useState<any>(null);
  const [rawError, setRawError] = React.useState<ApiError | null>(null);
  const [isPendingApproval, setIsPendingApproval] = React.useState(false);
  const [grantId, setGrantId] = React.useState<string | null>(null);
  // A persistent, stacked history of access changes made by another analyst.
  // Unlike the transient toast (~5s), these banners stay on the finding-detail
  // page until the analyst explicitly dismisses them, so a mid-investigation
  // revocation can never scroll past or auto-dismiss before it is seen. During a
  // busy two-analyst incident several transitions (e.g. approved → revoked →
  // re-granted) can land in quick succession; each gets its own entry so a later
  // transition never silently overwrites an earlier one the analyst hasn't read.
  const [accessNotices, setAccessNotices] = React.useState<AccessChangeEntry[]>([]);
  // Monotonic id source so each stacked entry has a stable React key + dismiss
  // target, independent of its transition kind (the same kind can recur).
  const accessNoticeIdRef = React.useRef(0);

  const queryClient = useQueryClient();

  // Keep the freshest grant in a ref so the polling predicate below (evaluated
  // lazily by react-query) sees the current status without re-subscribing.
  // Declared *before* useListBreakGlassGrants so the refetchInterval closure can
  // safely read it on react-query's first synchronous evaluation — declaring it
  // after the hook hit a temporal-dead-zone crash ("Cannot access
  // 'latestGrantRef' before initialization") the moment the page mounted.
  const latestGrantRef = React.useRef<BreakGlassGrant | null>(null);

  // Poll the analyst's own break-glass grants while one for this finding is in
  // flight (pending approval) or active, so a decision made elsewhere lands as a
  // live notice. Stops polling once the grant is terminal to avoid wasted calls.
  const { data: myGrants } = useListBreakGlassGrants({
    query: {
      queryKey: getListBreakGlassGrantsQueryKey(),
      refetchInterval: () => {
        const status = grantStatus(latestGrantRef.current);
        return status === "pending" || status === "active" ? BREAK_GLASS_POLL_INTERVAL_MS : false;
      },
      // Don't poll grant state while the tab is hidden — resumes on refocus.
      refetchIntervalInBackground: false,
    },
  });

  const myGrant = React.useMemo<BreakGlassGrant | null>(
    () => (myGrants ?? []).find((g) => g.finding_id === id) ?? null,
    [myGrants, id],
  );

  latestGrantRef.current = myGrant;

  // Detect approve/revoke transitions performed by another analyst and surface a
  // persistent inline banner (see AccessChangeBanner). `prevStatusRef` starts
  // unset so the first observed state never fires a notice — only genuine
  // transitions do. A transient ~5s toast was easy to miss for a
  // mid-investigation revocation, so the banner stays until acknowledged.
  const prevStatusRef = React.useRef<GrantStatus | null>(null);
  React.useEffect(() => {
    if (!myGrant) return;
    const status = grantStatus(myGrant);
    const transition = grantTransition(prevStatusRef.current, status);
    prevStatusRef.current = status;
    if (!transition) return;

    // Append the access change as its own persistent banner that stays until the
    // analyst dismisses it, rather than a toast that auto-dismisses (~5s). Each
    // transition stacks (newest first) so a rapid approve→revoke→re-grant burst
    // never silently overwrites a notice the analyst hasn't acknowledged yet.
    setAccessNotices((prev) => [
      { id: accessNoticeIdRef.current++, notice: transition, at: Date.now() },
      ...prev,
    ]);
    if (transition === "approved") {
      setIsPendingApproval(false);
      void fetchRaw();
    } else {
      setRawEvidence(null);
      setIsPendingApproval(false);
      setGrantId(null);
    }
    // The decision propagated from another analyst: refresh the header + History
    // timeline so they reflect the new state without a manual reload.
    queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(id!) });
    queryClient.invalidateQueries({ queryKey: getGetFindingHistoryQueryKey(id!) });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [myGrant]);

  const fetchRaw = async () => {
    try {
      setRawError(null);
      // Attempt to fetch raw without grant, might succeed if already granted or not required
      const response = await fetch(`/api/admin/findings/${id}/raw`);
      if (!response.ok) {
        const errData = await response.json().catch(() => null);
        throw new ApiError(response, errData, { method: "GET", url: `/api/admin/findings/${id}/raw` });
      }
      const data = await response.json();
      setRawEvidence(data);
    } catch (e: any) {
      if (e instanceof ApiError && e.status === 403) {
        const data = e.data as any;
        if (data?.break_glass_required) {
          setShowBreakGlass(true);
        } else if (data?.approval_required) {
          setIsPendingApproval(true);
          setGrantId(data.grant_id || "unknown");
        } else {
          setRawError(e);
        }
      } else {
        setRawError(e);
      }
    }
  };

  const handleBreakGlassSuccess = (grant: any) => {
    setShowBreakGlass(false);
    if (grant.pending_approval) {
      setIsPendingApproval(true);
      setGrantId(grant.id);
    } else {
      fetchRaw();
    }
  };

  if (isLoading || !finding) {
    return (
      <Layout>
        <div className="space-y-6">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-[400px] w-full" />
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        {accessNotices.length > 0 && (
          <div className="space-y-2">
            {accessNotices.length > 1 && (
              <div className="flex justify-end">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-xs text-muted-foreground"
                  onClick={() => setAccessNotices([])}
                >
                  Dismiss all ({accessNotices.length})
                </Button>
              </div>
            )}
            {accessNotices.map((entry) => (
              <AccessChangeBanner
                key={entry.id}
                notice={entry.notice}
                at={entry.at}
                onDismiss={() =>
                  setAccessNotices((prev) => prev.filter((n) => n.id !== entry.id))
                }
              />
            ))}
          </div>
        )}
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" asChild>
            <Link href="/findings">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          <div className="flex-1">
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight font-mono">{finding.id.substring(0, 8)}...</h1>
              <SeverityBadge severity={finding.severity} />
              <StatusBadge status={finding.status} />
            </div>
            <p className="text-sm text-muted-foreground font-mono mt-1">Fingerprint: {finding.fingerprint}</p>
          </div>
          
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => setShowReReview(true)}>
              <RefreshCw className="h-4 w-4 mr-2" /> Re-review
            </Button>
            {finding.status === "open" ? (
              <Button variant="outline" onClick={() => setShowResolve(true)}>
                <CheckCheck className="h-4 w-4 mr-2" /> Close Out
              </Button>
            ) : (
              <Button variant="outline" onClick={() => setShowReopen(true)}>
                <RotateCcw className="h-4 w-4 mr-2" /> Reopen
              </Button>
            )}
            <Button
              variant={rawEvidence ? "outline" : "destructive"}
              onClick={fetchRaw}
              disabled={!!rawEvidence || isPendingApproval}
            >
              {rawEvidence ? (
                <><Unlock className="h-4 w-4 mr-2" /> Raw Unlocked</>
              ) : isPendingApproval ? (
                <><AlertTriangle className="h-4 w-4 mr-2" /> Pending Approval</>
              ) : (
                <><Lock className="h-4 w-4 mr-2" /> Break Glass</>
              )}
            </Button>
          </div>
        </div>

        {isPendingApproval && (
          <Card className="border-orange-500/50 bg-orange-500/5">
            <CardContent className="pt-6 flex items-start gap-4">
              <AlertTriangle className="h-5 w-5 text-orange-500 shrink-0 mt-0.5" />
              <div>
                <h3 className="font-semibold text-orange-700 dark:text-orange-400">Two-Person Approval Required</h3>
                <p className="text-sm text-orange-600/90 dark:text-orange-300/90 mt-1">
                  Because this finding is marked as CRITICAL severity, your break-glass request must be approved by another analyst. 
                  Share this grant ID with a colleague: <code className="bg-orange-500/10 px-1 py-0.5 rounded">{grantId}</code>
                </p>
                <Button variant="outline" size="sm" className="mt-3" onClick={fetchRaw}>
                  Check Status
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Evidence</CardTitle>
                <CardDescription>
                  Log snippet containing the finding.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {rawEvidence ? (
                  <UnlockedEvidence rawEvidence={rawEvidence} onReRequest={() => setShowBreakGlass(true)} />
                ) : (
                  <div className="space-y-2">
                    <Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
                      REDACTED
                    </Badge>
                    <pre className="p-4 bg-muted rounded-md overflow-x-auto text-xs font-mono text-muted-foreground whitespace-pre-wrap">
                      {finding.redacted_evidence.snippet}
                    </pre>
                  </div>
                )}
                
                {!rawEvidence && finding.redacted_evidence.redactions.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2">Applied Redactions</h4>
                    <div className="flex flex-wrap gap-2">
                      {finding.redacted_evidence.redactions.map((r, i) => (
                        <Badge key={i} variant="secondary" className="font-mono text-xs">{r}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            <FindingHistoryCard findingId={finding.id} />
          </div>
          
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Metadata</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                <div className="grid grid-cols-2 gap-y-3">
                  <div className="text-muted-foreground">Class</div>
                  <div className="font-mono font-medium">{finding.classification}</div>
                  
                  <div className="text-muted-foreground">Subclass</div>
                  <div className="font-mono">{finding.subclass || "—"}</div>
                  
                  <div className="text-muted-foreground">Source</div>
                  <div className="font-mono">{finding.source}</div>
                  
                  <div className="text-muted-foreground">Detector</div>
                  <div className="font-mono">{finding.detector_version}</div>
                  
                  <div className="text-muted-foreground">Trust Label</div>
                  <div>
                    <Badge variant={finding.redacted_evidence.trust === "trusted" ? "default" : "secondary"}>
                      {finding.redacted_evidence.trust || "unknown"}
                    </Badge>
                  </div>
                  
                  <div className="text-muted-foreground">Occurrences</div>
                  <div className="font-mono">{finding.occurrence_count}</div>
                  
                  <div className="text-muted-foreground">First Seen</div>
                  <div className="font-mono text-xs">{safeTimestamp(finding.first_seen_at)}</div>
                  
                  <div className="text-muted-foreground">Last Seen</div>
                  <div className="font-mono text-xs">{safeTimestamp(finding.last_seen_at)}</div>
                </div>
              </CardContent>
            </Card>
            
            <AgentReviewCard finding={finding} />

            <ReviewHistoryCard findingId={finding.id} reviewStatus={finding.agent_review_status} />

            <Card>
              <CardHeader>
                <CardTitle>Agent Triage</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Discuss this finding with the compliance AI agent.
                </p>
                <Button className="w-full" asChild>
                  <Link href="/chat">
                    <MessageSquare className="h-4 w-4 mr-2" /> Start Chat
                  </Link>
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
      
      {finding && (
        <BreakGlassModal 
          open={showBreakGlass} 
          onOpenChange={setShowBreakGlass}
          findingId={finding.id}
          onSuccess={handleBreakGlassSuccess}
          defaultJustification={myGrant?.justification}
        />
      )}

      {finding && (
        <ResolveFindingModal
          open={showResolve}
          onOpenChange={setShowResolve}
          findingId={finding.id}
        />
      )}

      {finding && (
        <ReopenFindingModal
          open={showReopen}
          onOpenChange={setShowReopen}
          findingId={finding.id}
        />
      )}

      {finding && (
        <ReReviewFindingModal
          open={showReReview}
          onOpenChange={setShowReReview}
          findingId={finding.id}
        />
      )}
    </Layout>
  );
}

// Temporary to make it compile until we create MessageSquare properly
import { MessageSquare } from "lucide-react";

// ---------------------------------------------------------------------------
// M5: Multi-agent supervisor verdict card. Shows the Triage + Verifier
// verdicts that the in-process supervisor produced post-ingest, plus the
// review status (pending / in_progress / completed / failed / skipped). The
// rationale text shown here has already been PHI-scanned by the supervisor
// before persist — if PHI was detected in agent output, the supervisor
// replaces the rationale with `<REDACTED: ...>` and ledgers
// `agent.output_phi_detected`.
// ---------------------------------------------------------------------------

interface AgentReviewCardProps {
  finding: {
    agent_review_status?: string;
    triage_verdict?: unknown;
    verifier_verdict?: unknown;
    last_agent_review_at?: string | null;
  };
}

function statusBadge(status: string | undefined) {
  switch (status) {
    case "completed":
      return <Badge className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20"><CheckCircle2 className="h-3 w-3 mr-1" /> Reviewed</Badge>;
    case "in_progress":
      return <Badge variant="secondary"><Clock className="h-3 w-3 mr-1" /> In Progress</Badge>;
    case "pending":
      return <Badge variant="secondary"><Clock className="h-3 w-3 mr-1" /> Pending</Badge>;
    case "failed":
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" /> Failed</Badge>;
    case "skipped":
      return <Badge variant="outline"><HelpCircle className="h-3 w-3 mr-1" /> Skipped (budget)</Badge>;
    default:
      return <Badge variant="outline">{status ?? "unknown"}</Badge>;
  }
}

export function AgentReviewCard({ finding }: AgentReviewCardProps) {
  const triage = finding.triage_verdict as null | {
    recommended_severity: string;
    recommended_action: string;
    rationale: string;
    confidence: number;
    prompt_injection_suspected: boolean;
  };
  const verifier = finding.verifier_verdict as null | {
    verdict: string;
    rationale: string;
    confidence: number;
    prompt_injection_suspected: boolean;
    agrees_with_triage: boolean;
  };

  // While a review is in flight (pending / in_progress) show a live "reviewing…"
  // skeleton in place of the empty "No … verdict yet." copy, so the analyst sees
  // the agents are actively working rather than a card that looks finished-but-
  // empty. The parent page polls the finding on this same status (REVIEW_POLL),
  // so the verdicts swap in automatically once the supervisor persists them.
  const reviewing = isReviewActive(finding.agent_review_status);

  const reviewingPlaceholder = (which: string) => (
    <div
      className="flex items-center gap-2 text-xs text-muted-foreground"
      role="status"
      aria-live="polite"
    >
      <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
      <span>Agents reviewing… waiting for {which} verdict</span>
    </div>
  );

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2"><Bot className="h-4 w-4" /> Agent Review</CardTitle>
          {statusBadge(finding.agent_review_status)}
        </div>
        {finding.last_agent_review_at && (
          <CardDescription className="text-xs">
            {safeTimestamp(finding.last_agent_review_at)}
          </CardDescription>
        )}
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {triage ? (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-wide text-muted-foreground">Triage</span>
              <Badge variant="outline" className="font-mono text-xs">{triage.recommended_severity}</Badge>
              <Badge variant="secondary" className="font-mono text-xs">{triage.recommended_action}</Badge>
              <span className="text-xs text-muted-foreground ml-auto">conf {triage.confidence.toFixed(2)}</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">{triage.rationale}</p>
            {triage.prompt_injection_suspected && (
              <Badge variant="destructive" className="text-xs"><ShieldAlert className="h-3 w-3 mr-1" /> Prompt injection suspected</Badge>
            )}
          </div>
        ) : reviewing ? (
          reviewingPlaceholder("triage")
        ) : (
          <p className="text-xs text-muted-foreground">No triage verdict yet.</p>
        )}

        {verifier ? (
          <div className="space-y-1.5 pt-2 border-t">
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-wide text-muted-foreground">Verifier</span>
              <Badge variant="outline" className="font-mono text-xs">{verifier.verdict}</Badge>
              <Badge variant={verifier.agrees_with_triage ? "secondary" : "destructive"} className="text-xs">
                {verifier.agrees_with_triage ? "agrees" : "disagrees"}
              </Badge>
              <span className="text-xs text-muted-foreground ml-auto">conf {verifier.confidence.toFixed(2)}</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">{verifier.rationale}</p>
            {verifier.prompt_injection_suspected && (
              <Badge variant="destructive" className="text-xs"><ShieldAlert className="h-3 w-3 mr-1" /> Prompt injection suspected</Badge>
            )}
          </div>
        ) : reviewing ? (
          reviewingPlaceholder("verifier")
        ) : (
          <p className="text-xs text-muted-foreground">No verifier verdict yet.</p>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Finding lifecycle timeline. Surfaces the finding's audit-ledger history inline
// so a reviewer can understand the full incident lifecycle at a glance —
// including *why* a closed finding was reopened (and resolve / revoke notes) —
// without digging into the global Audit Ledger page. Most-recent-first, with the
// actor and timestamp on every event. Free-text reasons here were already
// content-policy scanned at write time, so they carry no raw PHI/secrets.
// ---------------------------------------------------------------------------

type HistoryEvent = {
  seq: number;
  ts: string;
  event_type: string;
  actor: Record<string, unknown>;
  payload: Record<string, unknown>;
};

export function actorLabel(actor: Record<string, unknown>): string {
  if (!actor || typeof actor !== "object") return "system";
  return (
    (actor.id as string) ||
    (actor.sub as string) ||
    (actor.kind as string) ||
    "system"
  );
}

export function eventMeta(eventType: string): {
  label: string;
  icon: React.ReactNode;
  tone: string;
} {
  switch (eventType) {
    case "finding.created":
      return { label: "Finding created", icon: <PlusCircle className="h-4 w-4" />, tone: "text-muted-foreground bg-muted border-border" };
    case "finding.resolved":
      return { label: "Closed out", icon: <CheckCheck className="h-4 w-4" />, tone: "text-emerald-600 bg-emerald-500/10 border-emerald-500/20" };
    case "finding.reopened":
      return { label: "Reopened", icon: <RotateCcw className="h-4 w-4" />, tone: "text-blue-600 bg-blue-500/10 border-blue-500/20" };
    case "agent.re_review_requested":
      return { label: "Re-review requested", icon: <RefreshCw className="h-4 w-4" />, tone: "text-violet-600 bg-violet-500/10 border-violet-500/20" };
    case "break_glass.granted":
      return { label: "Break-glass granted", icon: <KeyRound className="h-4 w-4" />, tone: "text-orange-600 bg-orange-500/10 border-orange-500/20" };
    case "break_glass.approved":
      return { label: "Break-glass approved", icon: <CheckCircle2 className="h-4 w-4" />, tone: "text-orange-600 bg-orange-500/10 border-orange-500/20" };
    case "break_glass.revoked":
      return { label: "Break-glass revoked", icon: <Ban className="h-4 w-4" />, tone: "text-orange-600 bg-orange-500/10 border-orange-500/20" };
    case "break_glass.raw_phi_accessed":
      return { label: "Raw PHI viewed", icon: <Eye className="h-4 w-4" />, tone: "text-destructive bg-destructive/10 border-destructive/20" };
    case "break_glass.approval_denied_self_approval":
      return { label: "Self-approval refused", icon: <ShieldAlert className="h-4 w-4" />, tone: "text-destructive bg-destructive/10 border-destructive/20" };
    case "policy.text_field_rejected":
      return { label: "Note rejected by policy", icon: <ShieldAlert className="h-4 w-4" />, tone: "text-destructive bg-destructive/10 border-destructive/20" };
    default:
      return { label: eventType, icon: <ShieldQuestion className="h-4 w-4" />, tone: "text-muted-foreground bg-muted border-border" };
  }
}

// Pull the human-meaningful free-text note out of the payload, mapping each
// event's note field to the one the reviewer cares about. Returns null when the
// event carries no note.
export function eventNote(eventType: string, payload: Record<string, unknown>): string | null {
  const str = (v: unknown): string | null => (typeof v === "string" && v.trim().length > 0 ? v : null);
  switch (eventType) {
    case "finding.reopened":
    case "break_glass.revoked":
      return str(payload.reason);
    case "break_glass.granted":
      return str(payload.justification);
    case "break_glass.approved":
      return str(payload.approval_note);
    default:
      return str(payload.reason) ?? str(payload.justification) ?? str(payload.approval_note);
  }
}

export function FindingHistoryCard({ findingId }: { findingId: string }) {
  const { data: events, isLoading } = useGetFindingHistory(findingId, {
    query: { queryKey: getGetFindingHistoryQueryKey(findingId) },
  });
  const list = Array.isArray(events) ? (events as HistoryEvent[]) : [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><History className="h-4 w-4" /> History</CardTitle>
        <CardDescription>Lifecycle of this finding from the audit ledger, most recent first.</CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : list.length === 0 ? (
          <p className="text-sm text-muted-foreground">No recorded events yet.</p>
        ) : (
          <ol className="relative space-y-5 border-l border-border pl-6">
            {list.map((ev, i) => {
              const meta = eventMeta(ev.event_type);
              const note = eventNote(ev.event_type, ev.payload ?? {});
              const extra =
                ev.event_type === "finding.resolved" && typeof ev.payload?.status === "string"
                  ? (ev.payload.status as string)
                  : ev.event_type === "break_glass.revoked" && ev.payload?.auto_revoked
                    ? "auto-revoked"
                    : null;
              return (
                <li key={ev.seq ?? i} className="relative">
                  <span className={`absolute -left-[31px] flex h-6 w-6 items-center justify-center rounded-full border ${meta.tone}`}>
                    {meta.icon}
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">{meta.label}</span>
                    {extra && (
                      <Badge variant="secondary" className="font-mono text-[10px]">{extra}</Badge>
                    )}
                    <Link
                      href={`/ledger?seq=${ev.seq}`}
                      className="ml-auto inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                      title="View this event's full record in the Audit Ledger"
                    >
                      <span className="font-mono">#{ev.seq}</span>
                      <ExternalLink className="h-3 w-3" />
                    </Link>
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5">
                    {actorLabel(ev.actor)} · {safeTimestamp(ev.ts)}
                  </div>
                  {note && (
                    <p className="mt-1.5 text-xs text-foreground bg-muted/50 border rounded-md px-2.5 py-1.5 whitespace-pre-wrap">
                      {note}
                    </p>
                  )}
                </li>
              );
            })}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Agent review re-run history. Each agent review (the initial post-ingest run
// plus every fix-and-replay) is grouped into a numbered attempt carrying its
// triage + verifier verdicts, reconstructed server-side from the tamper-evident
// ledger. Lets an analyst see at a glance how many times a finding was reviewed
// and why a verdict changed between re-runs. Rationale shown here was PHI-scanned
// before it landed in the immutable ledger, so it carries no raw PHI.
// ---------------------------------------------------------------------------

function outcomeBadge(outcome: ReviewAttempt["outcome"]) {
  switch (outcome) {
    case "completed":
      return <Badge className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20"><CheckCircle2 className="h-3 w-3 mr-1" /> Completed</Badge>;
    case "skipped":
      return <Badge variant="outline"><HelpCircle className="h-3 w-3 mr-1" /> Skipped (budget)</Badge>;
    case "failed":
      return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" /> Failed</Badge>;
    default:
      return <Badge variant="secondary"><Clock className="h-3 w-3 mr-1" /> Incomplete</Badge>;
  }
}

export function ReviewHistoryCard({ findingId, reviewStatus }: { findingId: string; reviewStatus?: string | null }) {
  const { data, isLoading } = useGetFindingReviewHistory(findingId, {
    query: {
      queryKey: getGetFindingReviewHistoryQueryKey(findingId),
      refetchInterval: isReviewActive(reviewStatus) ? REVIEW_POLL_INTERVAL_MS : false,
      // Don't poll review history while the tab is hidden — resumes on refocus.
      refetchIntervalInBackground: false,
    },
  });
  const attempts = data?.attempts ?? [];
  const total = data?.current_attempt ?? 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><RefreshCw className="h-4 w-4" /> Review History</CardTitle>
        <CardDescription>
          {isLoading
            ? "Loading agent review attempts…"
            : total === 0
              ? "No agent reviews have run for this finding yet."
              : `Reviewed ${total} ${total === 1 ? "time" : "times"} — most recent first.`}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 2 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : attempts.length === 0 ? (
          <p className="text-sm text-muted-foreground">No recorded review attempts yet.</p>
        ) : (
          <ol className="space-y-4">
            {attempts.map((a, i) => {
              const triage = a.triage_verdict as null | {
                recommended_severity: string;
                recommended_action: string;
                rationale: string;
                confidence: number;
                prompt_injection_suspected: boolean;
              };
              const verifier = a.verifier_verdict as null | {
                verdict: string;
                rationale: string;
                confidence: number;
                prompt_injection_suspected: boolean;
                agrees_with_triage: boolean;
              };
              const isLatest = i === 0;
              const ts = a.verifier_at ?? a.triage_at ?? null;
              return (
                <li
                  key={a.attempt}
                  className={`rounded-md border p-3 ${isLatest ? "border-primary/30 bg-primary/5" : "border-border"}`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold">Attempt #{a.attempt}</span>
                    {isLatest && (
                      <Badge variant="secondary" className="text-[10px]">latest</Badge>
                    )}
                    {outcomeBadge(a.outcome)}
                    {a.last_event_seq != null && (
                      <Link
                        href={`/ledger?seq=${a.last_event_seq}`}
                        className="ml-auto inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                        title="View this attempt's record in the Audit Ledger"
                      >
                        <span className="font-mono">#{a.last_event_seq}</span>
                        <ExternalLink className="h-3 w-3" />
                      </Link>
                    )}
                  </div>
                  {ts && (
                    <div className="text-xs text-muted-foreground mt-0.5">{safeTimestamp(ts)}</div>
                  )}

                  {triage && (
                    <div className="mt-2 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs uppercase tracking-wide text-muted-foreground">Triage</span>
                        <Badge variant="outline" className="font-mono text-xs">{triage.recommended_severity}</Badge>
                        <Badge variant="secondary" className="font-mono text-xs">{triage.recommended_action}</Badge>
                        <span className="text-xs text-muted-foreground ml-auto">conf {triage.confidence.toFixed(2)}</span>
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed">{triage.rationale}</p>
                      {triage.prompt_injection_suspected && (
                        <Badge variant="destructive" className="text-xs"><ShieldAlert className="h-3 w-3 mr-1" /> Prompt injection suspected</Badge>
                      )}
                    </div>
                  )}

                  {verifier && (
                    <div className="mt-2 space-y-1 pt-2 border-t">
                      <div className="flex items-center gap-2">
                        <span className="text-xs uppercase tracking-wide text-muted-foreground">Verifier</span>
                        <Badge variant="outline" className="font-mono text-xs">{verifier.verdict}</Badge>
                        <Badge variant={verifier.agrees_with_triage ? "secondary" : "destructive"} className="text-xs">
                          {verifier.agrees_with_triage ? "agrees" : "disagrees"}
                        </Badge>
                        <span className="text-xs text-muted-foreground ml-auto">conf {verifier.confidence.toFixed(2)}</span>
                      </div>
                      <p className="text-xs text-muted-foreground leading-relaxed">{verifier.rationale}</p>
                      {verifier.prompt_injection_suspected && (
                        <Badge variant="destructive" className="text-xs"><ShieldAlert className="h-3 w-3 mr-1" /> Prompt injection suspected</Badge>
                      )}
                    </div>
                  )}

                  {a.note && (
                    <p className="mt-2 text-xs text-foreground bg-muted/50 border rounded-md px-2.5 py-1.5 whitespace-pre-wrap">
                      {a.note}
                    </p>
                  )}
                </li>
              );
            })}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}
