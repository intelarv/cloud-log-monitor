import React from "react";
import Layout from "../components/layout";
import {
  useGetFinding,
  useGetFindingRaw,
  useGetFindingHistory,
  useGetFindingReviewHistory,
  getGetFindingQueryKey,
  getGetFindingHistoryQueryKey,
  getGetFindingReviewHistoryQueryKey,
} from "@workspace/api-client-react";
import type { ReviewAttempt } from "@workspace/api-client-react";
import { useParams, Link } from "wouter";
import { SeverityBadge, StatusBadge } from "../components/severity-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ArrowLeft, ShieldAlert, Lock, Unlock, AlertTriangle, ExternalLink, Bot, CheckCircle2, XCircle, Clock, HelpCircle, CheckCheck, RotateCcw, RefreshCw, History, KeyRound, Eye, Ban, ShieldQuestion, PlusCircle } from "lucide-react";
import { safeTimestamp } from "../lib/format";
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

function isReviewActive(status: string | null | undefined): boolean {
  return status === "pending" || status === "in_progress";
}

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: finding, isLoading } = useGetFinding(id!, {
    query: {
      enabled: !!id,
      queryKey: getGetFindingQueryKey(id!),
      refetchInterval: (query) =>
        isReviewActive(query.state.data?.agent_review_status) ? REVIEW_POLL_INTERVAL_MS : false,
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
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20">
                        RAW PHI/PII UNLOCKED
                      </Badge>
                      <span className="text-xs text-muted-foreground">Expires {safeTimestamp(rawEvidence.grant_expires_at, "HH:mm:ss")}</span>
                    </div>
                    <pre className="p-4 bg-muted/50 rounded-md overflow-x-auto text-xs font-mono border border-destructive/20 text-foreground whitespace-pre-wrap">
                      {JSON.stringify(rawEvidence.raw_evidence, null, 2)}
                    </pre>
                  </div>
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

function AgentReviewCard({ finding }: AgentReviewCardProps) {
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
