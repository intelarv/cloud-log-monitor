import React from "react";
import Layout from "../components/layout";
import { useGetFinding, useGetFindingRaw, getGetFindingQueryKey } from "@workspace/api-client-react";
import { useParams, Link } from "wouter";
import { SeverityBadge, StatusBadge } from "../components/severity-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ArrowLeft, ShieldAlert, Lock, Unlock, AlertTriangle, ExternalLink, Bot, CheckCircle2, XCircle, Clock, HelpCircle } from "lucide-react";
import { format } from "date-fns";
import BreakGlassModal from "../components/break-glass-modal";
import { ApiError } from "@workspace/api-client-react";

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: finding, isLoading } = useGetFinding(id!, { query: { enabled: !!id, queryKey: getGetFindingQueryKey(id!) } });
  
  const [showBreakGlass, setShowBreakGlass] = React.useState(false);
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
                      <span className="text-xs text-muted-foreground">Expires {format(new Date(rawEvidence.grant_expires_at), "HH:mm:ss")}</span>
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
                  <div className="font-mono text-xs">{format(new Date(finding.first_seen_at), "yyyy-MM-dd HH:mm:ss")}</div>
                  
                  <div className="text-muted-foreground">Last Seen</div>
                  <div className="font-mono text-xs">{format(new Date(finding.last_seen_at), "yyyy-MM-dd HH:mm:ss")}</div>
                </div>
              </CardContent>
            </Card>
            
            <AgentReviewCard finding={finding} />

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
            {format(new Date(finding.last_agent_review_at), "yyyy-MM-dd HH:mm:ss")}
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
