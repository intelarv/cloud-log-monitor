import React from "react";
import Layout from "../components/layout";
import { 
  useListBreakGlassGrants, 
  useListPendingBreakGlassApprovals, 
  useReplayIngestFixture,
  useApproveBreakGlassGrant,
  useRevokeBreakGlassGrant,
  useGetMaintenanceMetrics,
  getListBreakGlassGrantsQueryKey,
  getListPendingBreakGlassApprovalsQueryKey,
  getListFindingsQueryKey,
  getListLedgerQueryKey,
  getGetFindingQueryKey,
  getGetFindingHistoryQueryKey,
  ApiError,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Play, Shield, Clock, CheckCircle2, AlertTriangle, Key, Activity, Ban, Database, Archive } from "lucide-react";
import { isPast } from "date-fns";
import { safeTimestamp, safeRelativeTime } from "../lib/format";
import { useToast } from "@/hooks/use-toast";
import StepUpModal from "../components/step-up-modal";
import BreakGlassNoteModal from "../components/break-glass-note-modal";
import TotpEnrollment from "../components/totp-enrollment";

export default function Admin() {
  const { data: activeGrants, isLoading: loadingGrants } = useListBreakGlassGrants();
  const { data: pendingApprovals, isLoading: loadingApprovals, refetch: refetchApprovals } = useListPendingBreakGlassApprovals();
  const { data: maintenance } = useGetMaintenanceMetrics();
  const replayIngest = useReplayIngestFixture();
  const approveGrant = useApproveBreakGlassGrant();
  const revokeGrant = useRevokeBreakGlassGrant();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [approvingGrantId, setApprovingGrantId] = React.useState<string | null>(null);
  const [revokingGrantId, setRevokingGrantId] = React.useState<string | null>(null);
  const [showStepUp, setShowStepUp] = React.useState(false);
  const [stepUpReason, setStepUpReason] = React.useState("Approve break-glass grant");
  // #59: after step-up succeeds we collect the revoke reason / approval note in
  // an in-app modal (not a browser prompt). `noteModal` names which flow is
  // active so a single modal component can serve both.
  const [noteModal, setNoteModal] = React.useState<
    { kind: "revoke" | "approve"; id: string } | null
  >(null);

  const handleReplay = async () => {
    try {
      const res = await replayIngest.mutateAsync();
      toast({
        title: "Ingest replay complete",
        description: `Replayed ${res.replayed} logs, delivered ${res.delivered} findings. ${res.errors} errors.`,
      });
      queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListLedgerQueryKey() });
    } catch (e: any) {
      toast({
        title: "Replay failed",
        description: e.message,
        variant: "destructive",
      });
    }
  };

  const handleApproveClick = (id: string) => {
    setApprovingGrantId(id);
    setRevokingGrantId(null);
    setStepUpReason("Approve break-glass grant");
    setShowStepUp(true);
  };

  const handleRevokeClick = (id: string) => {
    setRevokingGrantId(id);
    setApprovingGrantId(null);
    setStepUpReason("Revoke break-glass grant");
    setShowStepUp(true);
  };

  const handleStepUpSuccess = () => {
    setShowStepUp(false);
    if (revokingGrantId) {
      setNoteModal({ kind: "revoke", id: revokingGrantId });
      return;
    }
    if (approvingGrantId) {
      setNoteModal({ kind: "approve", id: approvingGrantId });
    }
  };

  const invalidateFindingQueries = (findingId: string | undefined) => {
    if (!findingId) return;
    queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(findingId) });
    queryClient.invalidateQueries({ queryKey: getGetFindingHistoryQueryKey(findingId) });
  };

  const submitRevoke = async (id: string, reason?: string) => {
    const findingId = activeGrants?.find(g => g.id === id)?.finding_id;
    try {
      await revokeGrant.mutateAsync({ id, data: reason ? { reason } : {} });
      toast({ title: "Grant revoked", description: "Raw-PHI access has been cut off." });
      queryClient.invalidateQueries({ queryKey: getListBreakGlassGrantsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListPendingBreakGlassApprovalsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListLedgerQueryKey() });
      invalidateFindingQueries(findingId);
    } catch (e: any) {
      if (e instanceof ApiError && e.status === 401) {
        toast({
          title: "Step-up required",
          description: "Your step-up session expired. Click Revoke again.",
          variant: "destructive",
        });
      } else if (e instanceof ApiError && e.status === 400) {
        toast({
          title: "Reason rejected",
          description: "Your note was flagged by the content policy (possible PHI or secrets). The grant was not revoked — try again with a different note.",
          variant: "destructive",
        });
      } else if (e instanceof ApiError && e.status === 409) {
        toast({
          title: "Already revoked",
          description: "This grant has already been revoked.",
          variant: "destructive",
        });
        queryClient.invalidateQueries({ queryKey: getListBreakGlassGrantsQueryKey() });
      } else if (e instanceof ApiError && e.status === 410) {
        toast({
          title: "Grant expired",
          description: "This grant has already expired — nothing left to cut off.",
          variant: "destructive",
        });
        queryClient.invalidateQueries({ queryKey: getListBreakGlassGrantsQueryKey() });
      } else {
        toast({
          title: "Revoke failed",
          description: e?.message ?? String(e),
          variant: "destructive",
        });
      }
    } finally {
      setRevokingGrantId(null);
    }
  };

  const submitApproval = async (id: string, note: string) => {
    const findingId = pendingApprovals?.find(g => g.id === id)?.finding_id;
    try {
      await approveGrant.mutateAsync({ id, data: { approval_note: note } });
      toast({ title: "Grant approved", description: "The analyst can now view the raw finding." });
      queryClient.invalidateQueries({ queryKey: getListPendingBreakGlassApprovalsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListBreakGlassGrantsQueryKey() });
      invalidateFindingQueries(findingId);
    } catch (e: any) {
      if (e instanceof ApiError && e.status === 401) {
        toast({
          title: "Step-up required",
          description: "Your step-up session expired. Click Approve again.",
          variant: "destructive",
        });
      } else if (e instanceof ApiError && e.status === 403) {
        toast({
          title: "Self-approval refused",
          description: "You cannot approve a grant you requested. A different analyst must approve.",
          variant: "destructive",
        });
      } else {
        toast({
          title: "Approval failed",
          description: e?.message ?? String(e),
          variant: "destructive",
        });
      }
    }
  };

  return (
    <Layout>
      <div className="space-y-8">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Admin & Break-glass</h1>
          <p className="text-muted-foreground">Manage your active grants and approve requests for others.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="col-span-1 md:col-span-2">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                Your Active Grants
              </CardTitle>
              <CardDescription>Break-glass sessions you have initiated.</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Finding ID</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Granted</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Justification</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {activeGrants?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground py-6">
                        No active grants.
                      </TableCell>
                    </TableRow>
                  ) : (
                    activeGrants?.map(grant => {
                      const expired = isPast(new Date(grant.expires_at));
                      const revoked = grant.revoked_at !== null;
                      const terminal = revoked || expired;
                      const isRevoking = revokingGrantId === grant.id && revokeGrant.isPending;
                      return (
                        <TableRow key={grant.id} className="font-mono text-xs">
                          <TableCell>{grant.finding_id.substring(0,8)}</TableCell>
                          <TableCell>
                            {revoked ? (
                              <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20">Revoked</Badge>
                            ) : grant.pending_approval ? (
                              <Badge variant="outline" className="bg-orange-500/10 text-orange-500 border-orange-500/20">Pending Approval</Badge>
                            ) : expired ? (
                              <Badge variant="outline" className="bg-muted text-muted-foreground">Expired</Badge>
                            ) : (
                              <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 flex items-center w-fit gap-1">
                                <CheckCircle2 className="h-3 w-3" /> Active
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-muted-foreground">{safeTimestamp(grant.granted_at, "HH:mm:ss")}</TableCell>
                          <TableCell className={expired ? "text-muted-foreground" : "text-foreground font-semibold"}>
                            {expired ? "Expired" : safeRelativeTime(grant.expires_at)}
                          </TableCell>
                          <TableCell className="max-w-[200px] truncate" title={grant.justification}>
                            {grant.justification}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 text-destructive hover:text-destructive hover:bg-destructive/10 border-destructive/20 disabled:opacity-40"
                              disabled={terminal || isRevoking}
                              onClick={() => handleRevokeClick(grant.id)}
                            >
                              <Ban className="h-3 w-3 mr-1" />
                              {revoked ? "Revoked" : isRevoking ? "Revoking..." : "Revoke"}
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <TotpEnrollment />

          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Key className="h-5 w-5 text-orange-500" />
                Pending Approvals
              </CardTitle>
              <CardDescription>Critical severity requests waiting for your 2-person approval.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {pendingApprovals?.length === 0 ? (
                  <div className="text-sm text-muted-foreground text-center py-8 border rounded-md border-dashed">
                    No pending approvals.
                  </div>
                ) : (
                  pendingApprovals?.map(grant => (
                    <div key={grant.id} className="p-4 border rounded-md bg-orange-500/5 border-orange-500/20 space-y-3">
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="text-xs font-mono text-muted-foreground mb-1">User: {grant.user_id}</div>
                          <div className="text-sm font-semibold">Finding: {grant.finding_id.substring(0,8)}</div>
                        </div>
                        <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20 uppercase text-[10px]">
                          CRITICAL
                        </Badge>
                      </div>
                      <div className="text-xs bg-background p-2 rounded border font-mono text-muted-foreground">
                        "{grant.justification}"
                      </div>
                      <Button size="sm" className="w-full" onClick={() => handleApproveClick(grant.id)}>
                        Approve Request
                      </Button>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Activity className="h-5 w-5 text-primary" />
                System Testing
              </CardTitle>
              <CardDescription>Simulate incoming cloud logs.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="p-4 border rounded-md space-y-4">
                <p className="text-sm text-muted-foreground">
                  Replay the built-in fixture logs through the ingest pipeline to populate the dashboard with fresh findings and ledger entries.
                </p>
                <Button 
                  onClick={handleReplay} 
                  disabled={replayIngest.isPending}
                  className="w-full"
                >
                  <Play className="h-4 w-4 mr-2" />
                  {replayIngest.isPending ? "Replaying..." : "Replay Fixture Logs"}
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="col-span-1 md:col-span-2">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Database className="h-5 w-5 text-primary" />
                Cache-pruning Maintenance
              </CardTitle>
              <CardDescription>
                Activity from the two opt-in retention jobs, read from the audit ledger (counts only, this tenant). Both are off by default — zeros mean the jobs have never run here.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 border rounded-md space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold">
                    <Database className="h-4 w-4 text-muted-foreground" />
                    Memory eviction
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div>
                      <div className="text-2xl font-bold tabular-nums">{maintenance?.memory.embeddings_evicted ?? 0}</div>
                      <div className="text-[11px] text-muted-foreground uppercase tracking-wide">Embeddings evicted</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold tabular-nums">{maintenance?.memory.runs ?? 0}</div>
                      <div className="text-[11px] text-muted-foreground uppercase tracking-wide">Runs</div>
                    </div>
                    <div>
                      <div className={`text-2xl font-bold tabular-nums ${(maintenance?.memory.failures ?? 0) > 0 ? "text-destructive" : ""}`}>{maintenance?.memory.failures ?? 0}</div>
                      <div className="text-[11px] text-muted-foreground uppercase tracking-wide">Failures</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Clock className="h-3 w-3" />
                    {maintenance?.memory.last_run_at ? `Last run ${safeRelativeTime(String(maintenance.memory.last_run_at))}` : "Never run"}
                  </div>
                </div>

                <div className="p-4 border rounded-md space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold">
                    <Archive className="h-4 w-4 text-muted-foreground" />
                    Raw-evidence tiering
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-center">
                    <div>
                      <div className="text-2xl font-bold tabular-nums">{maintenance?.tiering.findings_tiered ?? 0}</div>
                      <div className="text-[11px] text-muted-foreground uppercase tracking-wide">Findings tiered</div>
                    </div>
                    <div>
                      <div className={`text-2xl font-bold tabular-nums ${(maintenance?.tiering.failures ?? 0) > 0 ? "text-destructive" : ""}`}>{maintenance?.tiering.failures ?? 0}</div>
                      <div className="text-[11px] text-muted-foreground uppercase tracking-wide">Failures</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Clock className="h-3 w-3" />
                    {maintenance?.tiering.last_run_at ? `Last run ${safeRelativeTime(String(maintenance.tiering.last_run_at))}` : "Never run"}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
      
      <StepUpModal 
        open={showStepUp} 
        onOpenChange={setShowStepUp}
        onSuccess={handleStepUpSuccess}
        reason={stepUpReason}
      />

      <BreakGlassNoteModal
        open={noteModal?.kind === "revoke"}
        onOpenChange={(v) => {
          if (!v) {
            setNoteModal(null);
            setRevokingGrantId(null);
          }
        }}
        title="Revoke break-glass access"
        description="Cut off raw-PHI access for this grant. You can optionally record why — this note is saved to the immutable audit ledger."
        label="Reason"
        placeholder="e.g., Investigation complete; access no longer needed."
        optional
        pending={revokeGrant.isPending}
        confirmLabel="Revoke access"
        onConfirm={(note) => {
          const id = noteModal!.id;
          setNoteModal(null);
          submitRevoke(id, note || undefined);
        }}
      />

      <BreakGlassNoteModal
        open={noteModal?.kind === "approve"}
        onOpenChange={(v) => {
          if (!v) {
            setNoteModal(null);
            setApprovingGrantId(null);
          }
        }}
        title="Approve break-glass request"
        description="Grant a second-analyst approval for this critical-severity request. Your justification note is saved to the immutable audit ledger."
        label="Approval justification"
        placeholder="e.g., Verified incident IR-1042 with requester; approval warranted."
        minLength={10}
        pending={approveGrant.isPending}
        confirmLabel="Approve request"
        onConfirm={(note) => {
          const id = noteModal!.id;
          setNoteModal(null);
          setApprovingGrantId(null);
          submitApproval(id, note);
        }}
      />
    </Layout>
  );
}
