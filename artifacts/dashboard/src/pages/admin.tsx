import React from "react";
import Layout from "../components/layout";
import { 
  useListBreakGlassGrants, 
  useListPendingBreakGlassApprovals, 
  useReplayIngestFixture,
  useApproveBreakGlassGrant,
  getListBreakGlassGrantsQueryKey,
  getListPendingBreakGlassApprovalsQueryKey,
  getListFindingsQueryKey,
  getListLedgerQueryKey,
  ApiError,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Play, Shield, Clock, CheckCircle2, AlertTriangle, Key, Activity } from "lucide-react";
import { format, formatDistanceToNow, isPast } from "date-fns";
import { useToast } from "@/hooks/use-toast";
import StepUpModal from "../components/step-up-modal";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function Admin() {
  const { data: activeGrants, isLoading: loadingGrants } = useListBreakGlassGrants();
  const { data: pendingApprovals, isLoading: loadingApprovals, refetch: refetchApprovals } = useListPendingBreakGlassApprovals();
  const replayIngest = useReplayIngestFixture();
  const approveGrant = useApproveBreakGlassGrant();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [approvingGrantId, setApprovingGrantId] = React.useState<string | null>(null);
  const [showStepUp, setShowStepUp] = React.useState(false);

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
    setShowStepUp(true);
  };

  const handleStepUpSuccess = () => {
    setShowStepUp(false);
    const note = prompt("Enter approval justification note (≥10 chars):");
    if (note && approvingGrantId) {
      submitApproval(approvingGrantId, note);
    }
  };

  const submitApproval = async (id: string, note: string) => {
    try {
      await approveGrant.mutateAsync({ id, data: { approval_note: note } });
      toast({ title: "Grant approved", description: "The analyst can now view the raw finding." });
      queryClient.invalidateQueries({ queryKey: getListPendingBreakGlassApprovalsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListBreakGlassGrantsQueryKey() });
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
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {activeGrants?.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground py-6">
                        No active grants.
                      </TableCell>
                    </TableRow>
                  ) : (
                    activeGrants?.map(grant => {
                      const expired = isPast(new Date(grant.expires_at));
                      return (
                        <TableRow key={grant.id} className="font-mono text-xs">
                          <TableCell>{grant.finding_id.substring(0,8)}</TableCell>
                          <TableCell>
                            {grant.pending_approval ? (
                              <Badge variant="outline" className="bg-orange-500/10 text-orange-500 border-orange-500/20">Pending Approval</Badge>
                            ) : expired ? (
                              <Badge variant="outline" className="bg-muted text-muted-foreground">Expired</Badge>
                            ) : (
                              <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 flex items-center w-fit gap-1">
                                <CheckCircle2 className="h-3 w-3" /> Active
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-muted-foreground">{format(new Date(grant.granted_at), "HH:mm:ss")}</TableCell>
                          <TableCell className={expired ? "text-muted-foreground" : "text-foreground font-semibold"}>
                            {expired ? "Expired" : formatDistanceToNow(new Date(grant.expires_at), { addSuffix: true })}
                          </TableCell>
                          <TableCell className="max-w-[200px] truncate" title={grant.justification}>
                            {grant.justification}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

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
        </div>
      </div>
      
      <StepUpModal 
        open={showStepUp} 
        onOpenChange={setShowStepUp}
        onSuccess={handleStepUpSuccess}
        reason="Approve break-glass grant"
      />
    </Layout>
  );
}
