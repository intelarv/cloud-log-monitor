import React from "react";
import Layout from "../components/layout";
import {
  useListRemediationProposals,
  useConfirmRemediationProposal,
  useRejectRemediationProposal,
  getListRemediationProposalsQueryKey,
  getListLedgerQueryKey,
  ApiError,
  type RemediationProposal,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Wrench, CheckCircle2, XCircle, Bot } from "lucide-react";
import { safeRelativeTime } from "../lib/format";
import { useToast } from "@/hooks/use-toast";
import StepUpModal from "../components/step-up-modal";

type StatusFilter = "pending" | "confirmed" | "rejected";

function StatusBadge({ status }: { status: RemediationProposal["status"] }) {
  if (status === "confirmed") {
    return (
      <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 flex items-center w-fit gap-1">
        <CheckCircle2 className="h-3 w-3" /> Confirmed
      </Badge>
    );
  }
  if (status === "rejected") {
    return (
      <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/20 flex items-center w-fit gap-1">
        <XCircle className="h-3 w-3" /> Rejected
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="bg-orange-500/10 text-orange-500 border-orange-500/20">
      Pending
    </Badge>
  );
}

export default function Remediation() {
  const [status, setStatus] = React.useState<StatusFilter>("pending");
  const { data: proposals, isLoading } = useListRemediationProposals({ status });
  const confirmProposal = useConfirmRemediationProposal();
  const rejectProposal = useRejectRemediationProposal();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [confirmingId, setConfirmingId] = React.useState<string | null>(null);
  const [showStepUp, setShowStepUp] = React.useState(false);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: getListRemediationProposalsQueryKey({ status: "pending" }) });
    queryClient.invalidateQueries({ queryKey: getListRemediationProposalsQueryKey({ status: "confirmed" }) });
    queryClient.invalidateQueries({ queryKey: getListRemediationProposalsQueryKey({ status: "rejected" }) });
    queryClient.invalidateQueries({ queryKey: getListLedgerQueryKey() });
  };

  const handleConfirmClick = (id: string) => {
    setConfirmingId(id);
    setShowStepUp(true);
  };

  const handleStepUpSuccess = () => {
    setShowStepUp(false);
    if (confirmingId) {
      const note = prompt("Optionally, why are you confirming this proposal? (leave blank to skip)");
      submitConfirm(confirmingId, note?.trim() || undefined);
    }
  };

  const submitConfirm = async (id: string, note?: string) => {
    try {
      await confirmProposal.mutateAsync({ id, data: note ? { note } : {} });
      toast({ title: "Proposal confirmed", description: "Recorded on the audit ledger. Execution stays operator-driven." });
      invalidate();
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 401) {
        toast({
          title: "Step-up required",
          description: "Your step-up session expired. Click Confirm again.",
          variant: "destructive",
        });
      } else if (e instanceof ApiError && e.status === 400) {
        toast({
          title: "Note rejected",
          description: "Your note was flagged by the content policy (possible PHI or secrets). The proposal was not confirmed — try again with a different note.",
          variant: "destructive",
        });
      } else if (e instanceof ApiError && e.status === 409) {
        toast({
          title: "Already decided",
          description: "This proposal has already been confirmed or rejected.",
          variant: "destructive",
        });
        invalidate();
      } else if (e instanceof ApiError && e.status === 404) {
        toast({ title: "Not found", description: "This proposal no longer exists.", variant: "destructive" });
        invalidate();
      } else {
        toast({ title: "Confirm failed", description: e instanceof Error ? e.message : String(e), variant: "destructive" });
      }
    } finally {
      setConfirmingId(null);
    }
  };

  const handleRejectClick = async (id: string) => {
    const note = prompt("Optionally, why are you rejecting this proposal? (leave blank to skip)");
    try {
      await rejectProposal.mutateAsync({ id, data: note?.trim() ? { note: note.trim() } : {} });
      toast({ title: "Proposal rejected", description: "The proposal stays inert and is recorded on the ledger." });
      invalidate();
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 400) {
        toast({
          title: "Note rejected",
          description: "Your note was flagged by the content policy (possible PHI or secrets). The proposal was not rejected — try again with a different note.",
          variant: "destructive",
        });
      } else if (e instanceof ApiError && e.status === 409) {
        toast({
          title: "Already decided",
          description: "This proposal has already been confirmed or rejected.",
          variant: "destructive",
        });
        invalidate();
      } else if (e instanceof ApiError && e.status === 404) {
        toast({ title: "Not found", description: "This proposal no longer exists.", variant: "destructive" });
        invalidate();
      } else {
        toast({ title: "Reject failed", description: e instanceof Error ? e.message : String(e), variant: "destructive" });
      }
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Wrench className="h-6 w-6 text-primary" />
            Remediation Proposals
          </h1>
          <p className="text-muted-foreground">
            Agent-drafted remediation proposals. They execute nothing — a human confirms (with step-up) or rejects, and the decision is ledgered.
          </p>
        </div>

        <Tabs value={status} onValueChange={(v) => setStatus(v as StatusFilter)}>
          <TabsList>
            <TabsTrigger value="pending">Pending</TabsTrigger>
            <TabsTrigger value="confirmed">Confirmed</TabsTrigger>
            <TabsTrigger value="rejected">Rejected</TabsTrigger>
          </TabsList>
        </Tabs>

        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[120px]">Action</TableHead>
                  <TableHead>Summary</TableHead>
                  <TableHead className="w-[110px]">Finding</TableHead>
                  <TableHead className="w-[140px]">Proposed by</TableHead>
                  <TableHead className="w-[110px]">Status</TableHead>
                  <TableHead className="text-right w-[110px]">Proposed</TableHead>
                  <TableHead className="w-[180px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  Array.from({ length: 4 }).map((_, i) => (
                    <TableRow key={i}>
                      {Array.from({ length: 7 }).map((__, j) => (
                        <TableCell key={j}><Skeleton className="h-5 w-full" /></TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : proposals?.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-10">
                      No {status} proposals.
                    </TableCell>
                  </TableRow>
                ) : (
                  proposals?.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell>
                        <Badge variant="secondary" className="font-mono text-[11px]">{p.action_type}</Badge>
                      </TableCell>
                      <TableCell className="max-w-[320px]">
                        <div className="font-medium truncate" title={p.summary}>{p.summary}</div>
                        <div className="text-xs text-muted-foreground truncate" title={p.rationale}>{p.rationale}</div>
                        {p.decision_note ? (
                          <div className="text-[11px] text-muted-foreground mt-1 italic truncate" title={p.decision_note}>
                            Note: {p.decision_note}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{p.finding_id.substring(0, 8)}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5 text-xs">
                          <Bot className="h-3 w-3 text-muted-foreground" />
                          <span className="font-mono truncate" title={p.proposed_by_agent}>{p.proposed_by_agent}</span>
                        </div>
                      </TableCell>
                      <TableCell><StatusBadge status={p.status} /></TableCell>
                      <TableCell className="text-right text-muted-foreground text-xs">
                        {safeRelativeTime(p.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        {p.status === "pending" ? (
                          <div className="flex items-center justify-end gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7"
                              disabled={confirmProposal.isPending || rejectProposal.isPending}
                              onClick={() => handleConfirmClick(p.id)}
                            >
                              <CheckCircle2 className="h-3 w-3 mr-1" /> Confirm
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 text-destructive hover:text-destructive hover:bg-destructive/10 border-destructive/20"
                              disabled={confirmProposal.isPending || rejectProposal.isPending}
                              onClick={() => handleRejectClick(p.id)}
                            >
                              <XCircle className="h-3 w-3 mr-1" /> Reject
                            </Button>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            {p.decided_at ? safeRelativeTime(p.decided_at) : "—"}
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      <StepUpModal
        open={showStepUp}
        onOpenChange={setShowStepUp}
        onSuccess={handleStepUpSuccess}
        reason="Confirm remediation proposal"
      />
    </Layout>
  );
}
