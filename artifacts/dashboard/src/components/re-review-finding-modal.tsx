import React from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useReReviewFinding,
  getGetFindingQueryKey,
  getGetFindingHistoryQueryKey,
  getGetFindingReviewHistoryQueryKey,
  type ReReviewFindingResult,
} from "@workspace/api-client-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { RefreshCw } from "lucide-react";

interface ReReviewFindingModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  findingId: string;
  onSuccess?: (result: ReReviewFindingResult) => void;
}

export default function ReReviewFindingModal({
  open,
  onOpenChange,
  findingId,
  onSuccess,
}: ReReviewFindingModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const reReview = useReReviewFinding();
  const [reason, setReason] = React.useState("");

  React.useEffect(() => {
    if (open) setReason("");
  }, [open]);

  const submit = async () => {
    const trimmed = reason.trim();
    try {
      const result = await reReview.mutateAsync({
        id: findingId,
        data: trimmed.length > 0 ? { reason: trimmed } : undefined,
      });

      await queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(findingId) });
      await queryClient.invalidateQueries({ queryKey: getGetFindingHistoryQueryKey(findingId) });
      await queryClient.invalidateQueries({ queryKey: getGetFindingReviewHistoryQueryKey(findingId) });

      toast({
        title: "Re-review enqueued",
        description:
          "The agent review was reset to pending and re-queued. The Triage and Verifier verdicts will refresh once it runs.",
      });

      onSuccess?.(result);
      onOpenChange(false);
    } catch (e: any) {
      const inProgress = e?.status === 409;
      toast({
        title: inProgress ? "Review already running" : "Could not re-review finding",
        description: inProgress
          ? "A review for this finding is already in progress. Try again once it completes."
          : e.message || "An unknown error occurred.",
        variant: "destructive",
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[460px]">
        <DialogHeader>
          <div className="flex items-center gap-2 mb-2">
            <RefreshCw className="h-5 w-5 text-muted-foreground" />
            <DialogTitle>Re-run agent review</DialogTitle>
          </div>
          <DialogDescription className="text-sm">
            Re-run the Triage and Verifier analysis for this finding from
            scratch. The current verdicts are reset to pending and a fresh review
            is queued — useful after a detector or policy change. You can
            optionally record why — this note is saved to the immutable audit
            ledger.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-2 pt-2">
          <Label htmlFor="re-review-reason" className="text-sm">
            Reason <span className="text-muted-foreground font-normal">(optional)</span>
          </Label>
          <Textarea
            id="re-review-reason"
            placeholder="e.g., Detector updated; re-running analysis to confirm the verdict."
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={2000}
            rows={3}
            disabled={reReview.isPending}
          />
        </div>

        <div className="flex justify-end pt-2 gap-2">
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={reReview.isPending}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={reReview.isPending}>
            <RefreshCw className="h-4 w-4 mr-2" />
            {reReview.isPending ? "Queuing…" : "Re-run review"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
