import React from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useReopenFinding,
  getGetFindingQueryKey,
  getListFindingsQueryKey,
  type ReopenFindingResult,
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
import { RotateCcw } from "lucide-react";

interface ReopenFindingModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  findingId: string;
  onSuccess?: (result: ReopenFindingResult) => void;
}

export default function ReopenFindingModal({
  open,
  onOpenChange,
  findingId,
  onSuccess,
}: ReopenFindingModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const reopen = useReopenFinding();
  const [reason, setReason] = React.useState("");

  React.useEffect(() => {
    if (open) setReason("");
  }, [open]);

  const submit = async () => {
    const trimmed = reason.trim();
    try {
      const result = await reopen.mutateAsync({
        id: findingId,
        data: trimmed.length > 0 ? { reason: trimmed } : undefined,
      });

      await queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(findingId) });
      await queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey() });

      toast({
        title: result.transitioned ? "Finding reopened" : "Already open",
        description: result.transitioned
          ? "The finding has been moved back to open. Emergency access was not affected."
          : "This finding was already open. No changes were made.",
      });

      onSuccess?.(result);
      onOpenChange(false);
    } catch (e: any) {
      toast({
        title: "Could not reopen finding",
        description: e.message || "An unknown error occurred.",
        variant: "destructive",
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[460px]">
        <DialogHeader>
          <div className="flex items-center gap-2 mb-2">
            <RotateCcw className="h-5 w-5 text-muted-foreground" />
            <DialogTitle>Reopen finding</DialogTitle>
          </div>
          <DialogDescription className="text-sm">
            Move this closed finding back to open. Emergency (break-glass) access
            is not affected. You can optionally record why it is being reopened —
            this note is saved to the immutable audit ledger.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-2 pt-2">
          <Label htmlFor="reopen-reason" className="text-sm">
            Reason <span className="text-muted-foreground font-normal">(optional)</span>
          </Label>
          <Textarea
            id="reopen-reason"
            placeholder="e.g., Closed by mistake during triage; still under investigation."
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={2000}
            rows={3}
            disabled={reopen.isPending}
          />
        </div>

        <div className="flex justify-end pt-2 gap-2">
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={reopen.isPending}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={reopen.isPending}>
            <RotateCcw className="h-4 w-4 mr-2" />
            {reopen.isPending ? "Reopening…" : "Reopen"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
