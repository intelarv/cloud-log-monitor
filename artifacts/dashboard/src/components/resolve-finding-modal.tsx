import React from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  useResolveFinding,
  getGetFindingQueryKey,
  getListFindingsQueryKey,
  type ResolveFindingResult,
} from "@workspace/api-client-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { CheckCircle2, XCircle, ShieldOff } from "lucide-react";

type ResolveStatus = "resolved" | "false_positive";

interface ResolveFindingModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  findingId: string;
  onSuccess?: (result: ResolveFindingResult) => void;
}

export default function ResolveFindingModal({
  open,
  onOpenChange,
  findingId,
  onSuccess,
}: ResolveFindingModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const resolve = useResolveFinding();
  const [selected, setSelected] = React.useState<ResolveStatus | null>(null);

  React.useEffect(() => {
    if (open) setSelected(null);
  }, [open]);

  const submit = async (status: ResolveStatus) => {
    setSelected(status);
    try {
      const result = await resolve.mutateAsync({ id: findingId, data: { status } });

      await queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(findingId) });
      await queryClient.invalidateQueries({ queryKey: getListFindingsQueryKey() });

      const label = status === "resolved" ? "Resolved" : "False positive";
      if (!result.transitioned) {
        toast({
          title: `Already ${label.toLowerCase()}`,
          description: "This finding was already in that state. No changes were made.",
        });
      } else if (result.revoked_grants > 0) {
        toast({
          title: `Finding marked ${label.toLowerCase()}`,
          description: `${result.revoked_grants} active emergency-access ${
            result.revoked_grants === 1 ? "grant was" : "grants were"
          } automatically revoked.`,
        });
      } else {
        toast({
          title: `Finding marked ${label.toLowerCase()}`,
          description: "No active emergency-access grants needed revoking.",
        });
      }

      onSuccess?.(result);
      onOpenChange(false);
    } catch (e: any) {
      toast({
        title: "Could not close out finding",
        description: e.message || "An unknown error occurred.",
        variant: "destructive",
      });
    } finally {
      setSelected(null);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[460px]">
        <DialogHeader>
          <div className="flex items-center gap-2 mb-2">
            <ShieldOff className="h-5 w-5 text-muted-foreground" />
            <DialogTitle>Close out finding</DialogTitle>
          </div>
          <DialogDescription className="text-sm">
            Choose how to close this finding. Any active emergency (break-glass)
            access for it will be automatically revoked, ending raw-PHI access
            with the incident. This action is recorded in the audit ledger.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3 pt-2">
          <Button
            variant="outline"
            className="justify-start h-auto py-3 border-emerald-500/30 hover:bg-emerald-500/5"
            disabled={resolve.isPending}
            onClick={() => submit("resolved")}
          >
            <CheckCircle2 className="h-5 w-5 mr-3 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <span className="text-left">
              <span className="block font-medium">Resolved</span>
              <span className="block text-xs text-muted-foreground font-normal">
                A genuine finding that has been remediated or actioned.
              </span>
            </span>
            {resolve.isPending && selected === "resolved" && (
              <span className="ml-auto text-xs text-muted-foreground">Saving…</span>
            )}
          </Button>

          <Button
            variant="outline"
            className="justify-start h-auto py-3 border-slate-500/30 hover:bg-slate-500/5"
            disabled={resolve.isPending}
            onClick={() => submit("false_positive")}
          >
            <XCircle className="h-5 w-5 mr-3 text-slate-500 shrink-0" />
            <span className="text-left">
              <span className="block font-medium">False positive</span>
              <span className="block text-xs text-muted-foreground font-normal">
                Not actually PHI/PII/secrets — flagged in error.
              </span>
            </span>
            {resolve.isPending && selected === "false_positive" && (
              <span className="ml-auto text-xs text-muted-foreground">Saving…</span>
            )}
          </Button>
        </div>

        <div className="flex justify-end pt-2">
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={resolve.isPending}>
            Cancel
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
