import React from "react";
import {
  useStepUpStatus,
  useStepUpRecoveryStatus,
  useStepUpRecoveryGenerate,
  useStepUpFactorRemove,
  getStepUpRecoveryStatusQueryKey,
  getStepUpStatusQueryKey,
  ApiError,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import StepUpModal from "./step-up-modal";
import { LifeBuoy, CheckCircle2, ShieldAlert, Trash2, Copy } from "lucide-react";

// Backup / recovery codes panel + "remove second factor" management action.
// Only rendered for non-dev step-up providers (dev has no enrollable factor) and
// only once a factor is verified — there is nothing to back up otherwise. Both
// the generate and remove actions require a fresh step-up, so the panel hosts
// its own StepUpModal and retries the pending action after the ceremony.
export default function RecoveryCodes() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: status, isLoading } = useStepUpStatus();

  const nonDev = !!status && status.provider !== "dev";
  const { data: recovery } = useStepUpRecoveryStatus({
    query: {
      enabled: nonDev && !!status?.verified,
      queryKey: getStepUpRecoveryStatusQueryKey(),
    },
  });
  const generate = useStepUpRecoveryGenerate();
  const removeFactor = useStepUpFactorRemove();

  const [codes, setCodes] = React.useState<string[] | null>(null);
  const [showStepUp, setShowStepUp] = React.useState(false);
  const [stepUpReason, setStepUpReason] = React.useState("Manage recovery codes");
  const [pendingAction, setPendingAction] = React.useState<
    "generate" | "remove" | null
  >(null);

  // Dev provider (and the eval-gate UI) has nothing to manage — render nothing.
  if (isLoading || !status || status.provider === "dev") return null;

  const doGenerate = async () => {
    try {
      const res = await generate.mutateAsync();
      setCodes(res.codes);
      queryClient.invalidateQueries({
        queryKey: getStepUpRecoveryStatusQueryKey(),
      });
      toast({
        title: "Backup codes generated",
        description: "Store these now — they are shown only once.",
      });
    } catch (e: any) {
      if (e instanceof ApiError && e.status === 401) {
        setPendingAction("generate");
        setStepUpReason("Generate recovery codes");
        setShowStepUp(true);
        return;
      }
      toast({
        title: "Could not generate codes",
        description:
          e instanceof ApiError && e.status === 400
            ? "Enroll and verify a second factor first."
            : e?.message ?? String(e),
        variant: "destructive",
      });
    }
  };

  const doRemove = async () => {
    try {
      await removeFactor.mutateAsync();
      setCodes(null);
      queryClient.invalidateQueries({ queryKey: getStepUpStatusQueryKey() });
      queryClient.invalidateQueries({
        queryKey: getStepUpRecoveryStatusQueryKey(),
      });
      toast({
        title: "Second factor removed",
        description: "Re-enroll a factor to restore step-up access.",
      });
    } catch (e: any) {
      if (e instanceof ApiError && e.status === 401) {
        setPendingAction("remove");
        setStepUpReason("Remove second factor");
        setShowStepUp(true);
        return;
      }
      toast({
        title: "Could not remove factor",
        description:
          e instanceof ApiError && e.status === 404
            ? "There is no enrolled factor to remove."
            : e?.message ?? String(e),
        variant: "destructive",
      });
    }
  };

  // After a successful step-up, retry whichever action triggered it.
  const handleStepUpSuccess = () => {
    setShowStepUp(false);
    const action = pendingAction;
    setPendingAction(null);
    if (action === "generate") void doGenerate();
    else if (action === "remove") void doRemove();
  };

  const copyCodes = () => {
    if (!codes) return;
    void navigator.clipboard?.writeText(codes.join("\n"));
    toast({ title: "Copied", description: "Backup codes copied to clipboard." });
  };

  const remaining = recovery?.remaining ?? 0;
  const enabled = recovery?.enabled ?? false;

  return (
    <Card className="col-span-1 md:col-span-2">
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <LifeBuoy className="h-5 w-5 text-primary" />
          Backup &amp; Recovery Codes
          {enabled ? (
            <Badge
              variant="outline"
              className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 flex items-center gap-1"
            >
              <CheckCircle2 className="h-3 w-3" /> {remaining} left
            </Badge>
          ) : (
            <Badge
              variant="outline"
              className="bg-orange-500/10 text-orange-500 border-orange-500/20 flex items-center gap-1"
            >
              <ShieldAlert className="h-3 w-3" /> None generated
            </Badge>
          )}
        </CardTitle>
        <CardDescription>
          Single-use codes that let you step up if you lose your second factor.
          Each code works once. Generating a new set invalidates any old codes.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!status.verified ? (
          <div className="p-4 border rounded-md text-sm text-muted-foreground">
            Enroll and verify a second factor above before generating backup
            codes.
          </div>
        ) : codes ? (
          // Show-once panel: the plaintext codes are visible only here, only now.
          <div className="p-4 border rounded-md space-y-3">
            <p className="text-sm font-medium text-orange-500 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" />
              Save these codes now — they will not be shown again.
            </p>
            <div
              className="grid grid-cols-2 gap-2 font-mono text-sm"
              data-testid="recovery-code-list"
            >
              {codes.map((c) => (
                <code key={c} className="bg-muted px-2 py-1 rounded text-center">
                  {c}
                </code>
              ))}
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={copyCodes}>
                <Copy className="h-4 w-4 mr-1" /> Copy
              </Button>
              <Button size="sm" onClick={() => setCodes(null)}>
                I've saved them
              </Button>
            </div>
          </div>
        ) : (
          <div className="p-4 border rounded-md space-y-3">
            <p className="text-sm text-muted-foreground">
              {enabled
                ? `You have ${remaining} unused backup code${remaining === 1 ? "" : "s"}. Regenerating replaces them with a fresh set.`
                : "Generate a set of backup codes and store them somewhere safe."}
            </p>
            <Button onClick={doGenerate} disabled={generate.isPending}>
              {generate.isPending
                ? "Generating..."
                : enabled
                  ? "Regenerate codes"
                  : "Generate backup codes"}
            </Button>
          </div>
        )}

        <div className="p-4 border rounded-md border-destructive/30 space-y-2">
          <p className="text-sm font-medium flex items-center gap-2">
            <Trash2 className="h-4 w-4 text-destructive" />
            Lost your device?
          </p>
          <p className="text-xs text-muted-foreground">
            Remove your enrolled second factor and its backup codes so you can
            start over with a fresh enrollment.
          </p>
          <Button
            variant="destructive"
            size="sm"
            onClick={doRemove}
            disabled={removeFactor.isPending}
          >
            {removeFactor.isPending ? "Removing..." : "Remove second factor"}
          </Button>
        </div>
      </CardContent>

      <StepUpModal
        open={showStepUp}
        onOpenChange={setShowStepUp}
        onSuccess={handleStepUpSuccess}
        reason={stepUpReason}
      />
    </Card>
  );
}
