import React from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  useStepUp,
  useStepUpStatus,
  useStepUpWebauthnChallenge,
  useStepUpOidcChallenge,
  useStepUpRecovery,
} from "@workspace/api-client-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { ShieldAlert, KeyRound } from "lucide-react";
import {
  performWebauthnAssertion,
  webauthnSupported,
} from "@/lib/webauthn-client";
import { runOidcPopup } from "@/lib/oidc-client";

const stepUpSchema = z.object({
  token: z.string(),
  reason: z.string().min(3, "Reason required"),
});

type StepUpForm = z.infer<typeof stepUpSchema>;

interface StepUpModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
  reason?: string;
}

export default function StepUpModal({ open, onOpenChange, onSuccess, reason = "Elevated access required" }: StepUpModalProps) {
  const { toast } = useToast();
  const stepUp = useStepUp();
  const recovery = useStepUpRecovery();
  const challenge = useStepUpWebauthnChallenge();
  const oidcChallenge = useStepUpOidcChallenge();
  const { data: status } = useStepUpStatus();
  const isTotp = status?.provider === "totp";
  const isWebauthn = status?.provider === "webauthn";
  const isOidc = status?.provider === "oidc";
  // Recovery codes are only meaningful for non-dev providers (the dev provider
  // uses a shared token and has no enrollable factor to lose).
  const recoverySupported = !!status && status.provider !== "dev";
  // When the user has lost their factor they can fall back to a single-use
  // backup code instead of running their primary ceremony.
  const [useRecovery, setUseRecovery] = React.useState(false);
  // Providers whose ceremony produces the token (no typed input field). In
  // recovery mode the user always types the code, so it is never a ceremony.
  const isCeremony = (isWebauthn || isOidc) && !useRecovery;

  // The token field is hidden for ceremony providers (webauthn/oidc produce the
  // token), so only require a typed token for the dev/totp/recovery providers.
  const resolverSchema = React.useMemo(
    () =>
      stepUpSchema.extend({
        token: isCeremony ? z.string() : z.string().min(1, "Token required"),
      }),
    [isCeremony],
  );

  const form = useForm<StepUpForm>({
    resolver: zodResolver(resolverSchema),
    defaultValues: {
      token: "", // Hint: dev-stepup
      reason: reason,
    },
  });

  // Reset form when opened
  React.useEffect(() => {
    if (open) {
      form.reset({ token: "", reason });
      setUseRecovery(false);
    }
  }, [open, form, reason]);

  const onSubmit = async (data: StepUpForm) => {
    try {
      if (useRecovery) {
        // Redeem a single-use backup code via the dedicated recovery endpoint;
        // the typed token IS the code.
        await recovery.mutateAsync({
          data: { token: data.token, reason: data.reason },
        });
      } else {
        let token = data.token;
        if (isWebauthn) {
          // Drive navigator.credentials.get() against a fresh single-use
          // challenge; the resulting assertion JSON is the step-up token.
          const opts = await challenge.mutateAsync();
          token = await performWebauthnAssertion(opts);
        } else if (isOidc) {
          // Run the IdP redirect popup against a fresh authorization URL; the
          // returned {code,state} JSON is the step-up token the server exchanges.
          const { authorization_url } = await oidcChallenge.mutateAsync();
          const { code, state } = await runOidcPopup(authorization_url);
          token = JSON.stringify({ code, state });
        }
        await stepUp.mutateAsync({ data: { token, reason: data.reason } });
      }
      toast({
        title: "Access Elevated",
        description: "Your session has been stepped up for 5 minutes.",
      });
      onSuccess();
    } catch (e: any) {
      toast({
        title: "Step-up failed",
        description: e.message || "Invalid token.",
        variant: "destructive",
      });
    }
  };

  const pending =
    stepUp.isPending ||
    recovery.isPending ||
    challenge.isPending ||
    oidcChallenge.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px] border-orange-500/20">
        <DialogHeader>
          <div className="flex items-center gap-2 text-orange-500 mb-2">
            <ShieldAlert className="h-5 w-5" />
            <DialogTitle>MFA Step-up Required</DialogTitle>
          </div>
          <DialogDescription>
            {useRecovery
              ? "Enter one of your single-use backup codes to continue."
              : isWebauthn
                ? "This action requires elevated privileges. Use your passkey to continue."
                : isOidc
                  ? "This action requires elevated privileges. Re-authenticate with your identity provider to continue."
                  : "This action requires elevated privileges. Please provide your MFA token to continue."}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            {isCeremony ? (
              <div className="rounded-md border p-3 flex items-start gap-2 text-sm text-muted-foreground">
                <KeyRound className="h-4 w-4 mt-0.5 text-primary shrink-0" />
                <span>
                  {isOidc
                    ? "A popup will open for you to sign in with your identity provider when you continue."
                    : webauthnSupported()
                      ? "You'll be prompted to verify with your registered passkey when you continue."
                      : "This browser does not support WebAuthn. Use a browser with passkey support to step up."}
                </span>
              </div>
            ) : (
              <FormField
                control={form.control}
                name="token"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>
                      {useRecovery
                        ? "Recovery code"
                        : isTotp
                          ? "Authenticator code"
                          : "MFA Token"}
                    </FormLabel>
                    <FormControl>
                      {useRecovery ? (
                        <Input
                          placeholder="XXXX-XXXX"
                          autoComplete="one-time-code"
                          maxLength={64}
                          {...field}
                          autoFocus
                        />
                      ) : isTotp ? (
                        <Input
                          placeholder="123456"
                          inputMode="numeric"
                          autoComplete="one-time-code"
                          maxLength={6}
                          {...field}
                          autoFocus
                        />
                      ) : (
                        <Input placeholder="Enter token..." type="password" {...field} autoFocus />
                      )}
                    </FormControl>
                    {useRecovery ? (
                      <p className="text-[10px] text-muted-foreground mt-1">Enter one of your single-use backup codes.</p>
                    ) : isTotp ? (
                      <p className="text-[10px] text-muted-foreground mt-1">Enter the 6-digit code from your authenticator app.</p>
                    ) : (
                      <p className="text-[10px] text-muted-foreground mt-1">Dev hint: use <code className="bg-muted px-1">dev-stepup</code></p>
                    )}
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
            <FormField
              control={form.control}
              name="reason"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Reason</FormLabel>
                  <FormControl>
                    <Input {...field} readOnly className="bg-muted text-muted-foreground" />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {recoverySupported && (
              <button
                type="button"
                className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground"
                onClick={() => {
                  setUseRecovery((v) => !v);
                  form.setValue("token", "");
                }}
              >
                {useRecovery
                  ? "Use my second factor instead"
                  : "Lost your device? Use a recovery code"}
              </button>
            )}
            <div className="flex justify-end pt-4">
              <Button type="button" variant="outline" className="mr-2" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={
                  pending || (isWebauthn && !useRecovery && !webauthnSupported())
                }
                className="bg-orange-600 hover:bg-orange-700 text-white"
              >
                {pending
                  ? "Verifying..."
                  : useRecovery
                    ? "Verify & Continue"
                    : isWebauthn
                      ? "Use passkey & continue"
                      : isOidc
                        ? "Sign in & continue"
                        : "Verify & Continue"}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
