import React from "react";
import {
  useStepUpStatus,
  useStepUpWebauthnRegisterBegin,
  useStepUpWebauthnRegisterFinish,
  getStepUpStatusQueryKey,
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
import { KeyRound, CheckCircle2, ShieldAlert } from "lucide-react";
import {
  performWebauthnRegistration,
  webauthnSupported,
} from "@/lib/webauthn-client";

// WebAuthn (passkey) enrollment panel. Only rendered when the server reports
// STEP_UP_PROVIDER=webauthn (dev/TOTP have nothing to enroll here). Mirrors the
// TOTP enrollment panel: a register button drives the platform authenticator
// ceremony (navigator.credentials.create) and confirms it server-side. No
// secret is ever shown — the private key never leaves the authenticator.
export default function WebauthnEnrollment() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: status, isLoading } = useStepUpStatus();
  const begin = useStepUpWebauthnRegisterBegin();
  const finish = useStepUpWebauthnRegisterFinish();

  const [registering, setRegistering] = React.useState(false);

  // Only the webauthn provider has a passkey to enroll. Render nothing for dev /
  // totp so those surfaces (and the eval-gate UI) are unchanged.
  if (isLoading || !status || status.provider !== "webauthn") return null;

  const supported = webauthnSupported();

  const handleRegister = async () => {
    setRegistering(true);
    try {
      const opts = await begin.mutateAsync();
      const attestation = await performWebauthnRegistration(opts);
      await finish.mutateAsync({ data: attestation });
      toast({
        title: "Passkey enrolled",
        description: "You can now use your passkey for step-up.",
      });
      queryClient.invalidateQueries({ queryKey: getStepUpStatusQueryKey() });
    } catch (e: any) {
      // navigator.credentials.create throws on user cancel / no authenticator.
      toast({
        title: "Could not register passkey",
        description: e?.message ?? String(e),
        variant: "destructive",
      });
    } finally {
      setRegistering(false);
    }
  };

  const pending = registering || begin.isPending || finish.isPending;

  return (
    <Card className="col-span-1 md:col-span-2">
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-primary" />
          Passkey (WebAuthn) Step-up
          {status.verified ? (
            <Badge
              variant="outline"
              className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 flex items-center gap-1"
            >
              <CheckCircle2 className="h-3 w-3" /> Enrolled
            </Badge>
          ) : (
            <Badge
              variant="outline"
              className="bg-orange-500/10 text-orange-500 border-orange-500/20 flex items-center gap-1"
            >
              <ShieldAlert className="h-3 w-3" /> Not enrolled
            </Badge>
          )}
        </CardTitle>
        <CardDescription>
          Your second factor for break-glass and remediation actions. Register a
          passkey (platform authenticator, security key, or biometric); the
          private key never leaves your device.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="p-4 border rounded-md space-y-4">
          {!supported ? (
            <p className="text-sm text-destructive">
              This browser does not support WebAuthn. Use a browser with passkey
              support to enroll.
            </p>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">
                {status.verified
                  ? "Your passkey is enrolled. Registering again replaces your existing passkey and requires re-confirmation."
                  : "Register a passkey to enable step-up. Until you enroll, step-up actions will be unavailable."}
              </p>
              <Button onClick={handleRegister} disabled={pending}>
                {pending
                  ? "Waiting for authenticator..."
                  : status.verified
                    ? "Re-register passkey"
                    : "Register passkey"}
              </Button>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
