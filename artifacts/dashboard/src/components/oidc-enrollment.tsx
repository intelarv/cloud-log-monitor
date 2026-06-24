import React from "react";
import {
  useStepUpStatus,
  useStepUpOidcRegisterBegin,
  useStepUpOidcRegisterFinish,
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
import { Building2, CheckCircle2, ShieldAlert } from "lucide-react";
import { runOidcPopup } from "@/lib/oidc-client";

// IdP-federated (OIDC) enrollment panel. Only rendered when the server reports
// STEP_UP_PROVIDER=oidc (dev/totp/webauthn have nothing to enroll here). Mirrors
// the TOTP / WebAuthn enrollment panels: a connect button runs the redirect
// ceremony (popup → IdP login → callback) and binds the verified subject to the
// user server-side. No secret is shown — the IdP owns the credential.
export default function OidcEnrollment() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: status, isLoading } = useStepUpStatus();
  const begin = useStepUpOidcRegisterBegin();
  const finish = useStepUpOidcRegisterFinish();

  const [connecting, setConnecting] = React.useState(false);

  // Only the oidc provider has an identity to enroll. Render nothing for dev /
  // totp / webauthn so those surfaces (and the eval-gate UI) are unchanged.
  if (isLoading || !status || status.provider !== "oidc") return null;

  const handleConnect = async () => {
    setConnecting(true);
    try {
      const { authorization_url } = await begin.mutateAsync();
      const { code, state } = await runOidcPopup(authorization_url);
      await finish.mutateAsync({ data: { code, state } });
      toast({
        title: "Identity provider linked",
        description: "You can now use your IdP login for step-up.",
      });
      queryClient.invalidateQueries({ queryKey: getStepUpStatusQueryKey() });
    } catch (e: any) {
      // runOidcPopup rejects on cancel / blocked popup / IdP error / timeout.
      toast({
        title: "Could not link identity provider",
        description: e?.message ?? String(e),
        variant: "destructive",
      });
    } finally {
      setConnecting(false);
    }
  };

  const pending = connecting || begin.isPending || finish.isPending;

  return (
    <Card className="col-span-1 md:col-span-2">
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <Building2 className="h-5 w-5 text-primary" />
          Identity Provider (OIDC) Step-up
          {status.verified ? (
            <Badge
              variant="outline"
              className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 flex items-center gap-1"
            >
              <CheckCircle2 className="h-3 w-3" /> Linked
            </Badge>
          ) : (
            <Badge
              variant="outline"
              className="bg-orange-500/10 text-orange-500 border-orange-500/20 flex items-center gap-1"
            >
              <ShieldAlert className="h-3 w-3" /> Not linked
            </Badge>
          )}
        </CardTitle>
        <CardDescription>
          Your second factor for break-glass and remediation actions. Link your
          organization's identity provider; step-up re-authenticates you against
          it. Credentials never touch this app.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="p-4 border rounded-md space-y-4">
          <p className="text-sm text-muted-foreground">
            {status.verified
              ? "Your identity provider is linked. Linking again re-confirms your account against the IdP."
              : "Link your identity provider to enable step-up. Until you link, step-up actions will be unavailable."}
          </p>
          <Button onClick={handleConnect} disabled={pending}>
            {pending
              ? "Waiting for identity provider..."
              : status.verified
                ? "Re-link identity provider"
                : "Link identity provider"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
