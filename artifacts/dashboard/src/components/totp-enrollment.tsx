import React from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  useStepUpStatus,
  useStepUpEnroll,
  useStepUpEnrollVerify,
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
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { useToast } from "@/hooks/use-toast";
import { Smartphone, CheckCircle2, ShieldAlert } from "lucide-react";

// Authenticator (TOTP) enrollment panel. Only rendered when the server reports
// STEP_UP_PROVIDER=totp (the dev provider has nothing to enroll). The secret is
// returned by the server once over the authenticated channel; it is shown here
// for QR scan / manual entry and never persisted client-side.
export default function TotpEnrollment() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: status, isLoading } = useStepUpStatus();
  const enroll = useStepUpEnroll();
  const verify = useStepUpEnrollVerify();

  const [provisioned, setProvisioned] = React.useState<{
    otpauth_uri: string;
    secret: string;
  } | null>(null);
  const [code, setCode] = React.useState("");

  // The dev provider has no enrollment surface — render nothing so the dev /
  // eval-gate UI is unchanged.
  if (isLoading || !status || status.provider !== "totp") return null;

  const handleStart = async () => {
    try {
      const res = await enroll.mutateAsync();
      setProvisioned(res);
      setCode("");
    } catch (e: any) {
      toast({
        title: "Could not start enrollment",
        description: e?.message ?? String(e),
        variant: "destructive",
      });
    }
  };

  const handleConfirm = async () => {
    try {
      await verify.mutateAsync({ data: { code } });
      toast({
        title: "Authenticator enrolled",
        description: "You can now use 6-digit codes for step-up.",
      });
      setProvisioned(null);
      setCode("");
      queryClient.invalidateQueries({ queryKey: getStepUpStatusQueryKey() });
    } catch (e: any) {
      toast({
        title: "Invalid code",
        description: "That code didn't match. Try the current code from your app.",
        variant: "destructive",
      });
    }
  };

  return (
    <Card className="col-span-1 md:col-span-2">
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2">
          <Smartphone className="h-5 w-5 text-primary" />
          Authenticator (TOTP) Step-up
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
          Your second factor for break-glass and remediation actions. Scan the QR
          code with an authenticator app, then confirm with a live code.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!provisioned ? (
          <div className="p-4 border rounded-md space-y-4">
            <p className="text-sm text-muted-foreground">
              {status.verified
                ? "Your authenticator is enrolled. Re-enrolling replaces your existing factor and requires re-confirmation."
                : "Set up an authenticator app to enable step-up. Until you enroll, step-up actions will be unavailable."}
            </p>
            <Button onClick={handleStart} disabled={enroll.isPending}>
              {enroll.isPending
                ? "Preparing..."
                : status.verified
                  ? "Re-enroll authenticator"
                  : "Set up authenticator"}
            </Button>
          </div>
        ) : (
          <div className="p-4 border rounded-md space-y-4">
            <div className="flex flex-col sm:flex-row gap-6 items-center sm:items-start">
              <div className="bg-white p-3 rounded-md">
                <QRCodeSVG value={provisioned.otpauth_uri} size={160} />
              </div>
              <div className="space-y-3 flex-1">
                <div>
                  <p className="text-sm font-medium">Can't scan?</p>
                  <p className="text-xs text-muted-foreground">
                    Enter this key manually:
                  </p>
                  <code className="text-xs bg-muted px-2 py-1 rounded break-all block mt-1">
                    {provisioned.secret}
                  </code>
                </div>
                <div className="space-y-2">
                  <p className="text-sm font-medium">Enter the 6-digit code</p>
                  <InputOTP maxLength={6} value={code} onChange={setCode}>
                    <InputOTPGroup>
                      <InputOTPSlot index={0} />
                      <InputOTPSlot index={1} />
                      <InputOTPSlot index={2} />
                      <InputOTPSlot index={3} />
                      <InputOTPSlot index={4} />
                      <InputOTPSlot index={5} />
                    </InputOTPGroup>
                  </InputOTP>
                </div>
                <div className="flex gap-2">
                  <Button
                    onClick={handleConfirm}
                    disabled={code.length !== 6 || verify.isPending}
                  >
                    {verify.isPending ? "Confirming..." : "Confirm enrollment"}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      setProvisioned(null);
                      setCode("");
                    }}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
