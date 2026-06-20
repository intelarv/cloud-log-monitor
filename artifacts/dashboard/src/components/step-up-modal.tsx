import React from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useStepUp, useStepUpStatus } from "@workspace/api-client-react";
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
import { ShieldAlert } from "lucide-react";

const stepUpSchema = z.object({
  token: z.string().min(1, "Token required"),
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
  const { data: status } = useStepUpStatus();
  const isTotp = status?.provider === "totp";

  const form = useForm<StepUpForm>({
    resolver: zodResolver(stepUpSchema),
    defaultValues: {
      token: "", // Hint: dev-stepup
      reason: reason,
    },
  });

  // Reset form when opened
  React.useEffect(() => {
    if (open) {
      form.reset({ token: "", reason });
    }
  }, [open, form, reason]);

  const onSubmit = async (data: StepUpForm) => {
    try {
      await stepUp.mutateAsync({ data });
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px] border-orange-500/20">
        <DialogHeader>
          <div className="flex items-center gap-2 text-orange-500 mb-2">
            <ShieldAlert className="h-5 w-5" />
            <DialogTitle>MFA Step-up Required</DialogTitle>
          </div>
          <DialogDescription>
            This action requires elevated privileges. Please provide your MFA token to continue.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="token"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{isTotp ? "Authenticator code" : "MFA Token"}</FormLabel>
                  <FormControl>
                    {isTotp ? (
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
                  {isTotp ? (
                    <p className="text-[10px] text-muted-foreground mt-1">Enter the 6-digit code from your authenticator app.</p>
                  ) : (
                    <p className="text-[10px] text-muted-foreground mt-1">Dev hint: use <code className="bg-muted px-1">dev-stepup</code></p>
                  )}
                  <FormMessage />
                </FormItem>
              )}
            />
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
            <div className="flex justify-end pt-4">
              <Button type="button" variant="outline" className="mr-2" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={stepUp.isPending} className="bg-orange-600 hover:bg-orange-700 text-white">
                {stepUp.isPending ? "Verifying..." : "Verify & Continue"}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
