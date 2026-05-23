import React from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useCreateBreakGlassGrant } from "@workspace/api-client-react";
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
import { Lock, AlertTriangle } from "lucide-react";
import StepUpModal from "./step-up-modal";
import { ApiError } from "@workspace/api-client-react";

const breakGlassSchema = z.object({
  justification: z.string().min(10, "Justification must be at least 10 characters").max(2000),
  ttl_seconds: z.coerce.number().min(60).max(900).default(300),
});

type BreakGlassForm = z.infer<typeof breakGlassSchema>;

interface BreakGlassModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  findingId: string;
  onSuccess: (grant: any) => void;
}

export default function BreakGlassModal({ open, onOpenChange, findingId, onSuccess }: BreakGlassModalProps) {
  const { toast } = useToast();
  const createGrant = useCreateBreakGlassGrant();
  
  const [showStepUp, setShowStepUp] = React.useState(false);

  const form = useForm<BreakGlassForm>({
    resolver: zodResolver(breakGlassSchema),
    defaultValues: {
      justification: "",
      ttl_seconds: 300,
    },
  });

  React.useEffect(() => {
    if (open) {
      form.reset({ justification: "", ttl_seconds: 300 });
    }
  }, [open, form]);

  const onSubmit = async (data: BreakGlassForm) => {
    try {
      const grant = await createGrant.mutateAsync({
        data: {
          finding_id: findingId,
          justification: data.justification,
          ttl_seconds: data.ttl_seconds,
        }
      });
      onSuccess(grant);
    } catch (e: any) {
      if (e instanceof ApiError && e.status === 401) {
        // Needs step-up
        setShowStepUp(true);
      } else {
        toast({
          title: "Break-glass request failed",
          description: e.message || "An unknown error occurred.",
          variant: "destructive",
        });
      }
    }
  };

  const handleStepUpSuccess = () => {
    setShowStepUp(false);
    // Auto-retry the grant creation now that we have elevated access
    form.handleSubmit(onSubmit)();
  };

  return (
    <>
      <Dialog open={open && !showStepUp} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-[500px] border-destructive/20">
          <DialogHeader>
            <div className="flex items-center gap-2 text-destructive mb-2">
              <AlertTriangle className="h-5 w-5" />
              <DialogTitle>Break-Glass Procedure</DialogTitle>
            </div>
            <DialogDescription className="text-sm">
              You are requesting to view raw, unredacted PHI/PII. This action will be securely logged to the immutable audit ledger. 
              <strong> Critical severity findings will require approval from a second analyst.</strong>
            </DialogDescription>
          </DialogHeader>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4 pt-2">
              <FormField
                control={form.control}
                name="justification"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Justification</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., Incident IR-1042 investigation" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="ttl_seconds"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Access Duration (seconds)</FormLabel>
                    <FormControl>
                      <Input type="number" min={60} max={900} {...field} className="font-mono" />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <div className="flex justify-end pt-4 gap-2">
                <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={createGrant.isPending} variant="destructive">
                  <Lock className="h-4 w-4 mr-2" />
                  {createGrant.isPending ? "Requesting..." : "Request Access"}
                </Button>
              </div>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      <StepUpModal 
        open={showStepUp} 
        onOpenChange={(v) => {
          setShowStepUp(v);
          if (!v) onOpenChange(false); // Close both if cancelled
        }}
        onSuccess={handleStepUpSuccess}
        reason={`Break-glass for ${findingId.substring(0,8)}`}
      />
    </>
  );
}
