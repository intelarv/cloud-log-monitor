import React from "react";
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

// #59: in-app modal replacing the browser `prompt()` previously used to collect
// break-glass revoke reasons and approval notes. A native prompt() is unstyled,
// unaccessible (no labelling, no validation, blocks the event loop), and — most
// importantly for this app — gives no affordance for the ">=10 char" approval
// rule, so an analyst only learns it was too short via a server 400. This modal
// enforces the minimum client-side (the server re-validates regardless) and is
// the same Dialog primitive used by the resolve/reopen/request flows.
interface BreakGlassNoteModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  label: string;
  placeholder?: string;
  /** When set, the note must be at least this many characters to confirm. */
  minLength?: number;
  /** Optional notes can be submitted blank (e.g. revoke reason). */
  optional?: boolean;
  confirmLabel: string;
  pending?: boolean;
  onConfirm: (note: string) => void;
}

export default function BreakGlassNoteModal({
  open,
  onOpenChange,
  title,
  description,
  label,
  placeholder,
  minLength = 0,
  optional = false,
  confirmLabel,
  pending = false,
  onConfirm,
}: BreakGlassNoteModalProps) {
  const [note, setNote] = React.useState("");

  React.useEffect(() => {
    if (open) setNote("");
  }, [open]);

  const trimmed = note.trim();
  const tooShort = !optional && trimmed.length < minLength;
  const canConfirm = optional || trimmed.length >= minLength;

  const submit = () => {
    if (!canConfirm) return;
    onConfirm(optional ? trimmed : trimmed);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[460px]">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription className="text-sm">{description}</DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-2 pt-2">
          <Label htmlFor="break-glass-note" className="text-sm">
            {label}{" "}
            {optional ? (
              <span className="text-muted-foreground font-normal">(optional)</span>
            ) : (
              <span className="text-muted-foreground font-normal">
                (min {minLength} characters)
              </span>
            )}
          </Label>
          <Textarea
            id="break-glass-note"
            placeholder={placeholder}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={2000}
            rows={3}
            disabled={pending}
          />
          {tooShort && trimmed.length > 0 ? (
            <p className="text-xs text-destructive">
              Please enter at least {minLength} characters.
            </p>
          ) : null}
        </div>

        <div className="flex justify-end pt-2 gap-2">
          <Button
            variant="ghost"
            onClick={() => onOpenChange(false)}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button onClick={submit} disabled={pending || !canConfirm}>
            {pending ? "Working…" : confirmLabel}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
