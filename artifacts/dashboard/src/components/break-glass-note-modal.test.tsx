import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

// ---------------------------------------------------------------------------
// Component coverage for the in-app break-glass note modal (Task #59), which
// replaced the browser `prompt()` previously used to collect revoke reasons and
// approval notes in the Admin page. Guarantees:
//   - Optional mode (revoke reason): blank submit is allowed and forwards "".
//   - Required mode (approval note, min 10): confirm is disabled until the
//     minimum length is met, and the trimmed note is forwarded on confirm.
//   - Cancel calls onOpenChange(false) and does NOT confirm.
//   - The field resets when the modal re-opens (no leaked prior note).
// ---------------------------------------------------------------------------

import BreakGlassNoteModal from "./break-glass-note-modal";

function renderModal(overrides: Partial<React.ComponentProps<typeof BreakGlassNoteModal>> = {}) {
  const onOpenChange = vi.fn();
  const onConfirm = vi.fn();
  const props: React.ComponentProps<typeof BreakGlassNoteModal> = {
    open: true,
    onOpenChange,
    title: "Revoke break-glass access",
    description: "desc",
    label: "Reason",
    confirmLabel: "Revoke access",
    onConfirm,
    ...overrides,
  };
  const utils = render(<BreakGlassNoteModal {...props} />);
  return { onOpenChange, onConfirm, ...utils };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("BreakGlassNoteModal", () => {
  it("optional mode: allows a blank submit and forwards an empty string", () => {
    const { onConfirm } = renderModal({ optional: true });
    const confirm = screen.getByRole("button", { name: "Revoke access" });
    expect(confirm).not.toBeDisabled();
    fireEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalledWith("");
  });

  it("optional mode: forwards a trimmed reason when provided", () => {
    const { onConfirm } = renderModal({ optional: true });
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "  no longer needed  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Revoke access" }));
    expect(onConfirm).toHaveBeenCalledWith("no longer needed");
  });

  it("required mode: confirm is disabled until the minimum length is met", () => {
    const { onConfirm } = renderModal({
      title: "Approve break-glass request",
      label: "Approval justification",
      confirmLabel: "Approve request",
      minLength: 10,
    });
    const confirm = screen.getByRole("button", { name: "Approve request" });
    expect(confirm).toBeDisabled();

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "short" } });
    expect(confirm).toBeDisabled();
    expect(
      screen.getByText("Please enter at least 10 characters."),
    ).toBeInTheDocument();

    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "verified incident IR-1042" },
    });
    expect(confirm).not.toBeDisabled();
    fireEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalledWith("verified incident IR-1042");
  });

  it("Cancel closes the modal without confirming", () => {
    const { onOpenChange, onConfirm } = renderModal({ optional: true });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("resets the field when re-opened", () => {
    const { rerender } = renderModal({ optional: true });
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "draft" } });
    expect(screen.getByRole("textbox")).toHaveValue("draft");

    rerender(
      <BreakGlassNoteModal
        open={false}
        onOpenChange={vi.fn()}
        title="Revoke break-glass access"
        description="desc"
        label="Reason"
        confirmLabel="Revoke access"
        optional
        onConfirm={vi.fn()}
      />,
    );
    rerender(
      <BreakGlassNoteModal
        open
        onOpenChange={vi.fn()}
        title="Revoke break-glass access"
        description="desc"
        label="Reason"
        confirmLabel="Revoke access"
        optional
        onConfirm={vi.fn()}
      />,
    );
    expect(screen.getByRole("textbox")).toHaveValue("");
  });
});
