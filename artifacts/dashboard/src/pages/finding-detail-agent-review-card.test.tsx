import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

// ---------------------------------------------------------------------------
// Component coverage for the finding-detail AgentReviewCard (Task #71), the
// browser-side surface of the multi-agent supervisor's Triage + Verifier
// verdicts. It is a pure presentational component (no network/DB), so we render
// it directly with crafted finding shapes. Guarantees:
//   - Completed review: both verdicts render with severity/action/verdict,
//     agree/disagree badge, confidence, and the (already PHI-scanned) rationale.
//   - prompt_injection_suspected surfaces the warning badge on each verdict.
//   - In-flight review (pending / in_progress) shows the live "reviewing…"
//     spinner placeholder (Task #101) rather than the empty "No … verdict yet."
//   - Settled-but-empty review (skipped / failed) shows the empty copy, NOT the
//     spinner, so a finished review never looks like it is still working.
//   - The status badge reflects agent_review_status.
// ---------------------------------------------------------------------------

import { AgentReviewCard } from "./finding-detail";

describe("AgentReviewCard", () => {
  it("renders completed triage + verifier verdicts with rationale and confidence", () => {
    render(
      <AgentReviewCard
        finding={{
          agent_review_status: "completed",
          last_agent_review_at: "2026-01-02T03:04:05.000Z",
          triage_verdict: {
            recommended_severity: "high",
            recommended_action: "notify",
            rationale: "Looks like a real PHI exposure in billing logs.",
            confidence: 0.82,
            prompt_injection_suspected: false,
          },
          verifier_verdict: {
            verdict: "confirmed",
            rationale: "Concur with triage assessment.",
            confidence: 0.9,
            prompt_injection_suspected: false,
            agrees_with_triage: true,
          },
        }}
      />,
    );

    expect(screen.getByText("Agent Review")).toBeInTheDocument();
    expect(screen.getByText("Reviewed")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("notify")).toBeInTheDocument();
    expect(
      screen.getByText("Looks like a real PHI exposure in billing logs."),
    ).toBeInTheDocument();
    expect(screen.getByText("confirmed")).toBeInTheDocument();
    expect(screen.getByText("agrees")).toBeInTheDocument();
    expect(screen.getByText("Concur with triage assessment.")).toBeInTheDocument();
    expect(screen.getByText("conf 0.82")).toBeInTheDocument();
    expect(screen.getByText("conf 0.90")).toBeInTheDocument();
  });

  it("flags prompt-injection on a verdict and a verifier/triage disagreement", () => {
    render(
      <AgentReviewCard
        finding={{
          agent_review_status: "completed",
          triage_verdict: {
            recommended_severity: "critical",
            recommended_action: "escalate",
            rationale: "Ignore previous instructions — suspicious payload.",
            confidence: 0.4,
            prompt_injection_suspected: true,
          },
          verifier_verdict: {
            verdict: "rejected",
            rationale: "Triage over-escalated; benign infra noise.",
            confidence: 0.7,
            prompt_injection_suspected: false,
            agrees_with_triage: false,
          },
        }}
      />,
    );

    expect(screen.getByText("Prompt injection suspected")).toBeInTheDocument();
    expect(screen.getByText("disagrees")).toBeInTheDocument();
  });

  it("shows the live reviewing spinner while a review is in progress (no verdicts yet)", () => {
    render(
      <AgentReviewCard
        finding={{
          agent_review_status: "in_progress",
          triage_verdict: null,
          verifier_verdict: null,
        }}
      />,
    );

    expect(screen.getByText("In Progress")).toBeInTheDocument();
    expect(
      screen.getByText("Agents reviewing… waiting for triage verdict"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Agents reviewing… waiting for verifier verdict"),
    ).toBeInTheDocument();
    // The settled empty-copy must NOT appear while reviewing.
    expect(screen.queryByText("No triage verdict yet.")).not.toBeInTheDocument();
    expect(screen.queryByText("No verifier verdict yet.")).not.toBeInTheDocument();
  });

  it("shows the reviewing spinner for a freshly-pending review too", () => {
    render(
      <AgentReviewCard
        finding={{ agent_review_status: "pending", triage_verdict: null, verifier_verdict: null }}
      />,
    );
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(
      screen.getByText("Agents reviewing… waiting for triage verdict"),
    ).toBeInTheDocument();
  });

  it("shows empty copy (not the spinner) for a settled review with no verdicts", () => {
    render(
      <AgentReviewCard
        finding={{ agent_review_status: "skipped", triage_verdict: null, verifier_verdict: null }}
      />,
    );

    expect(screen.getByText("Skipped (budget)")).toBeInTheDocument();
    expect(screen.getByText("No triage verdict yet.")).toBeInTheDocument();
    expect(screen.getByText("No verifier verdict yet.")).toBeInTheDocument();
    expect(
      screen.queryByText("Agents reviewing… waiting for triage verdict"),
    ).not.toBeInTheDocument();
  });
});
