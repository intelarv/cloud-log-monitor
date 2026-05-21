import { Router, type IRouter } from "express";
import { InvokeGetFindingToolBody as ToolGetFindingInput, InvokeGetFindingToolResponse as FindingSchema } from "@workspace/api-zod";
import { toolRegistry } from "../lib/tools";
import { requireSession } from "../lib/auth";

const router: IRouter = Router();

// Tool invocation surface mirrors what the agent uses internally. M0 exposes
// the same handler through the API so the dashboard (or a human) can
// re-validate a finding referenced in a chat citation.
router.post(
  "/tools/get_finding",
  requireSession,
  async (req, res): Promise<void> => {
    const parsed = ToolGetFindingInput.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const result = await toolRegistry.call(
      "get_finding",
      parsed.data,
      {
        tenantId: req.session!.tenant_id,
        userId: req.session!.sub,
        agent: "chat",
      },
    );
    if (!result.ok) {
      res.status(400).json({ error: result.error });
      return;
    }
    if (result.result == null) {
      res.status(404).json({ error: "finding not found" });
      return;
    }
    const row = result.result as {
      id: string;
      tenantId: string;
      classification: string;
      subclass: string | null;
      severity: string;
      status: string;
      source: string;
      fingerprint: string;
      redactedEvidence: unknown;
      detectorVersion: string;
      firstSeenAt: Date;
      lastSeenAt: Date;
      occurrenceCount: number;
    };
    res.json(
      FindingSchema.parse({
        id: row.id,
        tenant_id: row.tenantId,
        classification: row.classification,
        subclass: row.subclass,
        severity: row.severity,
        status: row.status,
        source: row.source,
        fingerprint: row.fingerprint,
        redacted_evidence: row.redactedEvidence,
        detector_version: row.detectorVersion,
        first_seen_at: row.firstSeenAt.toISOString(),
        last_seen_at: row.lastSeenAt.toISOString(),
        occurrence_count: row.occurrenceCount,
      }),
    );
  },
);

export default router;
