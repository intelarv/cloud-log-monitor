import { Router, type IRouter } from "express";
import { LoginBody as LoginInput, LoginResponse as SessionSchema } from "@workspace/api-zod";
import { issueCookie, clearCookie } from "../lib/auth";

const router: IRouter = Router();

router.post("/auth/login", async (req, res): Promise<void> => {
  const parsed = LoginInput.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const tenantId = parsed.data.tenant_id ?? "default";
  const session = issueCookie(res, { sub: parsed.data.username, tenant_id: tenantId });
  req.log.info({ sub: session.sub, tenant_id: session.tenant_id }, "login");
  res.json(SessionSchema.parse(session));
});

router.post("/auth/logout", async (_req, res): Promise<void> => {
  clearCookie(res);
  res.sendStatus(204);
});

router.get("/me", async (req, res): Promise<void> => {
  if (!req.session) {
    res.status(401).json({ error: "not authenticated" });
    return;
  }
  res.json(SessionSchema.parse(req.session));
});

export default router;
