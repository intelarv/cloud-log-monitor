import { createHmac, timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction, RequestHandler } from "express";

const COOKIE_NAME = "phia_sess";
const DEFAULT_TTL_SECONDS = 60 * 60 * 8; // 8 hours

export interface Session {
  sub: string;
  tenant_id: string;
  exp: number;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session?: Session;
    }
  }
}

function secret(): string {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 16) {
    throw new Error(
      "SESSION_SECRET must be set and at least 16 characters long.",
    );
  }
  return s;
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function sign(payload: string): string {
  return b64url(createHmac("sha256", secret()).update(payload).digest());
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function issueCookie(res: Response, session: Omit<Session, "exp">): Session {
  const exp = Math.floor(Date.now() / 1000) + DEFAULT_TTL_SECONDS;
  const full: Session = { ...session, exp };
  const payload = b64url(Buffer.from(JSON.stringify(full)));
  const sig = sign(payload);
  const value = `${payload}.${sig}`;
  res.cookie(COOKIE_NAME, value, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: DEFAULT_TTL_SECONDS * 1000,
    path: "/",
  });
  return full;
}

export function clearCookie(res: Response): void {
  res.clearCookie(COOKIE_NAME, { path: "/" });
}

export function parseCookie(raw: string | undefined): Session | null {
  if (!raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot < 0) return null;
  const payload = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  if (!safeEqual(sig, sign(payload))) return null;
  try {
    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    ) as Session;
    if (typeof session.exp !== "number" || session.exp * 1000 < Date.now()) {
      return null;
    }
    if (!session.sub || !session.tenant_id) return null;
    return session;
  } catch {
    return null;
  }
}

export const sessionMiddleware: RequestHandler = (req, _res, next) => {
  const raw = (req as Request & { cookies?: Record<string, string> }).cookies?.[
    COOKIE_NAME
  ];
  const sess = parseCookie(raw);
  if (sess) req.session = sess;
  next();
};

export function requireSession(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (!req.session) {
    res.status(401).json({ error: "not authenticated" });
    return;
  }
  next();
}
