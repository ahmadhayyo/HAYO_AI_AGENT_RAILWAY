import type { Request, Response, NextFunction } from "express";
import { authenticateRequest } from "../hayo/auth";
import { getEffectivePlan } from "../hayo/db";

/**
 * Express middleware that rejects unauthenticated requests.
 *
 * Many REST feature routers (reverse-engineering, office, studies, agent…) were
 * previously mounted with no authentication, exposing expensive/powerful tools
 * to anonymous callers. Mount this in front of them so only logged-in users can
 * reach them. The resolved user is attached to `req.user` for handlers that need it.
 */
export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await authenticateRequest(req);
    if (!user) {
      res.status(401).json({ error: "يجب تسجيل الدخول للوصول إلى هذه الميزة (401)" });
      return;
    }
    (req as any).user = user;
    next();
  } catch {
    res.status(401).json({ error: "فشل التحقق من الجلسة (401)" });
  }
}

/**
 * Gate a REST router to the platform owner/admin only. Must be mounted AFTER
 * `requireAuth` (it reads `req.user`). Use for owner-only service surfaces such
 * as the executive self-modifying agent (`/api/agent/*`), which can write to the
 * platform's own source and run shell commands — never a subscriber feature.
 */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const user = (req as any).user as { id: number; role: string } | undefined;
  if (!user) {
    res.status(401).json({ error: "يجب تسجيل الدخول (401)" });
    return;
  }
  if (user.role !== "admin") {
    res.status(403).json({ error: "هذه الميزة مخصّصة لمالك المنصة فقط (403)" });
    return;
  }
  next();
}

/**
 * Gate a REST router behind a plan feature flag. Must be mounted AFTER
 * `requireAuth` (it reads `req.user`). Admins/owner bypass. Returns 403 with an
 * upgrade hint when the user's effective plan does not unlock the feature.
 */
export function requireFeature(gate: string) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const user = (req as any).user as { id: number; role: string } | undefined;
    if (!user) {
      res.status(401).json({ error: "يجب تسجيل الدخول (401)" });
      return;
    }
    if (user.role === "admin") {
      next();
      return;
    }
    try {
      const { plan } = await getEffectivePlan(user.id);
      if (!plan || !(plan as Record<string, unknown>)[gate]) {
        res.status(403).json({ error: "هذه الميزة تتطلب ترقية خطتك للوصول إليها." });
        return;
      }
      next();
    } catch {
      res.status(403).json({ error: "تعذّر التحقق من صلاحية الخطة." });
    }
  };
}
