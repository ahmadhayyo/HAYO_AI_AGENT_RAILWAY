import type { Request, Response, NextFunction } from "express";
import { authenticateRequest } from "../hayo/auth";

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
