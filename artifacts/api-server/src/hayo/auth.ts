import { SignJWT, jwtVerify } from "jose";
import type { Request, Response } from "express";
import { db } from "@workspace/db";
import { users } from "@workspace/db/schema";
import { eq } from "drizzle-orm";
import type { User } from "@workspace/db/schema";
import { createHash, randomBytes, scryptSync, timingSafeEqual } from "crypto";
import { SESSION_SECRET } from "../lib/secrets";

const COOKIE_NAME = "app_session_id";
const JWT_SECRET = new TextEncoder().encode(SESSION_SECRET);
const SESSION_TTL = "30d"; // shorter-lived sessions reduce stolen-token exposure

export { COOKIE_NAME };

/**
 * Platform owner email. The owner ALWAYS has admin privileges — this is the
 * single source of truth (env-overridable). Enforced on every request in
 * authenticateRequest so the owner can never be silently downgraded to a
 * regular/trial account by any DB drift, reseed, or race.
 */
export const OWNER_EMAIL = (process.env.OWNER_EMAIL || "Fmf0038@gmail.com").trim();
export function isOwnerEmail(email: string | null | undefined): boolean {
  return !!email && email.toLowerCase() === OWNER_EMAIL.toLowerCase();
}

const SCRYPT_PREFIX = "scrypt$";

/**
 * Hash a password with scrypt (memory-hard KDF, built into Node — no extra
 * dependency) using a unique random salt per user. Output: "scrypt$<salt>$<hash>".
 */
export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const derived = scryptSync(password, salt, 64).toString("hex");
  return `${SCRYPT_PREFIX}${salt}$${derived}`;
}

/** Legacy (insecure) scheme kept only so pre-existing accounts can still log in. */
function legacyHash(password: string): string {
  const salt = createHash("sha256").update(password + "hayo-salt").digest("hex");
  return createHash("sha256").update(password + salt).digest("hex");
}

/** Constant-time verify supporting both the new scrypt format and legacy hashes. */
export function verifyPassword(password: string, stored: string): boolean {
  if (!stored) return false;
  if (stored.startsWith(SCRYPT_PREFIX)) {
    const parts = stored.split("$");
    const salt = parts[1], hash = parts[2];
    if (!salt || !hash) return false;
    const derived = scryptSync(password, salt, 64);
    const expected = Buffer.from(hash, "hex");
    return derived.length === expected.length && timingSafeEqual(derived, expected);
  }
  // Legacy sha256 hash — constant-time compare.
  const legacy = Buffer.from(legacyHash(password));
  const stored2 = Buffer.from(stored);
  return legacy.length === stored2.length && timingSafeEqual(legacy, stored2);
}

/** True if a stored hash uses the old scheme and should be re-hashed on next login. */
export function isLegacyHash(stored: string): boolean {
  return !!stored && !stored.startsWith(SCRYPT_PREFIX);
}

export async function createSessionToken(userId: number, role: string): Promise<string> {
  return new SignJWT({ userId, role })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(SESSION_TTL)
    .sign(JWT_SECRET);
}

export async function verifySessionToken(token: string): Promise<{ userId: number; role: string } | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return { userId: payload.userId as number, role: payload.role as string };
  } catch {
    return null;
  }
}

export async function authenticateRequest(req: Request): Promise<User | null> {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return null;

  // If database is not available, cannot authenticate
  if (!db) {
    console.warn("[Auth] Database not available — authentication skipped");
    return null;
  }

  const payload = await verifySessionToken(token);
  if (!payload) return null;

  try {
    const result = await db.select().from(users).where(eq(users.id, payload.userId)).limit(1);
    const user = result[0] ?? null;
    if (!user) return null;

    // The owner ALWAYS resolves as admin, on every request. This makes owner
    // privileges immune to any DB role drift/reseed/race that previously caused
    // the account to appear as a regular "trial" user after a refresh/navigation.
    if (isOwnerEmail(user.email) && user.role !== "admin") {
      user.role = "admin";
      // Self-heal the stored role in the background (best-effort, non-blocking).
      db.update(users).set({ role: "admin" }).where(eq(users.id, user.id))
        .catch((e: any) => console.warn("[Auth] owner role self-heal failed:", e?.message));
    }
    return user;
  } catch (err: any) {
    console.warn("[Auth] Failed to fetch user from database:", err.message);
    return null;
  }
}

export function getSessionCookieOptions(req: Request) {
  const isSecure = req.headers["x-forwarded-proto"] === "https" || req.secure;
  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: isSecure ? ("none" as const) : ("lax" as const),
    path: "/",
  };
}

const THIRTY_DAYS_MS = 1000 * 60 * 60 * 24 * 30;

export function setCookie(res: Response, req: Request, token: string) {
  const opts = getSessionCookieOptions(req);
  // Cookie lifetime matches the JWT TTL so the two expire together.
  res.cookie(COOKIE_NAME, token, { ...opts, maxAge: THIRTY_DAYS_MS });
}

export function clearCookie(res: Response, req: Request) {
  const opts = getSessionCookieOptions(req);
  res.clearCookie(COOKIE_NAME, { ...opts, maxAge: -1 });
}
