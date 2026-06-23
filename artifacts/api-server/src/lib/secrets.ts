/**
 * Centralised secret resolution.
 *
 * Goals:
 *  - NEVER ship a hard-coded production secret. In production a missing secret
 *    is a fatal misconfiguration and the process refuses to start (failing
 *    closed is safer than running wide-open with a public default).
 *  - In development we allow an ephemeral random fallback so local work keeps
 *    flowing, but we log a loud warning so it is never mistaken for real.
 *  - Encryption key falls back to the session secret for BACKWARD COMPATIBILITY
 *    so that broker credentials already encrypted with the old key remain
 *    decryptable; set ENCRYPTION_KEY explicitly to migrate to a dedicated key.
 */

import { randomBytes } from "crypto";

const isProduction = process.env.NODE_ENV === "production";

/** Resolve a required secret. Throws in production if absent. */
function requireSecret(name: string, value: string | undefined): string {
  if (value && value.trim().length > 0) return value;
  if (isProduction) {
    throw new Error(
      `[FATAL] Environment variable ${name} is required in production but is not set. ` +
        `Set it in your Railway service variables before deploying.`,
    );
  }
  const ephemeral = randomBytes(32).toString("hex");
  console.warn(
    `[secrets] ⚠️  ${name} is not set — using a random ephemeral value for DEV only. ` +
      `Sessions/encryption will reset on restart. Set ${name} for stable behaviour.`,
  );
  return ephemeral;
}

/** Secret used to sign session JWTs. */
export const SESSION_SECRET: string = requireSecret(
  "SESSION_SECRET",
  process.env.SESSION_SECRET,
);

/**
 * Secret used to encrypt credentials at rest. Prefers a dedicated ENCRYPTION_KEY
 * but falls back to SESSION_SECRET (the historical key) so previously-encrypted
 * data stays readable.
 */
export const ENCRYPTION_KEY: string =
  process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.trim().length > 0
    ? process.env.ENCRYPTION_KEY
    : SESSION_SECRET;
