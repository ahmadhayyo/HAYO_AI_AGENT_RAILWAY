import crypto from "crypto";
import CryptoJS from "crypto-js";
import { ENCRYPTION_KEY } from "../../lib/secrets.js";

// v2 format: "v2:" + base64(iv[12] | authTag[16] | ciphertext) using
// AES-256-GCM (authenticated — tampering is detected on decrypt).
// Values without the prefix are legacy CryptoJS passphrase-AES (MD5 KDF, no
// integrity check); they still decrypt so existing rows keep working, and are
// rewritten in v2 whenever they are next saved.
const V2_PREFIX = "v2:";
const KEY = crypto.createHash("sha256").update(ENCRYPTION_KEY, "utf8").digest();

export function encrypt(text: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const ct = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return V2_PREFIX + Buffer.concat([iv, tag, ct]).toString("base64");
}

export function decrypt(ciphertext: string): string {
  if (ciphertext.startsWith(V2_PREFIX)) {
    const raw = Buffer.from(ciphertext.slice(V2_PREFIX.length), "base64");
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ct = raw.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  }
  return CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY).toString(CryptoJS.enc.Utf8);
}
