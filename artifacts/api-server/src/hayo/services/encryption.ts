import CryptoJS from "crypto-js";
import { ENCRYPTION_KEY } from "../../lib/secrets.js";

const KEY = ENCRYPTION_KEY;

export function encrypt(text: string): string {
  return CryptoJS.AES.encrypt(text, KEY).toString();
}

export function decrypt(ciphertext: string): string {
  return CryptoJS.AES.decrypt(ciphertext, KEY).toString(CryptoJS.enc.Utf8);
}
