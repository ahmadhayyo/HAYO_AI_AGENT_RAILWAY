#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Runtime Crypto Solver (crypto_solver.py)
========================================================
يستهدف الأسرار **المشفّرة**: يأخذ المفاتيح والنصوص المشفّرة التي التقطتها خطافات
Frida وقت التشغيل (key_hex/iv_hex/input_hex/output_hex + أي blob مشفّر) ويُجرّب فكّها
(AES-CBC/ECB 128/192/256، المفتاح خام/hex/base64/sha256/md5، IV ملتقط/صفري/مُسبَّق).
كل نص واضح ناتج = سرّ مشفّر تمّ كشفه. هذا هو المفتاح لهزيمة التطبيقات التي تشفّر أسرارها.
"""
import base64
import hashlib
import re

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _apad
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    _OK = True
except Exception:
    _OK = False


def _rsa_decrypt(pem, ct_bytes):
    """فكّ نص مشفّر بـ RSA باستخدام مفتاح خاص ملتقط (PKCS1v15 / OAEP-SHA1/256)."""
    try:
        key = load_pem_private_key(pem.encode() if isinstance(pem, str) else pem,
                                   password=None, backend=default_backend())
    except Exception:
        return None
    pads = [_apad.PKCS1v15(),
            _apad.OAEP(mgf=_apad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            _apad.OAEP(mgf=_apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)]
    for pad in pads:
        try:
            pt = key.decrypt(ct_bytes, pad)
            m = _meaningful(pt)
            if m:
                return m
        except Exception:
            pass
    return None


def _pbkdf2(password, salt, iters, length):
    try:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt,
                         iterations=iters, backend=default_backend())
        return kdf.derive(password if isinstance(password, bytes) else password.encode())
    except Exception:
        return None

# أنماط تدل على أن النص المفكوك سرّ حقيقي (لا ضجيج)
_INTEREST = re.compile(
    r"(AIza|AKIA|ASIA|sk_live|sk-|eyJ|BEGIN|firebase|\.supabase\.co|amazonaws|"
    r"password|passwd|secret|token|api[_-]?key|bearer|mongodb|postgres|https?://|"
    r"[؀-ۿ]{3,})", re.I)


def _printable_ratio(t):
    if not t:
        return 0.0
    ok = sum(1 for c in t if 32 <= ord(c) < 127 or 0x600 <= ord(c) <= 0x6FF or c in "\t\n\r")
    return ok / len(t)


def _meaningful(pt_bytes):
    try:
        t = pt_bytes.decode("utf-8")
    except Exception:
        return None
    t = t.strip("\x00").strip()
    if len(t) < 4:
        return None
    if _printable_ratio(t) >= 0.85 and (_INTEREST.search(t) or _printable_ratio(t) >= 0.95):
        return t
    return None


def _to_bytes(s):
    """يحوّل سلسلة (hex أو base64 أو نص) إلى بايتات مرشّحة للنص المشفّر."""
    outs = []
    s = s.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        try: outs.append(bytes.fromhex(s))
        except Exception: pass
    try:
        b = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
        if len(b) >= 16:
            outs.append(b)
    except Exception:
        pass
    return outs


def _key_variants(k):
    """كل الاشتقاقات الشائعة للمفتاح (hex/utf8/base64/sha256/md5) بأحجام AES صحيحة."""
    raw = []
    if re.fullmatch(r"[0-9a-fA-F]+", k) and len(k) % 2 == 0:
        try: raw.append(bytes.fromhex(k))
        except Exception: pass
    raw.append(k.encode("utf-8", "ignore"))
    try:
        raw.append(base64.b64decode(k + "=" * (-len(k) % 4), validate=False))
    except Exception:
        pass
    raw.append(hashlib.sha256(k.encode("utf-8", "ignore")).digest())
    raw.append(hashlib.md5(k.encode("utf-8", "ignore")).digest())
    # اشتقاق PBKDF2 (المفتاح من كلمة مرور) — أملاح وتكرارات شائعة في تطبيقات أندرويد
    for salt in (b"", k.encode("utf-8", "ignore")[:16], b"salt", b"0000000000000000"):
        for iters in (1000, 10000):
            for dk in (16, 32):
                d = _pbkdf2(k, salt, iters, dk)
                if d:
                    raw.append(d)
    out = set()
    for v in raw:
        if not v:
            continue
        for size in (16, 24, 32):
            out.add(v[:size] if len(v) >= size else v.ljust(size, b"\x00"))
    return list(out)


def _aes_try(key, ct, ivs):
    found = []
    # ECB
    try:
        if len(ct) >= 16 and len(ct) % 16 == 0:
            d = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
            pt = d.update(ct) + d.finalize()
            m = _meaningful(_strip_pkcs7(pt))
            if m: found.append(m)
    except Exception:
        pass
    # CBC / CTR (IV ملتقط، صفري، أو مُسبَّق في أول 16 بايت)
    for iv in ivs:
        if not iv or len(iv) != 16:
            continue
        for data in (ct, ct[16:]):
            if len(data) < 16:
                continue
            # CBC (يتطلب مضاعف 16)
            if len(data) % 16 == 0:
                try:
                    d = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
                    pt = d.update(data) + d.finalize()
                    m = _meaningful(_strip_pkcs7(pt))
                    if m: found.append(m)
                except Exception:
                    pass
            # CTR (بلا حشو، أي طول)
            try:
                d = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend()).decryptor()
                pt = d.update(data) + d.finalize()
                m = _meaningful(pt)
                if m: found.append(m)
            except Exception:
                pass
    # GCM (آخر 16 بايت = tag، IV غالباً 12 بايت في أول البيانات)
    for nonce_len in (12, 16):
        if len(ct) < nonce_len + 17:
            continue
        try:
            nonce = ct[:nonce_len]
            tag = ct[-16:]
            body = ct[nonce_len:-16]
            d = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
            pt = d.update(body) + d.finalize()
            m = _meaningful(pt)
            if m: found.append(m)
        except Exception:
            pass
    return found


def _strip_pkcs7(pt):
    if pt and 1 <= pt[-1] <= 16 and len(pt) >= pt[-1]:
        return pt[:-pt[-1]]
    return pt


class CryptoSolver:
    def __init__(self, verbose=True):
        self.verbose = verbose

    def solve(self, findings):
        """يفكّ الأسرار المشفّرة من النتائج الملتقطة. يُعيد نتائج أسرار مفكوكة."""
        if not _OK:
            return []
        keys, ivs, cts, pems = set(), set(), set(), set()
        all_blob = []
        for f in findings or []:
            raw = f.get("raw", {}) or {}
            for kf in ("key_hex", "key", "key_b64"):
                if raw.get(kf): keys.add(str(raw[kf]))
            if raw.get("iv_hex"): ivs.add(str(raw["iv_hex"]))
            for cf in ("output_hex", "input_hex", "ciphertext", "data_hex"):
                if raw.get(cf): cts.add(str(raw[cf]))
            ftype = f.get("type", "")
            if "hex_key" in ftype or "crypto_key" in ftype:
                keys.add(str(f.get("data", "")))
            blob = str(f.get("detail", "")) + " " + " ".join(str(e) for e in (f.get("evidence") or []))
            all_blob.append(blob)
            for m in re.findall(r"[0-9a-fA-F]{32,512}", blob):
                cts.add(m)
            for m in re.findall(r"[A-Za-z0-9+/]{24,512}={0,2}", blob):
                cts.add(m)
        # كتل مفاتيح RSA الخاصة الكاملة (BEGIN…END) لفكّ RSA
        joined = "\n".join(all_blob)
        for m in re.findall(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
                            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", joined, re.S):
            pems.add(m)

        keys = [k for k in keys if k][:25]        # حدود لمنع الانفجار التوافقي
        cts = [c for c in cts if c][:60]
        iv_bytes = [b"\x00" * 16]
        for iv in ivs:
            iv_bytes += _to_bytes(iv)

        results, seen = [], set()
        if self.verbose and (keys and cts):
            print(f"  \033[96m[crypto-solver] محاولة فكّ {len(cts)} نص مشفّر بـ {len(keys)} مفتاح…\033[0m")
        for k in keys:
            for kv in _key_variants(k):
                for ct in cts:
                    for ctb in _to_bytes(ct):
                        for pt in _aes_try(kv, ctb, iv_bytes):
                            if pt in seen:
                                continue
                            seen.add(pt)
                            results.append({
                                "type": "decrypted_secret",
                                "title": "سرّ مشفّر تمّ فكّه",
                                "severity": "critical",
                                "detail": f"فُكّ التشفير → {pt[:120]}",
                                "evidence": [pt],
                                "data": pt,
                                "why": "نص مشفّر في التطبيق فُكّ باستخدام مفتاح مُلتقَط وقت التشغيل",
                                "phase": "crypto-solve",
                            })
                            if self.verbose:
                                print(f"    \033[92m[DECRYPTED] {pt[:60]}\033[0m")
        if self.verbose and results:
            print(f"  \033[92m[crypto-solver] كُشف {len(results)} سرّ مشفّر.\033[0m")
        return results


if __name__ == "__main__":
    # اختبار ذاتي: شفّر سرّاً ثم فكّه
    if _OK:
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        pt = b"API_KEY=AIzaSyTESTsecret12345"
        pad = 16 - (len(pt) % 16)
        data = pt + bytes([pad]) * pad
        enc = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
        ct = (enc.update(data) + enc.finalize()).hex()
        f = [{"type": "crypto_cipher_dofinal", "raw": {"key_hex": key.hex(), "output_hex": ct}, "evidence": [ct]}]
        print("Result:", CryptoSolver().solve(f))
