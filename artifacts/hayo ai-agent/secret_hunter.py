#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Secret Hunter (secret_hunter.py)
================================================
بحث واسع وعميق عن الأسرار والمفاتيح بكل أنواعها أثناء الطور الديناميكي.
يمسح مصادر وقت-التشغيل الحقيقية:
  1) أدلة/تفاصيل كل نتيجة ديناميكية (ما التقطته خطافات Frida فعلاً),
  2) بيانات التطبيق على الجهاز (shared_prefs / databases / files / cache) عبر root,
  3) logcat (كثيراً ما تُسرَّب المفاتيح في السجل),
ببطارية أنماط شاملة + كاشف إنتروبيا صارم (تفادياً للإيجابيات الكاذبة).

الاستخدام كمكتبة:
  from secret_hunter import SecretHunter
  hunter = SecretHunter(adb, device, package)
  found = hunter.hunt(dynamic_findings)   # -> list[dict] نتائج أسرار موحّدة
"""
import base64
import math
import os
import re
import subprocess

# ── بطارية الأنماط: عالية الثقة (خاصة بمزوّد) ─────────────────────────────
HIGH_CONFIDENCE = {
    "aws_access_key":     r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b",
    "google_api_key":     r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "google_oauth_id":    r"\b\d+-[0-9A-Za-z_]{20,}\.apps\.googleusercontent\.com\b",
    "gcp_service_account": r'"type"\s*:\s*"service_account"',
    "firebase_db_url":    r"https://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)",
    "firebase_storage":   r"\b[a-z0-9\-]+\.(?:appspot\.com|firebasestorage\.app)\b",
    "stripe_secret":      r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b",
    "stripe_public":      r"\bpk_(?:live|test)_[0-9A-Za-z]{20,}\b",
    "jwt":                r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\b",
    "private_key_block":  r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    "github_token":       r"\bgh[posur]_[A-Za-z0-9]{36,}\b",
    "gitlab_pat":         r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
    "slack_token":        r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",
    "slack_webhook":      r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    "twilio_account_sid": r"\bAC[0-9a-fA-F]{32}\b",
    "twilio_api_key":     r"\bSK[0-9a-fA-F]{32}\b",
    "sendgrid_key":       r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
    "mailgun_key":        r"\bkey-[0-9a-f]{32}\b",
    "openai_key":         r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
    "anthropic_key":      r"\bsk-ant-(?:api03-)?[A-Za-z0-9_\-]{20,}\b",
    # ── مفاتيح نماذج الذكاء الاصطناعي (شائعة جداً في التطبيقات الحديثة) ──
    "openrouter_key":     r"\bsk-or-v1-[a-f0-9]{48,}\b",
    "huggingface_token":  r"\bhf_[A-Za-z0-9]{30,}\b",
    "replicate_token":    r"\br8_[A-Za-z0-9]{35,}\b",
    "groq_key":           r"\bgsk_[A-Za-z0-9]{40,}\b",
    "perplexity_key":     r"\bpplx-[A-Za-z0-9]{40,}\b",
    "cohere_key":         r"(?i)\bcohere[_\-]?(?:api[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{40})\b",
    "mistral_key":        r"(?i)\bmistral[_\-]?api[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b",
    "elevenlabs_key":     r"(?i)\b(?:xi[_\-]?api[_\-]?key|elevenlabs)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})\b",
    "stability_key":      r"\bsk-[A-Za-z0-9]{48}\b",
    "deepseek_key":       r"(?i)\bdeepseek[_\-]?(?:api[_\-]?)?key['\"]?\s*[:=]\s*['\"]?(sk-[A-Za-z0-9]{20,})\b",
    "fireworks_key":      r"\bfw_[A-Za-z0-9]{24,}\b",
    "google_fcm_server":  r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}\b",
    "revenuecat_key":     r"\b(?:appl|goog|amzn)_[A-Za-z0-9]{30,}\b",
    "onesignal_key":      r"(?i)\bonesignal[_\-]?(?:rest[_\-]?)?(?:api[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{40,})",
    "sentry_dsn":         r"https://[0-9a-f]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io/\d+",
    "algolia_key":        r"(?i)\balgolia[_\-]?(?:api[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})\b",
    "digitalocean_token": r"\bdop_v1_[a-f0-9]{64}\b",
    "cloudflare_token":   r"(?i)\bcloudflare.{0,20}?['\"]([A-Za-z0-9_\-]{40})['\"]",
    "pusher_key":         r"(?i)\bpusher.{0,20}?(?:key|secret)['\"]?\s*[:=]\s*['\"]([a-f0-9]{20,})['\"]",
    "agora_appid":        r"(?i)\bagora.{0,20}?app[_\-]?id['\"]?\s*[:=]\s*['\"]([a-f0-9]{32})['\"]",
    "square_token":       r"\bsq0[a-z]{3}-[0-9A-Za-z_\-]{22,}\b",
    "braintree_token":    r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
    "discord_token":      r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}\b",
    "telegram_bot_token": r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b",
    "supabase_url":       r"https://[a-z0-9]{15,}\.supabase\.co",
    "mongodb_uri":        r"mongodb(?:\+srv)?://[^\s\"'<>]{8,}",
    "postgres_uri":       r"postgres(?:ql)?://[^\s\"'<>]{8,}",
    "basic_auth_url":     r"https?://[^:\s/@]+:[^@\s/]{3,}@[^\s\"'<>]+",
    "azure_storage_key":  r"(?i)AccountKey=[A-Za-z0-9+/=]{40,}",
    # ── مفاتيح نماذج الذكاء الاصطناعي (AI/LLM) ──────────────────────────────
    "openai_project_key": r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b",
    "openrouter_key":     r"\bsk-or-v1-[a-f0-9]{48,}\b",
    "huggingface_token":  r"\bhf_[A-Za-z0-9]{34,}\b",
    "replicate_token":    r"\br8_[A-Za-z0-9]{37,}\b",
    "groq_key":           r"\bgsk_[A-Za-z0-9]{50,}\b",
    "perplexity_key":     r"\bpplx-[A-Za-z0-9]{40,}\b",
    "xai_key":            r"\bxai-[A-Za-z0-9]{70,}\b",
    "google_ai_studio":   r"\bAIzaSy[A-Za-z0-9_\-]{33}\b",
    "azure_openai_key":   r"(?i)(?:azure|openai)[^\n]{0,40}?['\"]([a-f0-9]{32})['\"]",
    "elevenlabs_key":     r"(?i)(?:elevenlabs|xi-api-key)[^\n]{0,30}?['\"]?([a-f0-9]{32})",
    "cohere_key":         r"(?i)cohere[^\n]{0,30}?['\"]([A-Za-z0-9]{40})['\"]",
    "mistral_key":        r"(?i)mistral[^\n]{0,30}?['\"]([A-Za-z0-9]{32})['\"]",
    # ── سحابة/SaaS إضافية ──────────────────────────────────────────────────
    "google_fcm_server":  r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{130,}\b",
    "google_oauth_refresh": r"\b1//[A-Za-z0-9_\-]{30,}\b",
    "digitalocean_token": r"\bdop_v1_[a-f0-9]{64}\b",
    "shopify_token":      r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b",
    "notion_token":       r"\b(?:secret|ntn)_[A-Za-z0-9]{40,}\b",
    "mapbox_token":       r"\b(?:pk|sk)\.[A-Za-z0-9]{20,}\.[A-Za-z0-9]{20,}\b",
    "sentry_dsn":         r"https://[a-f0-9]{16,}@[a-z0-9.\-]+\.ingest\.(?:us\.|de\.)?sentry\.io/\d+",
    "algolia_key":        r"(?i)algolia[^\n]{0,30}?['\"]([a-f0-9]{32})['\"]",
    "datadog_key":        r"(?i)(?:datadog|dd[_\-]?api[_\-]?key)[^\n]{0,30}?['\"]?([a-f0-9]{32})",
    "jdbc_url":           r"jdbc:[a-z0-9]+://[^\s\"'<>]{8,}",
    "redis_url":          r"rediss?://[^\s\"'<>]{6,}",
    "amqp_url":           r"amqps?://[^\s\"'<>]{6,}",
}

# ── أنماط سياقية: لا تُقبل إلا مع كلمة مفتاحية سرّية مجاورة ────────────────
CONTEXTUAL = {
    "generic_credential": r"(?i)\b(?:api[_\-]?key|apikey|secret|token|passwd|password|pwd|auth[_\-]?token|access[_\-]?key|private[_\-]?key|client[_\-]?secret)\b['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,80})",
    "bearer_token":       r"(?i)\bbearer\s+([A-Za-z0-9_\-\.=]{20,})",
}

# ── أنماط خام (hex/base64) تُقبل فقط بجوار كلمة مفتاحية ────────────────────
RAW_NEAR_KEYWORD = {
    "hex_key_32": r"\b[0-9a-fA-F]{32}\b",
    "hex_key_64": r"\b[0-9a-fA-F]{64}\b",
    "b64_secret": r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
}
_KW_NEAR = re.compile(r"(?i)(key|secret|token|password|passwd|pwd|auth|crypt|aes|hmac|iv|salt|seed|api|cred)")
# كلمات قوية فقط لمسار الإنتروبيا العالية (لتفادي فيضان معرّفات قواعد البيانات:
# «id/token/key» تظهر كأعمدة في كل جدول → كانت تُفجّر عشرات الإيجابيات الكاذبة)
_KW_STRONG = re.compile(r"(?i)(secret|private[_\-]?key|passwd|password|api[_\-]?key|apikey|"
                        r"access[_\-]?key|client[_\-]?secret|credential|mnemonic|seed[_ ]?phrase|bearer)")

# كلمات تدل على ضجيج (نرفض هذه القيم)
_NOISE = re.compile(r"(?i)(example|sample|test1234|xxxx|0000000000|placeholder|your[_\-]?key|<.*>|application/|text/|image/|android\.|androidx\.|com\.google\.|java\.|kotlin\.|fbsdk|feature|_index|index_|enum|schema|drawable|mipmap|attr|style)")


def _looks_wordy(s: str) -> bool:
    """سلسلة مؤلَّفة من كلمات مركّبة (CamelCase/snake) = مُعرِّف/اسم صنف لا مفتاح.
    المفاتيح الحقيقية عشوائية ولا تنقسم إلى كلمات إنجليزية."""
    parts = re.findall(r"[A-Z][a-z]{2,}|[a-z]{3,}", s)
    return len(parts) >= 3


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_identifier(s: str) -> bool:
    # يرفض أسماء الأصناف/الدوال camelCase أو المفصولة بنقاط/شرطات مائلة
    if "/" in s or s.count(".") >= 2:
        return True
    if re.match(r"^[a-z]+([A-Z][a-z0-9]+)+$", s):
        return True
    return False


def _load_own_secrets():
    """أسرار المحرك نفسه (مفاتيح LLM للعقل) — يجب ألا تُبلَّغ أبداً كأسرار التطبيق.
    خطأ فادح سابق: مفتاح OpenAI/DeepSeek كان يظهر كـ«مُستخرَج من التطبيق»."""
    own = set()
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        import json as _json
        cfg = _json.load(open(os.path.join(here, "config.json"), encoding="utf-8"))
        for k, v in cfg.items():
            if v and ("key" in k.lower() or "secret" in k.lower() or "token" in k.lower()):
                own.add(str(v).strip())
    except Exception:
        pass
    for env in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY",
                "GEMINI_API_KEY", "GROQ_API_KEY", "HAYO_API_KEY"):
        v = os.environ.get(env)
        if v:
            own.add(v.strip())
    # جذور المفاتيح (أول 20 حرفاً) لالتقاط المقتطعات أيضاً
    return {s for s in own if len(s) >= 12}


class SecretHunter:
    def __init__(self, adb="adb", device="emulator-5554", package="", verbose=True):
        self.adb = adb
        self.device = device
        self.package = package
        self.verbose = verbose
        self.seen = set()
        self.own_secrets = _load_own_secrets()   # قائمة منع ذاتية (مفاتيح العقل)
        self._he_emitted = 0                     # عدّاد نتائج الإنتروبيا (سقف ضد الفيضان)

    def _is_own_secret(self, value):
        """هل القيمة هي أحد أسرار المحرك نفسه (مفتاح العقل)؟ إن نعم لا تُبلَّغ."""
        for own in self.own_secrets:
            if own and (own in value or value in own or value[:20] == own[:20]):
                return True
        return False

    # ── مسح النص ─────────────────────────────────────────────────────────
    def scan_text(self, text, source="runtime"):
        out = []
        if not text:
            return out
        # 1) عالية الثقة
        for name, pat in HIGH_CONFIDENCE.items():
            for m in re.finditer(pat, text):
                val = m.group(0)
                self._emit(out, name, val, source, "critical" if self._is_critical(name) else "high")
        # 2) سياقية (كلمة مفتاحية + قيمة)
        for name, pat in CONTEXTUAL.items():
            for m in re.finditer(pat, text):
                val = m.group(1) if m.groups() else m.group(0)
                if val and self._plausible(val):
                    self._emit(out, name, val, source, "high")
        # 3) خام قرب كلمة مفتاحية فقط
        for name, pat in RAW_NEAR_KEYWORD.items():
            for m in re.finditer(pat, text):
                val = m.group(0)
                window = text[max(0, m.start() - 40):m.end() + 40]
                if _KW_NEAR.search(window) and self._plausible(val):
                    if name == "b64_secret":
                        # لا تقبل base64 إلا إذا فُكّ إلى نص عالي الإنتروبيا/مفتاح
                        if not self._b64_meaningful(val):
                            continue
                    self._emit(out, name, val, source, "high")
        # 4) إنتروبيا عالية صارمة: يجب أن تحوي أرقاماً وألا تكون كلمات مركّبة
        for tok in re.findall(r"[A-Za-z0-9_\-+/=]{24,80}", text):
            if tok in self.seen or not self._plausible(tok):
                continue
            n_digits = sum(c.isdigit() for c in tok)
            if (_shannon(tok) >= 4.5 and n_digits >= 3
                    and re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok)):
                idx = text.find(tok)
                window = text[max(0, idx - 30):idx + len(tok) + 30]
                # كلمة قوية فقط + سقف صارم لعدد نتائج الإنتروبيا (تفادي فيضان المعرّفات)
                if _KW_STRONG.search(window) and self._he_emitted < 8:
                    self._emit(out, "high_entropy_secret", tok, source, "low")
        return out

    def _plausible(self, val):
        """يرفض المُعرِّفات/أسماء الأصناف/الكائنات والضجيج المعروف."""
        if not val or _NOISE.search(val):
            return False
        if re.search(r"[{}<>()\[\]\s]", val):   # كائنات Java toString / وسوم
            return False
        # طوابع زمنية/تواريخ/أرقام فقط (لاتينية أو عربية) — ليست أسراراً
        if re.match(r"^[\d\u0660-\u0669T:\.\-/,]+$", val):
            return False
        if _looks_identifier(val) or _looks_wordy(val):
            return False
        return True

    def _b64_meaningful(self, val):
        try:
            dec = base64.b64decode(val + "=" * (-len(val) % 4), validate=False)
            txt = dec.decode("utf-8", "ignore")
            if re.search(r"AIza|AKIA|sk_live|eyJ|BEGIN|firebase|api", txt):
                return True
            return _shannon(txt) >= 4.0 and len(txt) >= 16
        except Exception:
            return False

    def _is_critical(self, name):
        return any(k in name for k in ("private_key", "aws", "gcp", "stripe_secret",
                                       "openai", "anthropic", "google_api", "twilio_api",
                                       "sendgrid", "braintree", "azure", "basic_auth",
                                       "openrouter", "huggingface", "replicate", "groq",
                                       "perplexity", "xai", "google_ai", "cohere", "mistral",
                                       "elevenlabs", "fcm", "oauth_refresh", "digitalocean",
                                       "shopify", "notion", "mapbox", "sentry", "datadog",
                                       "jdbc", "redis_url", "amqp", "mongodb", "postgres",
                                       "supabase", "firebase"))

    def _emit(self, out, ftype, value, source, severity):
        value = (value or "").strip()
        if not value or value in self.seen:
            return
        if self._is_own_secret(value):   # لا تُبلِّغ مفاتيح العقل كأسرار التطبيق أبداً
            self.seen.add(value)
            return
        self.seen.add(value)
        if ftype == "high_entropy_secret":
            self._he_emitted += 1
        out.append({
            "type": f"secret_{ftype}",
            "title": f"سرّ مُكتشَف: {ftype}",
            "severity": severity,
            "detail": f"{ftype} = {value[:80]}" + ("…" if len(value) > 80 else ""),
            "evidence": [value],
            "data": value,
            "why": f"مفتاح/سرّ من نوع {ftype} عُثر عليه في {source}",
            "phase": "secret-hunt",
            "source_kind": source,
        })
        if self.verbose:
            print(f"    \033[92m[SECRET] {ftype}: {value[:48]}{'…' if len(value) > 48 else ''}\033[0m")

    # ── مصادر الجهاز (root) ───────────────────────────────────────────────
    def _su(self, cmd, timeout=25):
        try:
            r = subprocess.run([self.adb, "-s", self.device, "shell", f"su -c '{cmd}'"],
                               capture_output=True, text=True, timeout=timeout,
                               encoding="utf-8", errors="ignore")
            return r.stdout or ""
        except Exception:
            return ""

    def hunt_device_data(self):
        """مسح shared_prefs / databases / files / cache للتطبيق (root)."""
        out = []
        if not self.package:
            return out
        base = f"/data/data/{self.package}"
        for sub in ("shared_prefs", "databases", "files", "cache", "no_backup", "app_webview"):
            data = self._su(f"find {base}/{sub} -type f -exec cat {{}} + 2>/dev/null")
            if data.strip():
                out += self.scan_text(data, source=f"device:{sub}")
        # EncryptedSharedPreferences تُفكّ وقت التشغيل — نمسح أي نص واضح متبقٍّ
        return out

    def _app_pids(self):
        """PIDs الخاصة بالتطبيق المُختبَر فقط."""
        pids = []
        for cmd in (["shell", "pidof", self.package],
                    ["shell", f"pgrep -f {self.package}"]):
            try:
                out = subprocess.run([self.adb, "-s", self.device, *cmd],
                                     capture_output=True, text=True, timeout=10,
                                     encoding="utf-8", errors="ignore").stdout or ""
                pids += [p for p in re.split(r"\s+", out.strip()) if p.isdigit()]
            except Exception:
                pass
        return list(dict.fromkeys(pids))

    def hunt_logcat(self):
        """مسح سجل **التطبيق المُختبَر فقط** (عبر PID) — لا الجهاز كله.
        خطأ فادح سابق: logcat على مستوى الجهاز يخلط أسرار تطبيقات/جلسات أخرى →
        نفس الأسرار تظهر لتطبيقات مختلفة. الآن مقصور على PID التطبيق."""
        try:
            pids = self._app_pids()
            args = [self.adb, "-s", self.device, "logcat", "-d", "-t", "5000"]
            if pids:
                for p in pids:
                    args += ["--pid", p]        # logcat يدعم عدة --pid
            else:
                # لا PID (التطبيق غير عامل) → لا تمسح الجهاز كله (تفادي التلوث المتبادل)
                if self.verbose:
                    print("  [secret-hunt] لا PID للتطبيق — تخطّي logcat لتفادي خلط الأسرار.")
                return []
            r = subprocess.run(args, capture_output=True, text=True, timeout=25,
                               encoding="utf-8", errors="ignore")
            return self.scan_text(r.stdout or "", source="logcat")
        except Exception:
            return []

    def hunt_findings(self, findings):
        """مسح أدلة/تفاصيل النتائج الديناميكية الملتقطة."""
        out = []
        for f in findings or []:
            blob = str(f.get("detail", "")) + " " + \
                   " ".join(str(e) for e in (f.get("evidence") or [])) + " " + \
                   str(f.get("data", ""))
            out += self.scan_text(blob, source=f"finding:{f.get('type', '?')}")
        return out

    def hunt(self, dynamic_findings=None, store=None):
        """البحث الشامل: النتائج + بيانات الجهاز + logcat. يُعيد نتائج أسرار موحّدة."""
        if self.verbose:
            print("  \033[96m[secret-hunt] بحث واسع وعميق عن الأسرار بكل أنواعها…\033[0m")
        results = []
        results += self.hunt_findings(dynamic_findings or [])
        results += self.hunt_device_data()
        results += self.hunt_logcat()
        if store is not None:
            for r in results:
                try:
                    store.add("secret", r["data"], source="secret-hunt", note=r["type"])
                except Exception:
                    pass
        if self.verbose:
            print(f"  \033[96m[secret-hunt] العثور على {len(results)} سرّاً/مفتاحاً "
                  f"(بعد الترشيح الصارم).\033[0m")
        return results


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", "-p", required=True)
    ap.add_argument("--device", "-d", default="emulator-5554")
    ap.add_argument("--adb", default=os.environ.get("HAYO_ADB", "C:/Users/PT/Downloads/platform-tools/adb.exe"))
    args = ap.parse_args()
    h = SecretHunter(args.adb, args.device, args.package)
    found = h.hunt()
    print(f"\nTotal: {len(found)} secrets")
    for r in found:
        print(f"  [{r['severity']}] {r['type']}: {r['data'][:60]}")
