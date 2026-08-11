#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Key & URL Tester (key_url_tester.py)
=====================================================
أداة فحص يدوي حقيقي لأي مفتاح/سرّ/رابط: تكتشف نوعه تلقائيًا، ثم تختبره فعليًا
عبر شبكة الإنترنت الحقيقية مقابل عدّة نقاط نهاية/صلاحيات، وتقرّر بدقة:
- هل المفتاح صالح أصلًا؟
- في أي خدمة/صلاحية هو "مفتوح" (يعمل)؟
- في أي خدمة/صلاحية هو "مقيَّد" (Restricted/Forbidden/API غير مفعّلة)؟
- هل انتهت صلاحيته أو نفد رصيده (quota)؟

مبدأ العمل: طلبات HTTP حقيقية قصيرة (GET/POST بحد أدنى من البيانات) — لا تخمين
ولا محاكاة. كل نتيجة مبنية على استجابة فعلية من الخادم.
"""
import os
import re
import sys
import json
import time
import base64
import hmac
import hashlib
import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[94m"; M = "\033[95m"; X = "\033[0m"; BOLD = "\033[1m"

TIMEOUT = 10
HERE = os.path.dirname(os.path.abspath(__file__))
LOOT = os.path.join(HERE, "loot")
os.makedirs(LOOT, exist_ok=True)


# ============================================================
# أدوات مساعدة للطباعة المنظّمة
# ============================================================
class Report:
    def __init__(self, value, kind):
        self.value = value
        self.kind = kind
        self.rows = []          # [(scope_label, status, detail)]
        self.valid = None       # True/False/None(unknown)
        self.notes = []

    def add(self, scope, status, detail=""):
        """status: OPEN | RESTRICTED | QUOTA | EXPIRED | INVALID | ERROR | INFO"""
        self.rows.append((scope, status, detail))

    def note(self, text):
        self.notes.append(text)

    def print_all(self):
        icon = {
            "OPEN": (G, "✅ مفتوح"), "RESTRICTED": (Y, "🔒 مقيَّد"),
            "QUOTA": (Y, "⏳ نفد الرصيد/الحدّ"), "EXPIRED": (R, "⌛ منتهي الصلاحية"),
            "INVALID": (R, "❌ غير صالح"), "ERROR": (M, "⚠ خطأ اتصال"),
            "INFO": (C, "ℹ معلومة"),
        }
        print(f"\n{BOLD}{M}{'='*68}{X}")
        print(f"{BOLD}{M}  HAYO Cipher-7 — تقرير فحص: {self.kind}{X}")
        print(f"{BOLD}{M}{'='*68}{X}")
        masked = self.value if len(self.value) <= 12 else self.value[:8] + "…" + self.value[-4:]
        print(f"  القيمة المفحوصة: {masked}")
        print()
        if not self.rows:
            print(f"  {Y}لا نتائج — راجع الملاحظات أدناه.{X}")
        w = max([len(r[0]) for r in self.rows], default=10) + 2
        for scope, status, detail in self.rows:
            color, label = icon.get(status, (X, status))
            print(f"  {scope:<{w}} {color}{label}{X}" + (f"  — {detail}" if detail else ""))
        if self.notes:
            print()
            for n in self.notes:
                print(f"  {C}ℹ {n}{X}")
        # ملخّص أمني عالي المستوى
        opens = [r for r in self.rows if r[1] == "OPEN"]
        print()
        if any(r[1] == "INVALID" for r in self.rows) and not opens:
            print(f"  {R}{BOLD}الخلاصة: المفتاح/الرابط غير صالح أو مُلغى بالكامل.{X}")
        elif opens:
            print(f"  {G}{BOLD}الخلاصة: صالح ويعمل في {len(opens)} من أصل {len(self.rows)} نطاق(ات) مُختبَرة.{X}")
        else:
            print(f"  {Y}{BOLD}الخلاصة: لم يُثبَت أنه يعمل في أي نطاق مُختبَر (قد يكون مقيّدًا بالكامل أو الخدمات المختبرة غير مفعّلة عليه).{X}")
        print(f"{BOLD}{M}{'='*68}{X}\n")

    def to_dict(self):
        return {
            "kind": self.kind, "valid": self.valid,
            "rows": [{"scope": s, "status": st, "detail": d} for s, st, d in self.rows],
            "notes": self.notes,
        }


def _req(method, url, retries=1, **kw):
    """طلب HTTP مع إعادة محاولة واحدة تلقائيًا عند انقطاع شبكي عابر (timeout/CONN_ERROR)
    — يمنع نتائج 'خطأ اتصال' كاذبة لمفاتيح صالحة فعلًا بسبب هفوة شبكة لحظية."""
    kw.setdefault("timeout", TIMEOUT)
    last = None
    for attempt in range(retries + 1):
        try:
            return requests.request(method, url, **kw)
        except requests.exceptions.Timeout:
            last = ("TIMEOUT", None)
        except requests.exceptions.SSLError as e:
            return ("SSL_ERROR", str(e))  # لا فائدة من إعادة المحاولة لخطأ شهادة
        except requests.exceptions.ConnectionError as e:
            last = ("CONN_ERROR", str(e))
        except Exception as e:
            return ("ERROR", str(e))
        if attempt < retries:
            time.sleep(1.2)
    return last


def _is_err(resp):
    return isinstance(resp, tuple)


# ============================================================
# كشف نوع القيمة تلقائيًا
# ============================================================
PATTERNS = [
    ("openai_key",      re.compile(r"^sk-(?!ant-|or-)(proj-)?[A-Za-z0-9_\-]{20,}$")),
    ("anthropic_key",   re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,}$")),
    ("openrouter_key",  re.compile(r"^sk-or-v1-[A-Za-z0-9]{20,}$")),
    ("groq_key",        re.compile(r"^gsk_[A-Za-z0-9]{20,}$")),
    ("replicate_key",   re.compile(r"^r8_[A-Za-z0-9]{20,}$")),
    ("perplexity_key",  re.compile(r"^pplx-[A-Za-z0-9]{20,}$")),
    ("xai_key",         re.compile(r"^xai-[A-Za-z0-9]{20,}$")),
    ("google_api_key",  re.compile(r"^(AIza[0-9A-Za-z\-_]{35}|AQ\.[A-Za-z0-9_\-]{40,70})$")),
    ("huggingface_key", re.compile(r"^hf_[A-Za-z0-9]{20,}$")),
    ("stripe_key",      re.compile(r"^(sk|rk)_(live|test)_[0-9A-Za-z]{20,}$")),
    ("github_token",    re.compile(r"^(ghp_|github_pat_)[A-Za-z0-9_]{20,}$")),
    ("sendgrid_key",    re.compile(r"^SG\.[A-Za-z0-9_\-\.]{20,}$")),
    ("aws_access_key",  re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$")),
    ("telegram_token",  re.compile(r"^\d{6,12}:[A-Za-z0-9_\-]{35}$")),
    ("jwt_token",       re.compile(r"^eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")),
    ("supabase_anon",   re.compile(r"^eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\..+")),  # subset of JWT, checked after
]

# ملاحظة عن deepseek_key: صيغة DeepSeek متطابقة شكليًا مع OpenAI (بادئة sk-)
# فلا يمكن تمييزها تلقائيًا — تُفحص عبر --type deepseek_key يدويًا من القائمة المنسدلة.


def detect_kind(value: str) -> str:
    v = value.strip().strip('"').strip("'")
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    for kind, pat in PATTERNS:
        if pat.match(v):
            return kind
    if ":" in v and v.count(":") == 1 and re.match(r"^[A-Za-z0-9+/=]{10,}$", v.split(":")[1] or ""):
        return "generic_pair"  # SID:SECRET style (Twilio, Basic-auth pair, AWS pair via --secret)
    return "unknown"


# ============================================================
# فاحص: OpenAI
# ============================================================
def test_openai(key, rep: Report):
    h = {"Authorization": f"Bearer {key}"}
    r = _req("GET", "https://api.openai.com/v1/models", headers=h)
    if _is_err(r):
        rep.add("قائمة النماذج /v1/models", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        n = len(r.json().get("data", []))
        rep.add("قائمة النماذج /v1/models", "OPEN", f"{n} نموذج متاح")
    elif r.status_code == 401:
        rep.valid = False
        rep.add("قائمة النماذج /v1/models", "INVALID", "مفتاح غير صالح/مُلغى")
        return
    elif r.status_code == 429:
        rep.add("قائمة النماذج /v1/models", "QUOTA", "تجاوز الحدّ (rate limit)")
    else:
        rep.add("قائمة النماذج /v1/models", "RESTRICTED", f"HTTP {r.status_code}")

    body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}
    r2 = _req("POST", "https://api.openai.com/v1/chat/completions", headers=h, json=body)
    if _is_err(r2):
        rep.add("محادثة (chat/completions)", "ERROR", r2[0])
    elif r2.status_code == 200:
        rep.add("محادثة (chat/completions)", "OPEN", "استدعاء ناجح — يوجد رصيد/صلاحية")
    elif r2.status_code == 429:
        rep.add("محادثة (chat/completions)", "QUOTA", "quota/rate-limit — المفتاح صالح لكن بلا رصيد")
    elif r2.status_code == 403:
        rep.add("محادثة (chat/completions)", "RESTRICTED", "ممنوع (منطقة/سياسة استخدام)")
    else:
        rep.add("محادثة (chat/completions)", "RESTRICTED", f"HTTP {r2.status_code}: {r2.text[:120]}")

    r3 = _req("POST", "https://api.openai.com/v1/embeddings", headers=h,
              json={"model": "text-embedding-3-small", "input": "hi"})
    if _is_err(r3):
        rep.add("التضمينات (embeddings)", "ERROR", r3[0])
    elif r3.status_code == 200:
        rep.add("التضمينات (embeddings)", "OPEN")
    elif r3.status_code == 429:
        rep.add("التضمينات (embeddings)", "QUOTA")
    else:
        rep.add("التضمينات (embeddings)", "RESTRICTED", f"HTTP {r3.status_code}")

    r4 = _req("POST", "https://api.openai.com/v1/images/generations", headers=h,
              json={"model": "dall-e-2", "prompt": "a red dot", "n": 1, "size": "256x256"})
    if _is_err(r4):
        rep.add("توليد الصور (images)", "ERROR", r4[0])
    elif r4.status_code == 200:
        rep.add("توليد الصور (images)", "OPEN")
    elif r4.status_code == 429:
        rep.add("توليد الصور (images)", "QUOTA")
    else:
        rep.add("توليد الصور (images)", "RESTRICTED", f"HTTP {r4.status_code}")


# ============================================================
# فاحص: Anthropic
# ============================================================
def test_anthropic(key, rep: Report):
    h = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    body = {"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}
    r = _req("POST", "https://api.anthropic.com/v1/messages", headers=h, json=body)
    if _is_err(r):
        rep.add("رسائل (messages)", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        rep.add("رسائل (messages)", "OPEN", "استدعاء ناجح — يوجد رصيد/صلاحية")
    elif r.status_code == 401:
        rep.valid = False
        rep.add("رسائل (messages)", "INVALID", "مفتاح غير صالح")
    elif r.status_code == 429:
        rep.add("رسائل (messages)", "QUOTA", "تجاوز الحدّ/نفاد الرصيد")
    elif r.status_code == 403:
        rep.add("رسائل (messages)", "RESTRICTED", "ممنوع (منطقة/سياسة)")
    else:
        rep.add("رسائل (messages)", "RESTRICTED", f"HTTP {r.status_code}: {r.text[:120]}")


# ============================================================
# فاحص: Google API Key — عبر عدّة خدمات (المثال الذي طلبه المستخدم)
# ============================================================
def test_google(key, rep: Report):
    # ملاحظة حاسمة: عائلة Maps الكلاسيكية (Geocoding/Places) لا تُرجع أبدًا HTTP خطأ —
    # ترجع دومًا HTTP 200 مع حقل body["status"] ("OK"/"REQUEST_DENIED"/"OVER_QUERY_LIMIT"...)
    # بينما Generative Language/YouTube/Translate/Books/Identity Toolkit تستخدم بنية
    # {"error": {...}} قياسية. خلطهما يُنتج نتائج "مفتوح" خاطئة — لكل عائلة تحقّقها الخاص.
    services = [
        ("Generative Language / Gemini", "GET",
         f"https://generativelanguage.googleapis.com/v1beta/models?key={key}", None, "error"),
        ("خرائط جوجل — Geocoding", "GET",
         f"https://maps.googleapis.com/maps/api/geocode/json?address=cairo&key={key}", None, "maps_status"),
        ("خرائط جوجل — Places", "GET",
         f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=cafe&key={key}", None, "maps_status"),
        ("YouTube Data API v3", "GET",
         f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={key}", None, "error"),
        ("ترجمة جوجل — Translate", "GET",
         f"https://translation.googleapis.com/language/translate/v2?key={key}&q=hello&target=fr", None, "error"),
        ("Books API", "GET",
         f"https://www.googleapis.com/books/v1/volumes?q=test&key={key}", None, "error"),
        ("Firebase Identity Toolkit — إنشاء حساب ⚠", "POST",
         f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}",
         {"email": f"hayo.probe.{int(time.time())}@example.com", "password": "Probe!2026xx", "returnSecureToken": True}, "error"),
    ]
    any_open = False
    for label, method, url, payload, schema in services:
        r = _req(method, url, json=payload) if payload else _req(method, url)
        if _is_err(r):
            rep.add(label, "ERROR", r[0]); continue
        try:
            data = r.json()
        except Exception:
            data = {}

        if schema == "maps_status":
            # بنية Maps الكلاسيكية: {"status": "...", "error_message": "..."}
            mstatus = str(data.get("status", "")) if isinstance(data, dict) else ""
            emsg = str(data.get("error_message", "")) if isinstance(data, dict) else ""
            if mstatus in ("OK", "ZERO_RESULTS"):
                any_open = True
                rep.add(label, "OPEN")
            elif mstatus == "REQUEST_DENIED":
                if "invalid" in emsg.lower():
                    rep.valid = False
                    rep.add(label, "INVALID", "المفتاح غير صالح")
                elif "not authorized" in emsg.lower() or "this api project is not authorized" in emsg.lower():
                    rep.add(label, "RESTRICTED", "الـAPI غير مفعَّلة لهذا المشروع")
                elif "referer" in emsg.lower() or "ip address" in emsg.lower() or "restrict" in emsg.lower():
                    rep.add(label, "RESTRICTED", "مُقيَّد بـ Referrer/IP لا يطابق الطلب الحالي")
                else:
                    rep.add(label, "RESTRICTED", emsg[:100] or "REQUEST_DENIED")
            elif mstatus == "OVER_QUERY_LIMIT":
                rep.add(label, "QUOTA", "تجاوز الحدّ اليومي/quota")
            else:
                rep.add(label, "INFO", f"status={mstatus}")
            continue

        # schema == "error" (البنية القياسية)
        err = (data.get("error") or {}) if isinstance(data, dict) else {}
        msg = str(err.get("message", ""))
        status_field = err.get("status", "")
        if r.status_code == 200 and not err:
            any_open = True
            note = ""
            if "signUp" in url:
                note = "⚠ خطير: يمكن إنشاء حسابات Firebase Auth بهذا المفتاح دون تحكّم"
            rep.add(label, "OPEN", note)
        elif "API keys are not supported by this API" in msg or "Expected OAuth2 access token" in msg:
            rep.add(label, "RESTRICTED", "هذه الخدمة لا تقبل هذا النوع من المفاتيح إطلاقًا — مفتاح مخصّص (مثل مفاتيح Gemini الحديثة AQ.) وليس مفتاح Google Cloud عامًا")
        elif status_field == "PERMISSION_DENIED" or "not been used" in msg or "not enabled" in msg or "disabled" in msg.lower():
            rep.add(label, "RESTRICTED", "الـAPI غير مُفعَّلة لهذا المشروع")
        elif "API key not valid" in msg or (r.status_code in (400, 401) and "API_KEY_INVALID" in msg):
            rep.valid = False
            rep.add(label, "INVALID", "المفتاح غير صالح")
        elif "referer" in msg.lower() or "IP address" in msg or "application restrictions" in msg.lower():
            rep.add(label, "RESTRICTED", "مُقيَّد بـ Referrer/IP لا يطابق الطلب الحالي")
        elif r.status_code == 429 or "RESOURCE_EXHAUSTED" in status_field:
            rep.add(label, "QUOTA", "تجاوز الحدّ اليومي/quota")
        else:
            rep.add(label, "RESTRICTED", f"HTTP {r.status_code}" + (f": {msg[:100]}" if msg else ""))
    if any_open:
        rep.valid = True
    elif rep.valid is None:
        rep.valid = False
        rep.note("لم يُثبَت عمل المفتاح في أي من الخدمات المُختبَرة أعلاه — إما مقيّد بالكامل أو غير صالح.")


# ============================================================
# فاحص عام لأي مزوّد متوافق مع OpenAI API (chat/completions + models)
# ============================================================
def _test_openai_compatible(key, rep, base_url, model, extra_headers=None, models_path="/models"):
    h = {"Authorization": f"Bearer {key}"}
    if extra_headers:
        h.update(extra_headers)
    r = _req("GET", base_url + models_path, headers=h)
    if not _is_err(r):
        if r.status_code == 200:
            rep.valid = True
            try:
                n = len(r.json().get("data", []))
                rep.add("قائمة النماذج", "OPEN", f"{n} نموذج متاح")
            except Exception:
                rep.add("قائمة النماذج", "OPEN")
        elif r.status_code == 401:
            rep.valid = False
            rep.add("قائمة النماذج", "INVALID", "مفتاح غير صالح")
            return
        elif r.status_code == 429:
            rep.add("قائمة النماذج", "QUOTA", "تجاوز الحدّ")
        else:
            rep.add("قائمة النماذج", "RESTRICTED", f"HTTP {r.status_code}")
    else:
        rep.add("قائمة النماذج", "ERROR", r[0])

    body = {"model": model, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}
    r2 = _req("POST", base_url + "/chat/completions", headers=h, json=body)
    if _is_err(r2):
        rep.add("محادثة تجريبية (chat/completions)", "ERROR", r2[0]); return
    if r2.status_code == 200:
        rep.valid = True
        rep.add("محادثة تجريبية (chat/completions)", "OPEN", "استدعاء ناجح — يوجد رصيد/صلاحية")
    elif r2.status_code == 401:
        rep.valid = False
        rep.add("محادثة تجريبية (chat/completions)", "INVALID", "مفتاح غير صالح")
    elif r2.status_code == 429:
        rep.add("محادثة تجريبية (chat/completions)", "QUOTA", "quota/rate-limit — المفتاح صالح لكن بلا رصيد")
    elif r2.status_code == 403:
        rep.add("محادثة تجريبية (chat/completions)", "RESTRICTED", "ممنوع (منطقة/سياسة)")
    else:
        rep.add("محادثة تجريبية (chat/completions)", "RESTRICTED", f"HTTP {r2.status_code}: {r2.text[:120]}")


def test_deepseek(key, rep: Report):
    _test_openai_compatible(key, rep, "https://api.deepseek.com", "deepseek-chat")


def test_groq(key, rep: Report):
    _test_openai_compatible(key, rep, "https://api.groq.com/openai/v1", "llama-3.1-8b-instant")


def test_xai(key, rep: Report):
    _test_openai_compatible(key, rep, "https://api.x.ai/v1", "grok-beta")


def test_mistral(key, rep: Report):
    _test_openai_compatible(key, rep, "https://api.mistral.ai/v1", "mistral-small-latest")


def test_perplexity(key, rep: Report):
    h = {"Authorization": f"Bearer {key}"}
    body = {"model": "llama-3.1-sonar-small-128k-online", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}
    r = _req("POST", "https://api.perplexity.ai/chat/completions", headers=h, json=body)
    if _is_err(r):
        rep.add("محادثة تجريبية", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        rep.add("محادثة تجريبية", "OPEN", "استدعاء ناجح")
    elif r.status_code == 401:
        rep.valid = False
        rep.add("محادثة تجريبية", "INVALID", "مفتاح غير صالح")
    elif r.status_code == 429:
        rep.add("محادثة تجريبية", "QUOTA", "تجاوز الحدّ/نفاد الرصيد")
    else:
        rep.add("محادثة تجريبية", "RESTRICTED", f"HTTP {r.status_code}: {r.text[:120]}")


def test_openrouter(key, rep: Report):
    # OpenRouter يوفّر نقطة هوية مخصّصة تُرجع الحدّ والاستهلاك الحاليين دون استهلاك رصيد
    r = _req("GET", "https://openrouter.ai/api/v1/auth/key", headers={"Authorization": f"Bearer {key}"})
    if _is_err(r):
        rep.add("معلومات المفتاح (auth/key)", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        d = (r.json() or {}).get("data", {})
        rep.add("معلومات المفتاح (auth/key)", "OPEN",
                f"limit: {d.get('limit','∞')} | usage: {d.get('usage','?')} | free_tier: {d.get('is_free_tier','?')}")
    elif r.status_code == 401:
        rep.valid = False
        rep.add("معلومات المفتاح (auth/key)", "INVALID", "مفتاح غير صالح")
    else:
        rep.add("معلومات المفتاح (auth/key)", "RESTRICTED", f"HTTP {r.status_code}")


def test_replicate(key, rep: Report):
    r = _req("GET", "https://api.replicate.com/v1/account", headers={"Authorization": f"Bearer {key}"})
    if _is_err(r):
        rep.add("الحساب (account)", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        d = r.json() or {}
        rep.add("الحساب (account)", "OPEN", f"username: {d.get('username','?')} | type: {d.get('type','?')}")
    elif r.status_code == 401:
        rep.valid = False
        rep.add("الحساب (account)", "INVALID", "مفتاح غير صالح")
    else:
        rep.add("الحساب (account)", "RESTRICTED", f"HTTP {r.status_code}")


def test_cohere(key, rep: Report):
    r = _req("POST", "https://api.cohere.com/v1/check-api-key", headers={"Authorization": f"Bearer {key}"})
    if _is_err(r):
        rep.add("فحص المفتاح (check-api-key)", "ERROR", r[0]); return
    if r.status_code == 200:
        d = r.json() or {}
        rep.valid = bool(d.get("valid", True))
        rep.add("فحص المفتاح (check-api-key)", "OPEN" if rep.valid else "INVALID")
    elif r.status_code == 401:
        rep.valid = False
        rep.add("فحص المفتاح (check-api-key)", "INVALID", "مفتاح غير صالح")
    else:
        rep.add("فحص المفتاح (check-api-key)", "RESTRICTED", f"HTTP {r.status_code}")


# ============================================================
# فاحص: HuggingFace
# ============================================================
def test_huggingface(key, rep: Report):
    r = _req("GET", "https://huggingface.co/api/whoami-v2", headers={"Authorization": f"Bearer {key}"})
    if _is_err(r):
        rep.add("الهوية (whoami)", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        who = r.json()
        rep.add("الهوية (whoami)", "OPEN", f"user: {who.get('name','?')} | type: {who.get('type','?')}")
        auth = who.get("auth", {})
        acc = auth.get("accessToken", {})
        role = acc.get("role") or auth.get("role")
        if role:
            rep.add("مستوى الصلاحية (role)", "INFO", role)
    elif r.status_code == 401:
        rep.valid = False
        rep.add("الهوية (whoami)", "INVALID", "مفتاح غير صالح")
    else:
        rep.add("الهوية (whoami)", "RESTRICTED", f"HTTP {r.status_code}")


# ============================================================
# فاحص: Stripe
# ============================================================
def test_stripe(key, rep: Report):
    h = {"Authorization": f"Bearer {key}"}
    endpoints = [
        ("الرصيد (balance)", "https://api.stripe.com/v1/balance"),
        ("العملاء (customers)", "https://api.stripe.com/v1/customers?limit=1"),
        ("المدفوعات (charges)", "https://api.stripe.com/v1/charges?limit=1"),
        ("الاشتراكات (subscriptions)", "https://api.stripe.com/v1/subscriptions?limit=1"),
    ]
    any_open = False
    for label, url in endpoints:
        r = _req("GET", url, headers=h)
        if _is_err(r):
            rep.add(label, "ERROR", r[0]); continue
        if r.status_code == 200:
            any_open = True
            rep.add(label, "OPEN")
        elif r.status_code == 401:
            rep.valid = False
            rep.add(label, "INVALID", "مفتاح غير صالح/مُلغى")
        elif r.status_code == 403:
            rep.add(label, "RESTRICTED", "الصلاحية غير ممنوحة لهذا النطاق (Restricted key)")
        else:
            rep.add(label, "RESTRICTED", f"HTTP {r.status_code}")
    if any_open:
        rep.valid = True
        rep.note("مفتاح Stripe حيّ ⚠ خطر مالي مباشر — أبلغ المطوّر لإلغائه فورًا (Rotate).")


# ============================================================
# فاحص: GitHub Token
# ============================================================
def test_github(key, rep: Report):
    h = {"Authorization": f"Bearer {key}", "Accept": "application/vnd.github+json"}
    r = _req("GET", "https://api.github.com/user", headers=h)
    if _is_err(r):
        rep.add("الحساب (/user)", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        u = r.json()
        rep.add("الحساب (/user)", "OPEN", f"login: {u.get('login','?')}")
        scopes = r.headers.get("X-OAuth-Scopes", "")
        rep.add("الصلاحيات الممنوحة (scopes)", "INFO", scopes or "(fine-grained / classic بلا scopes مُعلَنة)")
    elif r.status_code == 401:
        rep.valid = False
        rep.add("الحساب (/user)", "INVALID", "مفتاح غير صالح")
        return
    else:
        rep.add("الحساب (/user)", "RESTRICTED", f"HTTP {r.status_code}")

    r2 = _req("GET", "https://api.github.com/user/repos?per_page=1&visibility=private", headers=h)
    if not _is_err(r2):
        if r2.status_code == 200:
            rep.add("المستودعات الخاصة (private repos)", "OPEN", "يمكنه رؤية مستودعات خاصة!")
        elif r2.status_code == 403:
            rep.add("المستودعات الخاصة (private repos)", "RESTRICTED", "لا صلاحية repo")


# ============================================================
# فاحص: Telegram Bot Token
# ============================================================
def test_telegram(token, rep: Report):
    r = _req("GET", f"https://api.telegram.org/bot{token}/getMe")
    if _is_err(r):
        rep.add("هوية البوت (getMe)", "ERROR", r[0]); return
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code == 200 and data.get("ok"):
        rep.valid = True
        res = data.get("result", {})
        rep.add("هوية البوت (getMe)", "OPEN", f"@{res.get('username','?')} — {res.get('first_name','')}")
        r2 = _req("GET", f"https://api.telegram.org/bot{token}/getUpdates?limit=1")
        if not _is_err(r2) and r2.status_code == 200:
            n = len(r2.json().get("result", []))
            rep.add("سجلّ الرسائل (getUpdates)", "OPEN", f"{n} تحديث متاح للقراءة")
        r3 = _req("GET", f"https://api.telegram.org/bot{token}/getWebhookInfo")
        if not _is_err(r3) and r3.status_code == 200:
            wh = r3.json().get("result", {}).get("url", "")
            rep.add("الـ Webhook الحالي", "INFO", wh or "(غير مضبوط)")
    else:
        rep.valid = False
        rep.add("هوية البوت (getMe)", "INVALID", "توكن بوت غير صالح")


# ============================================================
# فاحص: SendGrid
# ============================================================
def test_sendgrid(key, rep: Report):
    r = _req("GET", "https://api.sendgrid.com/v3/user/account", headers={"Authorization": f"Bearer {key}"})
    if _is_err(r):
        rep.add("الحساب (account)", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        rep.add("الحساب (account)", "OPEN", str(r.json()))
    elif r.status_code == 401:
        rep.valid = False
        rep.add("الحساب (account)", "INVALID")
    else:
        rep.add("الحساب (account)", "RESTRICTED", f"HTTP {r.status_code}")


# ============================================================
# فاحص: AWS Access/Secret Key pair (SigV4 لـ STS GetCallerIdentity)
# ============================================================
def _aws_sigv4_get_caller_identity(access_key, secret_key, session_token=None, region="us-east-1"):
    service = "sts"
    host = f"sts.{region}.amazonaws.com"
    endpoint = f"https://{host}/"
    amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_date[:8]
    payload = "Action=GetCallerIdentity&Version=2011-06-15"

    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n" + \
                      hashlib.sha256(canonical_request.encode()).hexdigest()

    def _sign(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret_key).encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth_header = (f"{algorithm} Credential={access_key}/{credential_scope}, "
                    f"SignedHeaders={signed_headers}, Signature={signature}")
    headers = {"x-amz-date": amz_date, "Authorization": auth_header,
               "Content-Type": "application/x-www-form-urlencoded"}
    if session_token:
        headers["x-amz-security-token"] = session_token
    return endpoint, headers, payload


def test_aws(access_key, secret_key, rep: Report):
    if not secret_key:
        rep.add("STS GetCallerIdentity", "ERROR", "يلزم مفتاح AWS السرّي (Secret Key) أيضًا — أدخله في الحقل الثانوي")
        rep.note("مفتاح AWS الوصول (Access Key) وحده لا يكفي للفحص — AWS يتطلّب توقيع SigV4 بالمفتاحين معًا.")
        return
    endpoint, headers, payload = _aws_sigv4_get_caller_identity(access_key, secret_key)
    r = _req("POST", endpoint, headers=headers, data=payload)
    if _is_err(r):
        rep.add("STS GetCallerIdentity", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        arn = re.search(r"<Arn>(.*?)</Arn>", r.text)
        acc = re.search(r"<Account>(.*?)</Account>", r.text)
        rep.add("STS GetCallerIdentity", "OPEN",
                f"Account: {acc.group(1) if acc else '?'} | ARN: {arn.group(1) if arn else '?'}")
        rep.note("المفاتيح صالحة وحيّة على حساب AWS — أبلغ المالك لإلغائها فورًا إن كانت مسرَّبة.")
    elif r.status_code == 403:
        rep.valid = False
        rep.add("STS GetCallerIdentity", "INVALID", "توقيع مرفوض — مفاتيح غير صحيحة أو مُلغاة")
    else:
        rep.add("STS GetCallerIdentity", "RESTRICTED", f"HTTP {r.status_code}: {r.text[:150]}")


# ============================================================
# فاحص: JWT — فكّ محلي + اختبار اختياري مقابل رابط
# ============================================================
def test_jwt(token, rep: Report, base_url=None):
    parts = token.split(".")
    if len(parts) < 2:
        rep.add("بنية الرمز", "INVALID", "ليس JWT صالح البنية"); return
    try:
        pad = lambda s: s + "=" * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    except Exception as e:
        rep.add("فكّ الترميز", "ERROR", str(e)); return

    rep.add("الخوارزمية (alg)", "INFO", header.get("alg", "?"))
    if header.get("alg", "").lower() == "none":
        rep.add("تحذير أمني", "RESTRICTED", "⚠ alg:none — الرمز غير موقّع أصلًا، خطر تزوير")

    exp = payload.get("exp")
    if exp:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        expired = exp_dt < datetime.now(timezone.utc)
        rep.add("تاريخ الانتهاء (exp)", "EXPIRED" if expired else "OPEN",
                exp_dt.strftime("%Y-%m-%d %H:%M UTC") + (" — منتهي" if expired else " — سارٍ"))
        rep.valid = not expired
    else:
        rep.add("تاريخ الانتهاء (exp)", "INFO", "لا يوجد exp — رمز دائم!")

    interesting = {k: payload[k] for k in payload if k.lower() in
                   ("role", "roles", "admin", "isadmin", "ispremium", "premium", "plan", "scope", "scopes", "sub", "aud", "iss")}
    if interesting:
        rep.add("مطالبات مهمّة (claims)", "INFO", json.dumps(interesting, ensure_ascii=False))

    if base_url:
        for path in ("/api/me", "/api/user", "/me", "/user", "/api/profile"):
            url = base_url.rstrip("/") + path
            r = _req("GET", url, headers={"Authorization": f"Bearer {token}"})
            if _is_err(r):
                continue
            if r.status_code == 200:
                rep.add(f"اختبار حيّ: {path}", "OPEN", f"HTTP 200 — الرمز مقبول على الخادم")
                rep.valid = True
                return
            elif r.status_code in (401, 403):
                rep.add(f"اختبار حيّ: {path}", "RESTRICTED", f"HTTP {r.status_code}")
            elif r.status_code == 404:
                continue
        rep.note("لم يُعثر على مسار API قياسي يقبل الرمز — جرّب تحديد --base-url أدقّ (مسار كامل).")
    else:
        rep.note("لاختبار الرمز حيًّا مقابل خادم فعلي، أدخل رابط الموقع الأساسي في الحقل الثانوي.")


# ============================================================
# فاحص: رابط عام (URL) — استطلاع كامل
# ============================================================
def test_url(url, rep: Report, extra_auth=None):
    r = _req("GET", url, allow_redirects=True)
    if _is_err(r):
        rep.add("الوصول الأساسي (GET)", "ERROR", r[0])
        rep.note("تعذّر الاتصال — تحقّق من الرابط أو اتصال الشبكة.")
        return

    rep.valid = True
    chain = " → ".join([str(h.status_code) for h in r.history] + [str(r.status_code)])
    rep.add("الوصول الأساسي (GET)", "OPEN" if r.status_code < 400 else "RESTRICTED",
            f"سلسلة الحالات: {chain}" + (f" | إعادة توجيه إلى: {r.url}" if r.history else ""))

    www_auth = r.headers.get("WWW-Authenticate")
    if r.status_code in (401, 403):
        rep.add("متطلّبات المصادقة", "INFO", www_auth or "يتطلّب مصادقة (تفاصيل غير مُعلَنة في الترويسة)")
    else:
        rep.add("متطلّبات المصادقة", "OPEN", "لا يتطلّب مصادقة للوصول الأساسي")

    sec_headers = {
        "Strict-Transport-Security": "HSTS", "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options", "X-Content-Type-Options": "X-Content-Type-Options",
    }
    missing = [label for h, label in sec_headers.items() if h not in r.headers]
    if missing:
        rep.add("ترويسات الأمان الناقصة", "RESTRICTED", "، ".join(missing))
    else:
        rep.add("ترويسات الأمان", "OPEN", "كل الترويسات الأساسية موجودة")

    server = r.headers.get("Server")
    powered = r.headers.get("X-Powered-By")
    if server or powered:
        rep.add("كشف التقنية (Server/X-Powered-By)", "INFO", ", ".join(filter(None, [server, powered])))

    if extra_auth:
        for style, headers in (
            ("Authorization: Bearer", {"Authorization": f"Bearer {extra_auth}"}),
            ("X-API-Key", {"X-API-Key": extra_auth}),
            ("api-key", {"api-key": extra_auth}),
        ):
            r2 = _req("GET", url, headers=headers)
            if _is_err(r2):
                continue
            status = "OPEN" if r2.status_code < 400 else ("RESTRICTED" if r2.status_code in (401, 403) else "INFO")
            rep.add(f"مع مصادقة عبر {style}", status, f"HTTP {r2.status_code}")

    ct = r.headers.get("Content-Type", "")
    if "json" in ct:
        try:
            preview = json.dumps(r.json(), ensure_ascii=False)[:200]
            rep.add("معاينة الاستجابة (JSON)", "INFO", preview)
        except Exception:
            pass


# ============================================================
# فاحص: رابط Firebase Realtime DB (فحص قراءة/كتابة مفتوحة)
# ============================================================
def test_firebase_rtdb(url, rep: Report):
    base = url.rstrip("/")
    if not base.endswith(".json"):
        probe = base + "/.json"
    else:
        probe = base
    r = _req("GET", probe)
    if _is_err(r):
        rep.add("قراءة مفتوحة (.json)", "ERROR", r[0]); return
    if r.status_code == 200 and r.text.strip() not in ("null", ""):
        rep.valid = True
        rep.add("قراءة مفتوحة (.json)", "OPEN", "⚠ خطير: قاعدة البيانات قابلة للقراءة بلا مصادقة")
        rep.add("حجم البيانات المكشوفة", "INFO", f"{len(r.text)} بايت")
    elif r.status_code == 200:
        rep.add("قراءة مفتوحة (.json)", "OPEN", "الوصول مسموح لكن القاعدة فارغة")
    elif r.status_code in (401, 403):
        rep.add("قراءة مفتوحة (.json)", "RESTRICTED", "قواعد الأمان تمنع القراءة العامة (جيد)")
    else:
        rep.add("قراءة مفتوحة (.json)", "INFO", f"HTTP {r.status_code}")


# ============================================================
# فاحص: رابط Supabase (PostgREST) — قراءة مفتوحة بلا مفتاح anon
# ============================================================
def test_supabase(url, rep: Report, anon_key=None):
    base = url.rstrip("/")
    root = base if "/rest/v1" in base else base + "/rest/v1/"
    h = {"apikey": anon_key} if anon_key else {}
    r = _req("GET", root, headers=h)
    if _is_err(r):
        rep.add("جذر REST API", "ERROR", r[0]); return
    if r.status_code == 200:
        rep.valid = True
        rep.add("جذر REST API" + (" (بمفتاح anon)" if anon_key else " (بلا مفتاح!)"),
                "OPEN", "⚠ قابل للوصول" if not anon_key else "")
    elif r.status_code in (401, 403):
        rep.add("جذر REST API" + (" (بمفتاح anon)" if anon_key else " (بلا مفتاح)"),
                "RESTRICTED", "يتطلّب apikey صالحًا (جيد)")
    else:
        rep.add("جذر REST API", "INFO", f"HTTP {r.status_code}")


# ============================================================
# فاحص: دلو AWS S3 (قراءة/سرد مفتوح)
# ============================================================
def test_s3_bucket(url, rep: Report):
    r = _req("GET", url)
    if _is_err(r):
        rep.add("سرد الدلو (List Bucket)", "ERROR", r[0]); return
    if r.status_code == 200 and ("<ListBucketResult" in r.text or "<Contents>" in r.text):
        rep.valid = True
        n = r.text.count("<Key>")
        rep.add("سرد الدلو (List Bucket)", "OPEN", f"⚠ خطير: الدلو قابل للسرد العلني — {n}+ عنصر ظاهر")
    elif r.status_code == 403:
        rep.add("سرد الدلو (List Bucket)", "RESTRICTED", "AccessDenied — الدلو محمي من السرد العلني (جيد)")
    elif r.status_code == 404:
        rep.add("سرد الدلو (List Bucket)", "INFO", "الدلو غير موجود أو الاسم غير صحيح")
    else:
        rep.add("سرد الدلو (List Bucket)", "INFO", f"HTTP {r.status_code}")


# ============================================================
# Dispatcher
# ============================================================
TESTERS = {
    "openai_key": ("مفتاح OpenAI", test_openai),
    "anthropic_key": ("مفتاح Anthropic (Claude)", test_anthropic),
    "google_api_key": ("مفتاح Google API", test_google),
    "huggingface_key": ("مفتاح HuggingFace", test_huggingface),
    "stripe_key": ("مفتاح Stripe", test_stripe),
    "github_token": ("توكن GitHub", test_github),
    "telegram_token": ("توكن بوت Telegram", test_telegram),
    "sendgrid_key": ("مفتاح SendGrid", test_sendgrid),
    "deepseek_key": ("مفتاح DeepSeek", test_deepseek),
    "groq_key": ("مفتاح Groq", test_groq),
    "openrouter_key": ("مفتاح OpenRouter", test_openrouter),
    "replicate_key": ("مفتاح Replicate", test_replicate),
    "perplexity_key": ("مفتاح Perplexity", test_perplexity),
    "xai_key": ("مفتاح xAI (Grok)", test_xai),
    "mistral_key": ("مفتاح Mistral AI", test_mistral),
    "cohere_key": ("مفتاح Cohere", test_cohere),
}


def run(value, override_type=None, base_url=None, secondary=None):
    value = value.strip()
    kind = override_type or detect_kind(value)
    label_map = {**{k: v[0] for k, v in TESTERS.items()},
                 "url": "رابط / نقطة نهاية", "jwt_token": "رمز JWT",
                 "aws_access_key": "مفتاح AWS Access Key", "generic_pair": "زوج بيانات (SID:Secret)",
                 "unknown": "غير معروف — فحص عام"}
    rep = Report(value, label_map.get(kind, kind))

    if kind == "url":
        test_url(value, rep, extra_auth=secondary)
        if any(k in value for k in ("firebaseio.com", "firebasedatabase.app")):
            test_firebase_rtdb(value, rep)
        if ".supabase.co" in value or "/rest/v1" in value:
            test_supabase(value, rep, anon_key=secondary)
        if ".s3.amazonaws.com" in value or ".s3." in value or "s3-" in value:
            test_s3_bucket(value, rep)
    elif kind == "jwt_token":
        test_jwt(value, rep, base_url=base_url)
    elif kind == "aws_access_key":
        test_aws(value, secondary, rep)
    elif kind == "generic_pair" and requests:
        sid, sec = value.split(":", 1)
        r = _req("GET", f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json", auth=(sid, sec))
        if not _is_err(r) and r.status_code == 200:
            rep.valid = True
            rep.add("حساب Twilio", "OPEN", str(r.json().get("friendly_name", "")))
        elif not _is_err(r) and r.status_code == 401:
            rep.valid = False
            rep.add("حساب Twilio", "INVALID")
        else:
            rep.add("فحص كزوج Twilio SID:Token", "INFO", "لم يُتعرَّف عليه كحساب Twilio صالح")
    elif kind in TESTERS:
        if requests is None:
            rep.add("الفحص", "ERROR", "مكتبة requests غير مثبّتة");
        else:
            TESTERS[kind][1](value, rep)
    else:
        rep.note("لم يُتعرَّف على نوع القيمة تلقائيًا.")
        if base_url:
            test_url(base_url, rep, extra_auth=value)
        else:
            rep.note("إن كانت هذه القيمة مفتاح API لخدمة غير مدعومة تلقائيًا، أدخل رابط الخدمة الأساسي في الحقل الثانوي وسأختبرها كـ Bearer/X-API-Key/api-key عليه.")

    rep.print_all()

    out = os.path.join(LOOT, f"key_test_{int(time.time())}.json")
    try:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(rep.to_dict(), f, ensure_ascii=False, indent=2)
        print(f"{C}📄 حُفظ التقرير في: {out}{X}")
    except Exception:
        pass
    return rep


# ============================================================
# الوضع الجماعي بقيادة العقل: تُلصَق مستخرجات كاملة (من loot/ مثلًا)،
# فيستخرج كل المفاتيح/الروابط تلقائيًا، يستشير العقل المُدرَّب لتحديد
# الأولوية طبقًا لتعليمات المستخدم، يفحص كل واحد فعليًا، ثم يلخّص.
# ============================================================
EXTRACT_PATTERNS = [
    ("openai_key", re.compile(r"sk-(?!ant-|or-)(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openrouter_key", re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}")),
    ("groq_key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    ("replicate_key", re.compile(r"r8_[A-Za-z0-9]{20,}")),
    ("perplexity_key", re.compile(r"pplx-[A-Za-z0-9]{20,}")),
    ("xai_key", re.compile(r"xai-[A-Za-z0-9]{20,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}|AQ\.[A-Za-z0-9_\-]{40,70}")),
    ("huggingface_key", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("stripe_key", re.compile(r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}")),
    ("github_token", re.compile(r"(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}")),
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_\-\.]{20,}")),
    ("aws_access_key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("telegram_token", re.compile(r"\d{6,12}:[A-Za-z0-9_\-]{35}")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{6,}")),
    ("url", re.compile(r"https?://[^\s\"'<>\)\]\},]{6,}")),
]


def extract_candidates(blob: str, max_per_type=8):
    """يستخرج كل القيم المرشّحة من نص خام، مُصنَّفة ومُزال تكرارها."""
    found = {}
    for kind, pat in EXTRACT_PATTERNS:
        vals = []
        for m in pat.finditer(blob):
            v = m.group(0).rstrip(".,;:)")
            if v not in vals:
                vals.append(v)
            if len(vals) >= max_per_type:
                break
        if vals:
            found[kind] = vals
    # إزالة تكرار عابر للأنواع (رابط JWT قد يُلتقَط أيضًا كجزء من URL طويل، إلخ) — غير حرج، نُبقيه
    return found


def _brain():
    """تحميل ExtendedBrain (المُدرَّب على منهجية HAYO عبر brain_directive.txt)."""
    try:
        from extended_brain import ExtendedBrain
        return ExtendedBrain(verbose=False, package="key_url_tester")
    except Exception as e:
        print(f"{Y}[*] تعذّر تحميل العقل ({e}) — سيُتابَع بدون توجيه ذكي (فحص شامل لكل المستخرجات).{X}")
        return None


def run_bulk(blob: str, instructions: str = ""):
    print(f"\n{BOLD}{M}{'='*68}{X}")
    print(f"{BOLD}{M}  HAYO Cipher-7 — الفحص الجماعي بقيادة العقل (Key & URL Tester){X}")
    print(f"{BOLD}{M}{'='*68}{X}")

    candidates = extract_candidates(blob)
    total = sum(len(v) for v in candidates.values())
    if not total:
        print(f"{Y}لم يُستخرَج أي مفتاح/رابط قابل للتعرّف من النص المُلصَق.{X}")
        return
    print(f"{C}🔎 استُخرِج {total} مرشّحًا عبر {len(candidates)} نوع:{X}")
    for kind, vals in candidates.items():
        print(f"   • {kind}: {len(vals)}")

    brain = _brain()
    plan = None
    if brain and instructions.strip():
        print(f"\n{C}🧠 يستشير العقل المُدرَّب لتحديد الأولوية طبقًا لتعليماتك...{X}")
        flat = [{"type": k, "value": v} for k, vals in candidates.items() for v in vals]
        sys_prompt = ("You are the HAYO key/URL triage planner. Given extracted candidate "
                      "secrets/URLs and the user's testing instructions, decide which candidates "
                      "to test and in what priority order, respecting the instructions exactly "
                      "(e.g. 'only test X', 'skip Y', 'focus on Z'). "
                      'Output ONLY JSON: {"selected": [{"type":"...","value":"..."}], "reasoning":"..."}')
        user_prompt = f"التعليمات: {instructions}\n\nالمرشّحون:\n{json.dumps(flat, ensure_ascii=False, indent=2)[:6000]}"
        try:
            resp = brain._ai_chat(sys_prompt, user_prompt)
            m = re.search(r"\{.*\}", resp or "", re.DOTALL)
            plan = json.loads(m.group(0)) if m else None
        except Exception as e:
            print(f"{Y}[*] فشل تخطيط العقل ({e}) — سيُفحص كل المستخرجات.{X}")
            plan = None

    if plan and plan.get("selected"):
        print(f"{G}✅ خطة العقل: {plan.get('reasoning', '')[:200]}{X}")
        to_test = [(c["type"], c["value"]) for c in plan["selected"] if c.get("value")]
    else:
        to_test = [(k, v) for k, vals in candidates.items() for v in vals]

    print(f"\n{C}▶ سيتم فحص {len(to_test)} عنصرًا فعليًا الآن...{X}")
    all_reports = []
    for i, (kind, value) in enumerate(to_test, 1):
        print(f"\n{B}--- [{i}/{len(to_test)}] ---{X}")
        try:
            rep = run(value, override_type=None if kind == "url" else kind)
            all_reports.append(rep.to_dict())
        except Exception as e:
            print(f"{R}[!] خطأ أثناء فحص {value[:30]}: {e}{X}")

    # ملخّص نهائي بقيادة العقل، مطابق لتعليمات المستخدم
    if brain and all_reports:
        print(f"\n{BOLD}{M}{'='*68}{X}")
        print(f"{BOLD}{M}  📋 ملخّص العقل النهائي{X}")
        print(f"{BOLD}{M}{'='*68}{X}")
        sys_prompt2 = ("You are the HAYO key/URL triage summarizer. Given the user's original "
                       "instructions and the full test results, write a precise Arabic summary "
                       "that directly answers what the user asked for — which keys/URLs are OPEN, "
                       "where each is RESTRICTED, which are dangerous/critical, and clear next "
                       "steps. Never claim a key works if the evidence says otherwise.")
        user_prompt2 = f"تعليمات المستخدم: {instructions or '(لا توجد — لخّص كل شيء بشكل عام)'}\n\n" \
                       f"النتائج الكاملة:\n{json.dumps(all_reports, ensure_ascii=False)[:8000]}"
        try:
            summary = brain._ai_chat(sys_prompt2, user_prompt2)
            print(summary or "(لم يُرجع العقل ملخّصًا)")
        except Exception as e:
            print(f"{Y}[*] تعذّر توليد الملخّص: {e}{X}")

    out = os.path.join(LOOT, f"bulk_key_test_{int(time.time())}.json")
    try:
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"instructions": instructions, "candidates": candidates,
                       "plan": plan, "results": all_reports}, f, ensure_ascii=False, indent=2)
        print(f"\n{C}📄 حُفظ التقرير الجماعي الكامل في: {out}{X}")
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="HAYO Key & URL Tester")
    ap.add_argument("--value", "-v", help="المفتاح/السرّ/الرابط المراد فحصه (الوضع الفردي)")
    ap.add_argument("--type", help="فرض نوع مُحدَّد بدل الكشف التلقائي")
    ap.add_argument("--base-url", help="رابط أساسي إضافي (لاختبار JWT/مفتاح غير معروف حيًّا)")
    ap.add_argument("--secondary", help="قيمة ثانوية (AWS Secret Key، أو Bearer بديل)")
    ap.add_argument("--bulk-file", help="ملف يحوي مستخرجات كاملة (الوضع الجماعي بقيادة العقل)")
    ap.add_argument("--instructions-file", help="ملف تعليمات المستخدم للعقل (الوضع الجماعي)")
    args = ap.parse_args()

    if requests is None:
        print(f"{R}[!] مكتبة requests غير مثبّتة — لا يمكن إجراء أي فحص شبكي.{X}")
        sys.exit(1)

    if args.bulk_file:
        with open(args.bulk_file, "r", encoding="utf-8", errors="replace") as f:
            blob = f.read()
        instructions = ""
        if args.instructions_file and os.path.isfile(args.instructions_file):
            with open(args.instructions_file, "r", encoding="utf-8", errors="replace") as f:
                instructions = f.read()
        run_bulk(blob, instructions)
    elif args.value:
        run(args.value, override_type=args.type, base_url=args.base_url, secondary=args.secondary)
    else:
        ap.error("يلزم إما --value (فحص فردي) أو --bulk-file (فحص جماعي)")


if __name__ == "__main__":
    main()
