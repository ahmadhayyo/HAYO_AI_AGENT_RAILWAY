#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Static Analysis Engine (static_engine.py)
==========================================================
المحرك الساكن: يحلل التطبيق قبل التشغيل، يستخرج:
  - AndroidManifest permissions, activities, services, receivers, providers (+exported)
  - API endpoints, URLs, cloud service domains
  - Hardcoded secrets, API keys, tokens
  - Firebase and cloud configs
  - Network security config
  - Third-party SDKs and libraries
يحفظ كل شيء في IntelStore ثم يسلم للمحرك الديناميكي.

يعتمد على androguard لتحليل الـ APK (يعمل بدون root)، مع أوامر adb/su كإضافات
أفضل-جهد. جميع مسارات الملفات مقتبسة/ممرَّرة كقوائم وسائط لتفادي كسر المسافات.
"""
import json
import os
import re
import subprocess
import sys
import time
import zipfile
from datetime import datetime

try:
    # androguard 4.x يستخدم loguru ويُغرق الكونسول بسجلّات DEBUG — نُسكته
    try:
        from loguru import logger as _loguru_logger
        _loguru_logger.remove()
    except Exception:
        pass
    import logging as _logging
    _logging.getLogger("androguard").setLevel(_logging.ERROR)
    from androguard.core.apk import APK as _AndroguardAPK
    _HAS_ANDROGUARD = True
except Exception:
    _HAS_ANDROGUARD = False

# كونسول ويندوز الافتراضي (cp1256) يفشل على الرموز/العربية → أجبر UTF-8
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[94m"; M = "\033[95m"; X = "\033[0m"

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = r"C:\Users\PT\Downloads\platform-tools\adb.exe"
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Patterns for secrets and endpoints
SECRET_PATTERNS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret": r"(?i)aws[_-]?(secret|access)[_-]?key[_-]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
    "gcp_key": r"AIza[0-9A-Za-z_-]{35}",
    "firebase_url": r"https?://[a-zA-Z0-9_-]+\.firebaseio\.com",
    "firebase_project": r"[a-zA-Z0-9_-]+\.firebaseapp\.com",
    "google_api": r"AIza[0-9A-Za-z_-]{35}",
    "stripe_pk": r"pk_live_[0-9A-Za-z]{24,}",
    "stripe_sk": r"sk_live_[0-9A-Za-z]{24,}",
    "jwt_token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "cloud_url": r"https?://[a-zA-Z0-9.-]+\.(amazonaws\.com|googleapis\.com|azure\.com|cloudfront\.net|s3\.amazonaws\.com)",
    "graphql_url": r"https?://[a-zA-Z0-9./_-]+/graphql",
    "api_endpoint": r"https?://api\.[a-zA-Z0-9.-]+",
    "supabase_url": r"https?://[a-zA-Z0-9.-]+\.supabase\.co",
    "mongodb_uri": r"mongodb(?:\+srv)?://[a-zA-Z0-9@:./%?&=#_-]+",
    "github_token": r"ghp_[A-Za-z0-9]{36}",
    "slack_token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "private_key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "firebase_db_url": r"https?://[a-zA-Z0-9_-]+\.(firebaseio|firebasedatabase)\.com",
}

CLOUD_DOMAINS = [
    "firebaseio.com", "firebasedatabase.app", "googleapis.com",
    "amazonaws.com", "azure.com", "windows.net", "cloudfront.net",
    "supabase.co", "herokuapp.com", "onrender.com", "fly.dev",
    "netlify.app", "vercel.app", "railway.app", "digitaloceanspaces.com",
    "backblazeb2.com", "wasabisys.com", "contabo.com",
]

# ملفات موارد شائعة تحوي مفاتيح Firebase/Google في الـ APK
_CONFIG_FILE_HINTS = ("google-services.json", "strings.xml", "values.xml",
                      "firebase", "config", "secrets")

# تصنيف الأنشطة: بوابات دخول vs شاشات داخلية (post-login) لتجاوز بوابة الدخول
_LOGIN_GATE_RE = re.compile(r"(login|signin|sign_in|register|signup|sign_up|welcome|"
                            r"onboard|auth|otp|verify|verification|splash|intro|"
                            r"getstarted|landing|forgot)", re.I)
_POST_LOGIN_RE = re.compile(r"(main|home|dashboard|chat|feed|menu|drawer|content|"
                            r"profile|account|settings|explore|discover|library|"
                            r"workspace|hub|lobby|root|container|app)", re.I)


class StaticEngine:
    def __init__(self, package, store=None, device="emulator-5554", apk_path=None):
        self.package = package
        self.device = device
        self.adb = ADB
        self.store = store
        # apk_path قد يُمرَّر مباشرةً (ملف محلي من الواجهة) بدل السحب من الجهاز
        self.apk_path = apk_path if (apk_path and os.path.isfile(apk_path)) else None
        self.manifest = {}
        self.secrets = {}
        self.endpoints = set()
        self.activities = []
        self.services = []
        self.receivers = []
        self.providers = []
        self.exported = []      # مكونات exported (سطح هجوم)
        self.login_gates = []            # بوابات تسجيل الدخول
        self.post_login_candidates = []  # شاشات داخلية للقفز إليها (تجاوز الدخول)
        self.permissions = []
        self.dex_classes = []
        self.strings_db = []
        self.cloud_endpoints = []
        self.start_time = time.time()
        self.loot_dir = os.path.join(HERE, "loot", f"static_{package.replace('.', '_')}")
        os.makedirs(self.loot_dir, exist_ok=True)

    def log(self, msg, color=C):
        print(f"{color}[STATIC] {msg}{X}")

    # ── adb helpers (args passed as a list → لا تنكسر بالمسافات) ──────────
    def _run(self, args, timeout=30):
        try:
            r = subprocess.run([self.adb, "-s", self.device, *args],
                               capture_output=True, text=True, timeout=timeout,
                               encoding="utf-8", errors="ignore")
            return (r.stdout or "").strip(), (r.stderr or "").strip()
        except Exception as e:
            return "", str(e)

    def _adb_shell(self, cmd, timeout=30):
        """تنفيذ أمر داخل شِل الجهاز (سلسلة واحدة تمرَّر لـ adb shell)."""
        return self._run(["shell", cmd], timeout=timeout)

    def _su(self, cmd, timeout=30):
        """أمر root أفضل-جهد؛ يفشل بصمت على الأجهزة غير المروَّتة."""
        return self._adb_shell(f"su -c '{cmd}'", timeout=timeout)

    # ── APK acquisition ─────────────────────────────────────────────────
    def pull_apk(self):
        """سحب ملف APK (base.apk) من الجهاز — أو استخدام ملف مُمرَّر مسبقاً."""
        if self.apk_path and os.path.isfile(self.apk_path) and os.path.getsize(self.apk_path) > 0:
            self.log(f"استخدام APK مُمرَّر مباشرةً: {self.apk_path} "
                     f"({os.path.getsize(self.apk_path):,} bytes)", G)
            return True
        self.log(f"سحب APK للتطبيق {self.package}...")
        out, err = self._adb_shell(f"pm path {self.package}")
        if not out:
            self.log(f"فشل العثور على APK: {err}", R)
            return False
        # قد تُرجَع عدة أسطر (split APKs)؛ نُفضّل base.apk
        paths = [ln.replace("package:", "").strip()
                 for ln in out.splitlines() if ln.strip().startswith("package:")]
        if not paths:
            self.log("لم يُرجَع أي مسار APK صالح", R)
            return False
        remote = next((p for p in paths if p.endswith("base.apk")), paths[0])
        self.apk_path = os.path.join(self.loot_dir, f"{self.package}.apk")
        # قائمة الوسائط تتعامل مع المسافات في self.apk_path بشكل سليم
        _, err2 = self._run(["pull", remote, self.apk_path], timeout=120)
        if os.path.isfile(self.apk_path) and os.path.getsize(self.apk_path) > 0:
            sz = os.path.getsize(self.apk_path)
            self.log(f"APK سحب بنجاح: {sz:,} bytes", G)
            return True
        self.log(f"فشل سحب APK: {err2}", R)
        return False

    # ── Manifest via androguard (تحليل AXML الثنائي بشكل صحيح) ────────────
    def extract_manifest(self):
        """استخراج AndroidManifest.xml وتحليل الأذونات والمكونات."""
        self.log("تحليل AndroidManifest.xml...")
        if self.apk_path and os.path.isfile(self.apk_path) and _HAS_ANDROGUARD:
            try:
                self._parse_manifest_androguard()
                return
            except Exception as e:
                self.log(f"androguard فشل، ارتداد للتحليل الاحتياطي: {e}", Y)

        if not _HAS_ANDROGUARD:
            self.log("androguard غير مثبّت — pip install androguard للحصول على تحليل manifest دقيق", Y)

        if self.apk_path and os.path.isfile(self.apk_path):
            # ارتداد: مسح موارد الـ APK نصياً بحثاً عن URLs
            try:
                with zipfile.ZipFile(self.apk_path, 'r') as zf:
                    for name in zf.namelist():
                        if name.endswith('.xml'):
                            try:
                                content = zf.read(name).decode('utf-8', errors='ignore')
                                self._scan_xml_urls(content)
                            except Exception:
                                pass
                        elif name.endswith('.dex'):
                            self.dex_classes.append(name)
            except Exception as e:
                self.log(f"خطأ في فتح APK: {e}", R)
        else:
            # ارتداد أخير عبر adb (يحتاج root غالباً)
            out2, _ = self._adb_shell(f"dumpsys package {self.package}")
            if out2:
                self._parse_pm_dump(out2)

    def _parse_manifest_androguard(self):
        apk = _AndroguardAPK(self.apk_path)
        self.permissions = list(apk.get_permissions() or [])
        self.activities = list(apk.get_activities() or [])
        self.services = list(apk.get_services() or [])
        self.receivers = list(apk.get_receivers() or [])
        try:
            self.providers = list(apk.get_providers() or [])
        except Exception:
            self.providers = []
        self.dex_classes = [n for n in apk.get_files() if n.endswith('.dex')]

        # اكتشاف المكونات المُصدَّرة (exported) + سمات application من الـ XML مباشرة
        debuggable = False
        allow_backup = True
        try:
            axml = apk.get_android_manifest_xml()
            for tag in ("activity", "service", "receiver", "provider"):
                for el in axml.iter(tag):
                    name = el.get(_ANDROID_NS + "name")
                    if not name:
                        continue
                    exported_attr = el.get(_ANDROID_NS + "exported")
                    has_filter = el.find("intent-filter") is not None
                    is_exported = (exported_attr == "true") or (exported_attr is None and has_filter)
                    if is_exported:
                        self.exported.append({"type": tag, "name": name,
                                              "explicit": exported_attr == "true"})
            app_el = axml.find("application")
            if app_el is not None:
                debuggable = app_el.get(_ANDROID_NS + "debuggable") == "true"
                allow_backup = app_el.get(_ANDROID_NS + "allowBackup") != "false"
        except Exception as e:
            self.log(f"تعذّر قراءة سمات application/exported: {e}", Y)

        def _safe(fn):
            try:
                return fn()
            except Exception:
                return None

        self.manifest = {
            "package": apk.get_package() or self.package,
            "version_name": _safe(apk.get_androidversion_name),
            "version_code": _safe(apk.get_androidversion_code),
            "min_sdk": _safe(apk.get_min_sdk_version),
            "target_sdk": _safe(apk.get_target_sdk_version),
            "debuggable": debuggable,
            "allow_backup": allow_backup,
        }
        self.log(f"androguard: {len(self.permissions)} صلاحية, "
                 f"{len(self.activities)} نشاط, {len(self.services)} خدمة, "
                 f"{len(self.receivers)} مستقبِل, {len(self.exported)} مُصدَّر", G)
        if self.manifest.get("debuggable"):
            self.log("  [!] التطبيق debuggable=true — استخراج ذاكرة/مفاتيح ممكن دون root", R)

    def _scan_xml_urls(self, content):
        for m in re.finditer(r'https?://[^\s"\'<>]+', content):
            self.endpoints.add(m.group(0))

    def _parse_pm_dump(self, dump):
        """تحليل مخرجات dumpsys package (ارتداد)."""
        for line in dump.split('\n'):
            low = line.lower()
            if 'android.permission.' in line:
                for m in re.finditer(r'android\.permission\.\w+', line):
                    self.permissions.append(m.group(0))
            elif 'activity' in low and self.package in line:
                m = re.search(rf'({re.escape(self.package)}[\w./]+)', line)
                if m:
                    self.activities.append(m.group(1))
        self.log(f"dumpsys: {len(set(self.activities))} نشاط, {len(set(self.permissions))} صلاحية")

    # ── String / secret extraction ──────────────────────────────────────
    def extract_strings(self):
        """استخراج النصوص من DEX وملفات الموارد داخل الـ APK (+ بيانات التطبيق root)."""
        self.log("استخراج النصوص والبيانات الحساسة...")
        all_text = ""

        # 1) من داخل الـ APK — يعمل بدون root
        if self.apk_path and os.path.isfile(self.apk_path):
            try:
                with zipfile.ZipFile(self.apk_path, 'r') as zf:
                    for name in zf.namelist():
                        try:
                            if name.endswith('.dex'):
                                data = zf.read(name)
                                for s in re.findall(rb'[\x20-\x7e]{8,}', data):
                                    all_text += s.decode('ascii', errors='ignore') + "\n"
                            elif (name.endswith('.xml') or name.endswith('.json')
                                  or any(h in name.lower() for h in _CONFIG_FILE_HINTS)):
                                all_text += zf.read(name).decode('utf-8', errors='ignore') + "\n"
                        except Exception:
                            pass
            except Exception as e:
                self.log(f"تعذّر قراءة الـ APK للنصوص: {e}", Y)

        # 2) من بيانات التطبيق على الجهاز (أفضل-جهد، يحتاج root)
        for subdir in ["shared_prefs", "databases", "files"]:
            out, _ = self._su(f"cat /data/data/{self.package}/{subdir}/* 2>/dev/null")
            if out:
                all_text += out + "\n"

        strings_file = os.path.join(self.loot_dir, "strings_dump.txt")
        with open(strings_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(all_text[:2_000_000])
        return all_text

    def find_secrets(self, text):
        """البحث عن المفاتيح والأسرار في النصوص المستخرجة."""
        self.log("البحث عن المفاتيح والأسرار المشفرة...")
        found = dict(self.secrets)  # تراكمي عبر عدة مصادر
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, text, re.MULTILINE)
            if not matches:
                continue
            vals = set(found.get(name, []))
            for m in matches:
                val = m if isinstance(m, str) else next((p for p in m if p), "")
                if not val or val in vals:
                    continue
                vals.add(val)
                self.log(f"  [+] {name}: {val[:50]}...",
                         G if ('key' in name or 'token' in name or 'secret' in name) else Y)
                if self.store:
                    self.store.add("secret", val, source="static", note=name)
            found[name] = list(vals)
        self.secrets = found
        return found

    def find_cloud_endpoints(self, text):
        """البحث عن endpoints سحابية + كل روابط HTTP/HTTPS."""
        self.log("البحث عن نقاط النهاية السحابية...")
        for domain in CLOUD_DOMAINS:
            pattern = rf'https?://[a-zA-Z0-9._-]+\.{re.escape(domain)}[^\s"\'<>]*'
            for m in re.finditer(pattern, text):
                url = m.group(0)
                if url not in self.endpoints:
                    self.endpoints.add(url)
                    if url not in self.cloud_endpoints:
                        self.cloud_endpoints.append(url)
                    self.log(f"  [→] Cloud endpoint: {url}", C)
                    if self.store:
                        self.store.add("endpoint", url, source="static", note=f"cloud_{domain}")

        for m in re.finditer(r'https?://[^\s"\'<>)]+', text):
            self.endpoints.add(m.group(0))
        return list(self.endpoints)

    def analyze_network_config(self):
        """تحليل إعدادات الشبكة والأمان (أفضل-جهد root + من الـ APK)."""
        self.log("تحليل إعدادات الشبكة...")
        # من داخل الـ APK: network_security_config
        if self.apk_path and os.path.isfile(self.apk_path):
            try:
                with zipfile.ZipFile(self.apk_path, 'r') as zf:
                    for name in zf.namelist():
                        if 'network_security_config' in name.lower():
                            content = zf.read(name).decode('utf-8', errors='ignore')
                            if 'cleartextTrafficPermitted="true"' in content:
                                self.log("  [!] cleartextTrafficPermitted=true", R)
                                if self.store:
                                    self.store.add("note", "cleartext traffic permitted", source="static")
                            if 'pin-set' not in content and 'pin ' not in content:
                                self.log("  [i] لا يوجد certificate pinning في network config", Y)
            except Exception:
                pass

    def check_firebase(self):
        """التحقق من Firebase configuration داخل الـ APK ثم على الجهاز."""
        self.log("فحص Firebase...")
        gs_text = ""
        if self.apk_path and os.path.isfile(self.apk_path):
            try:
                with zipfile.ZipFile(self.apk_path, 'r') as zf:
                    for name in zf.namelist():
                        if name.endswith("google-services.json"):
                            gs_text = zf.read(name).decode('utf-8', errors='ignore')
                            break
            except Exception:
                pass
        if not gs_text:
            out, _ = self._su(f"find /data/data/{self.package} -name 'google-services.json' 2>/dev/null")
            if out:
                first = out.split(chr(10))[0]
                gs_text, _ = self._su(f"cat {first}")

        if gs_text:
            self.log("  [+] google-services.json موجود!", G)
            for m in re.finditer(r'"current_key":\s*"([^"]+)"', gs_text):
                self.log(f"  [+] Firebase API Key: {m.group(1)[:30]}...", G)
                if self.store:
                    self.store.add("secret", m.group(1), source="static", note="firebase_api_key")
            for m in re.finditer(r'"project_id":\s*"([^"]+)"', gs_text):
                self.log(f"  [+] Firebase Project: {m.group(1)}", C)
                if self.store:
                    self.store.add("cloud_id", m.group(1), source="static", note="firebase_project")
            for m in re.finditer(r'"firebase_url":\s*"([^"]+)"', gs_text):
                self.endpoints.add(m.group(1))
                if self.store:
                    self.store.add("endpoint", m.group(1), source="static", note="firebase_db")
        return gs_text

    def classify_activities(self):
        """تصنيف الأنشطة → بوابات دخول + شاشات داخلية (post-login) بصيغة pkg/activity.
        الشاشات الداخلية تُسلَّم للمستكشف ليقفز إليها مباشرةً متجاوزاً بوابة الدخول."""
        pkg = (self.manifest.get("package") or self.package)
        login_gates, post_login = [], []
        for a in sorted(set(self.activities)):
            comp = f"{pkg}/{a}"   # صيغة am start -n : pkg/full.class.Name
            short = a.rsplit(".", 1)[-1]
            if _LOGIN_GATE_RE.search(short) and not _POST_LOGIN_RE.search(short):
                login_gates.append(comp)
            elif _POST_LOGIN_RE.search(short):
                post_login.append(comp)
        # الأنشطة المُصدَّرة الداخلية أولوية (قابلة للإطلاق المباشر)
        exported_names = {e["name"] for e in self.exported if e["type"] == "activity"}
        post_login.sort(key=lambda c: 0 if c.rsplit("/", 1)[-1] in exported_names else 1)
        self.login_gates = login_gates
        self.post_login_candidates = post_login
        if post_login:
            self.log(f"شاشات داخلية للقفز إليها (تجاوز الدخول): {len(post_login)} — "
                     f"{', '.join(c.rsplit('/',1)[-1] for c in post_login[:5])}", G)
        if login_gates:
            self.log(f"بوابات دخول مكتشفة: {len(login_gates)}", Y)
        if self.store:
            for c in post_login:
                self.store.add("post_login_activity", c, source="static", note="jump_target")
            for c in login_gates:
                self.store.add("login_gate", c, source="static", note="auth_gate")
        return {"login_gates": login_gates, "post_login_candidates": post_login}

    def run_full_static(self):
        """تشغيل التحليل الساكن الكامل."""
        print(f"\n{M}{'='*60}{X}")
        print(f"{M}      المحرك الساكن - Static Analysis Engine{X}")
        print(f"{M}      Target: {self.package}{X}")
        print(f"{M}{'='*60}{X}\n")

        self.pull_apk()
        self.extract_manifest()
        self.analyze_network_config()
        self.check_firebase()

        strings = self.extract_strings()
        self.find_secrets(strings)
        self.find_cloud_endpoints(strings)

        self.classify_activities()   # بوابات دخول + شاشات داخلية للقفز إليها

        report = {
            "package": self.package,
            "timestamp": datetime.now().isoformat(),
            "app_info": self.manifest,
            "manifest": {
                "permissions": sorted(set(self.permissions)),
                "activities": sorted(set(self.activities)),
                "services": sorted(set(self.services)),
                "receivers": sorted(set(self.receivers)),
                "providers": sorted(set(self.providers)),
                "exported": self.exported,
            },
            "secrets": {k: sorted(set(v)) for k, v in self.secrets.items()},
            "endpoints": sorted(self.endpoints),
            "cloud_endpoints": sorted(set(self.cloud_endpoints)),
            "login_gates": self.login_gates,
            "post_login_candidates": self.post_login_candidates,
        }

        report_path = os.path.join(self.loot_dir, "static_report.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        n_secrets = sum(len(v) for v in report['secrets'].values())
        print(f"\n{G}{'='*60}{X}")
        print(f"{G}  التحليل الساكن اكتمل!{X}")
        print(f"{G}  - {len(report['manifest']['permissions'])} صلاحيات{X}")
        print(f"{G}  - {len(report['manifest']['activities'])} نشاطات{X}")
        print(f"{G}  - {len(report['manifest']['services'])} خدمات{X}")
        print(f"{G}  - {len(report['manifest']['exported'])} مكوّن مُصدَّر (سطح هجوم){X}")
        print(f"{G}  - {n_secrets} سر/مفتاح{X}")
        print(f"{G}  - {len(report['endpoints'])} نقطة نهاية ({len(report['cloud_endpoints'])} سحابية){X}")
        print(f"{G}  - التقرير: {report_path}{X}")
        print(f"{G}{'='*60}{X}\n")

        if self.store:
            for p in sorted(set(self.permissions)):
                self.store.add("note", f"permission:{p}", source="static")
            for a in sorted(set(self.activities)):
                self.store.add("note", f"activity:{a}", source="static")
            for s in sorted(set(self.services)):
                self.store.add("note", f"service:{s}", source="static")
            for ex in self.exported:
                self.store.add("attack_surface", f"{ex['type']}:{ex['name']}",
                               source="static", note="exported")
            self.store.add("note", "static_analysis_complete", source="static")

        return report


if __name__ == "__main__":
    import argparse
    try:
        from intel_store import IntelStore
    except Exception:
        IntelStore = None

    ap = argparse.ArgumentParser()
    ap.add_argument("--package", "-p", required=True, help="Package name")
    ap.add_argument("--device", "-d", default="emulator-5554")
    args = ap.parse_args()

    store = IntelStore(args.package) if IntelStore else None
    engine = StaticEngine(args.package, store=store, device=args.device)
    report = engine.run_full_static()
    if store:
        store.save()
