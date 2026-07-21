#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Campaign Orchestrator (campaign.py)
===================================================
The methodology the owner asked for, end to end, managed by the AI agent:

  1) STATIC  — pull the APK from the device (or --apk), extract embedded secrets /
     backend hosts / endpoints / cloud ids → SEED the shared blackboard (IntelStore).
  2) SEED    — derive exploration goals from what static found.
  3) DYNAMIC — run the unified DynamicEngine (deep Frida instrumentation + the
     AI-guided explorer), wired to the SAME blackboard. Everything captured live
     (tokens, TLS requests, reached screens, runtime findings) flows into it.
  4) FEEDBACK — a live correlator subscribes to NEW facts: the moment a credential
     or endpoint appears (from static OR dynamic), it is validated / probed against
     the discovered backends, and the result is written back to the blackboard —
     so advanced stages exploit what earlier stages discovered.
  5) REPORT  — the brain triages the whole blackboard and writes one unified,
     prioritized report (loot/campaign_<pkg>_<ts>.md/.json + intel_<pkg>.json).

Usage:
  py -3.12 campaign.py --package com.app --device emulator-5554 --duration 180
  Options: --apk PATH (skip device pull), --no-ai, --static-only, --goal "...".
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime

from intel_store import IntelStore
from llm_brain import LLMBrain
from dynamic_engine import DynamicEngine

HERE = os.path.dirname(os.path.abspath(__file__))
LOOT = os.path.join(HERE, "loot")
E = chr(27); G = E + "[92m"; R = E + "[91m"; Y = E + "[93m"; C = E + "[96m"; B = E + "[1m"; X = E + "[0m"

# ── secret/url patterns (self-contained; mirrors hayo_auto without importing it) ──
SECRET_PATTERNS = [
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("openai_key",     re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("anthropic_key",  re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("aws_key",        re.compile(rb"(?:AKIA|ASIA|AGPA|AROA)[0-9A-Z]{16}")),
    ("stripe_key",     re.compile(rb"[sr]k_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("github_token",   re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("slack_token",    re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("jwt",            re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}")),
]
CLOUD_PATTERNS = [
    ("firebase_rtdb",    re.compile(rb"https://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)")),
    ("firebase_storage", re.compile(rb"[a-z0-9\-]+\.(?:appspot\.com|firebasestorage\.app)")),
    ("supabase",         re.compile(rb"https://[a-z0-9]{16,}\.supabase\.co")),
]
URL_RE = re.compile(rb"https?://[a-zA-Z0-9.\-]+(?::\d{2,5})?(?:/[a-zA-Z0-9._/\-]*)?")
URL_NOISE = re.compile(rb"schemas\.android|w3\.org|apache\.org|bouncycastle|gstatic|fonts\.google|"
                       rb"play\.google|goo\.gl|schema\.org|json-schema|googleapis\.com/oauth|"
                       rb"facebook\.com|youtube|twitter|instagram|whatsapp|gnu\.org|openssl\.org|"
                       rb"sqlite\.org|kernel\.org|w3\.org|xmlpull|ns\.adobe", re.I)


def log(m): print(m, flush=True)


def adb(dev, *args, timeout=30, binary=False):
    cmd = [ADB] + (["-s", dev] if dev else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout if binary else (r.stdout.decode("utf-8", "ignore"))
    except Exception:
        return b"" if binary else ""


# ── STATIC phase ────────────────────────────────────────────────────────────
def pull_apk(dev, package, dest_dir):
    out = adb(dev, "shell", "pm", "path", package)
    paths = [ln.split("package:", 1)[1].strip() for ln in out.splitlines() if ln.startswith("package:")]
    if not paths:
        return None
    os.makedirs(dest_dir, exist_ok=True)
    local = os.path.join(dest_dir, "base.apk")
    # base.apk is enough for secret/URL extraction; splits rarely hold secrets
    base = next((p for p in paths if p.endswith("base.apk")), paths[0])
    r = subprocess.run([ADB] + (["-s", dev] if dev else []) + ["pull", base, local],
                       capture_output=True, timeout=120)
    return local if os.path.isfile(local) else None


def scan_bytes(blob):
    """Return (secrets{kind:set}, clouds{kind:set}, urls:set) from a byte blob."""
    secrets, clouds, urls = {}, {}, set()
    for kind, rx in SECRET_PATTERNS:
        for m in rx.findall(blob):
            secrets.setdefault(kind, set()).add(m.decode("ascii", "ignore"))
    for kind, rx in CLOUD_PATTERNS:
        for m in rx.findall(blob):
            clouds.setdefault(kind, set()).add(m.decode("ascii", "ignore"))
    for m in URL_RE.findall(blob):
        if URL_NOISE.search(m):
            continue
        s = m.decode("ascii", "ignore")
        if re.match(r"https?://[a-z0-9.\-]+\.[a-z]{2,}", s, re.I):
            urls.add(s)
    return secrets, clouds, urls


def run_static(store, apk_path):
    log(C + B + f"\n══ [1/3] STATIC — extracting from {os.path.basename(apk_path)} ══" + X)
    total = {"secret": 0, "cloud": 0, "url": 0}
    try:
        zf = zipfile.ZipFile(apk_path)
    except Exception as e:
        log(R + f"[!] cannot open APK: {e}" + X); return total
    for name in zf.namelist():
        if not re.search(r"\.(dex|so|arsc|xml|json|properties|js|txt)$|assets/", name):
            continue
        try:
            blob = zf.read(name)[:16_000_000]
        except Exception:
            continue
        secrets, clouds, urls = scan_bytes(blob)
        for kind, vals in secrets.items():
            for v in vals:
                if store.add("secret", v, source="static", note=kind, verified=False):
                    total["secret"] += 1
                    log(G + f"  🔑 {kind}: " + X + v[:60] + Y + f"  @ {name}" + X)
        for kind, vals in clouds.items():
            for v in vals:
                if store.add("cloud_id", v, source="static", provider=kind):
                    total["cloud"] += 1
                    log(C + f"  ☁️  {kind}: " + X + v[:70] + X)
        for v in urls:
            if store.add("url", v, source="static"):
                total["url"] += 1
    log(Y + f"  static seeded blackboard: {total['secret']} secrets, {total['cloud']} cloud ids, "
        f"{total['url']} urls." + X)
    return total


def seed_goals(store):
    store.add("note", "goal: reach login and authenticate", source="seed")
    store.add("note", "goal: reach premium/subscription screens", source="seed")
    if store.query("cloud_id") or any("firebase" in u.lower() for u in store.values("url")):
        store.add("note", "goal: trigger cloud sync to capture backend tokens", source="seed")


# ── FEEDBACK: live correlator ───────────────────────────────────────────────
class Correlator:
    """Subscribes to NEW facts and validates credentials / probes endpoints the
    moment they appear, from static OR dynamic — the static↔dynamic feedback loop."""
    def __init__(self, store):
        self.store = store
        self._seen = set()
        self._lock = threading.Lock()
        try:
            import requests; self.requests = requests
        except Exception:
            self.requests = None

    def on_fact(self, kind, value, fact):
        if self.requests is None:
            return
        if kind == "secret" and (fact.get("kind") == "google_api_key" or value.startswith("AIza")):
            self._bg(self._check_google, value)
        elif kind in ("credential",) or (kind == "secret" and value.lower().startswith(("bearer", "eyj"))):
            self._bg(self._probe_hosts_with_token, value)

    def _bg(self, fn, arg):
        with self._lock:
            k = fn.__name__ + "|" + arg[:40]
            if k in self._seen:
                return
            self._seen.add(k)
        threading.Thread(target=fn, args=(arg,), daemon=True).start()

    def _check_google(self, key):
        try:
            r = self.requests.get(
                f"https://generativelanguage.googleapis.com/v1beta/models?key={key}", timeout=10)
            live = r.status_code == 200
            self.store.add("cred_test", key, source="correlator",
                           note=("LIVE Google/Gemini key" if live else f"invalid (HTTP {r.status_code})"),
                           verified=live)
            if live:
                self.store.add_finding({
                    "type": "live_credential", "severity": "critical",
                    "title": "مفتاح Google حيّ (تحقّق مباشر)",
                    "detail": "المفتاح المستخرج فعّال ويصل خدمة Google Generative Language.",
                    "evidence": [{"label": "google_api_key", "value": key, "sensitive": True}],
                    "phase": "correlation"})
                log(R + B + f"  [✓ LIVE] Google API key verified active: {key[:16]}…" + X)
        except Exception:
            pass

    def _probe_hosts_with_token(self, token):
        token = token.split(" ", 1)[1] if token.lower().startswith("bearer ") else token
        hosts = [u for u in self.store.values("url") if "://" in u]
        origins = sorted({re.match(r'(https?://[^/]+)', u).group(1) for u in hosts if re.match(r'https?://[^/]+', u)})
        for origin in origins[:6]:
            try:
                r = self.requests.get(origin, headers={"Authorization": "Bearer " + token},
                                      timeout=8, allow_redirects=False)
                self.store.add("cred_test", origin, source="correlator",
                               note=f"token→{origin} HTTP {r.status_code}")
            except Exception:
                pass


# ── unified report ──────────────────────────────────────────────────────────
def write_report(store, brain, package, dynamic_meta):
    findings = store.findings
    log(C + B + f"\n══ [3/3] REPORT — triaging {len(findings)} findings over the blackboard ══" + X)
    triaged = brain.triage(findings)
    session = {
        "package": package,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "brain": ("deepseek:" + brain.model) if brain.available else "offline",
        "intel_counts": store.counts(),
        "visited": dynamic_meta.get("visited", []),
        "explore_steps": dynamic_meta.get("explore_steps", 0),
        "raw_count": len(findings),
        "findings": findings,
        "triaged": triaged,
        "blackboard": store.brain_context(30),
    }
    session["summary"] = brain.summarize(session)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(LOOT, f"campaign_{package}_{ts}")
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(session, f, ensure_ascii=False, indent=2)
    _md(base + ".md", store, session, triaged)
    intel_path = store.save(os.path.join(LOOT, f"intel_{package}.json"))

    sev = {}
    for t in triaged:
        s = str(t.get("severity", "info")).lower(); sev[s] = sev.get(s, 0) + 1
    log(G + B + f"\n[✓] campaign complete — {len(triaged)} findings "
        f"(critical={sev.get('critical',0)} high={sev.get('high',0)} medium={sev.get('medium',0)})." + X)
    log(Y + f"    report : {base}.md" + X)
    log(Y + f"    intel  : {intel_path}" + X)
    log(C + "\n── ملخّص ──\n" + X + session["summary"] + "\n")
    return session


def _md(path, store, session, triaged):
    c = store.counts()
    L = ["# HAYO Cipher-7 — تقرير الحملة الكاملة (ثابت + ديناميكي)", "",
         f"- **التطبيق:** `{session['package']}`",
         f"- **التاريخ:** {session['timestamp']}",
         f"- **العقل:** {session['brain']}",
         f"- **السبّورة:** أسرار={c.get('secret',0)}, بيانات اعتماد={c.get('credential',0)}, "
         f"روابط={c.get('url',0)}, نقاط نهاية={c.get('endpoint',0)}, سحابة={c.get('cloud_id',0)}, "
         f"شاشات={c.get('ui_screen',0)}",
         f"- **شاشات زُرِت (استكشاف):** {len(session['visited'])} — خطوات: {session['explore_steps']}",
         f"- **نتائج خام:** {session['raw_count']} — بعد الفرز: {len(triaged)}", "",
         "## الملخّص التنفيذي", "", session["summary"], "",
         "## النتائج (مرتّبة حسب الخطورة)", ""]
    for i, t in enumerate(triaged, 1):
        fp = " *(محتمل إيجابية كاذبة)*" if t.get("false_positive") else ""
        L.append(f"### {i}. [{str(t.get('severity','info')).upper()}] {t.get('title','')}{fp}")
        if t.get("why"): L.append(f"- **الوصف:** {t['why']}")
        if t.get("exploitation"): L.append(f"- **الاستغلال:** {t['exploitation']}")
        if t.get("type"): L.append(f"- **النوع:** `{t['type']}`")
        L.append("")
    # verified credentials section
    tests = [f for f in store.query("cred_test") if f.get("verified")]
    if tests:
        L += ["## بيانات اعتماد مُتحقّقة حيّاً", ""]
        for f in tests:
            L.append(f"- `{f['value'][:50]}…` — {(f.get('notes') or ['?'])[0]}")
        L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    global ADB
    ap = argparse.ArgumentParser(description="HAYO Cipher-7 — static→dynamic campaign orchestrator")
    ap.add_argument("--package", required=True)
    ap.add_argument("--device", default=os.environ.get("HAYO_DEV", "emulator-5554"))
    ap.add_argument("--adb", default=os.environ.get("HAYO_ADB", "C:/Users/PT/Downloads/platform-tools/adb.exe"))
    ap.add_argument("--apk", help="APK path (skip pulling from device)")
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--static-only", action="store_true")
    ap.add_argument("--goal", default="reach login, premium/subscription and cloud-sync screens")
    args = ap.parse_args()
    ADB = args.adb

    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(encoding="utf-8", errors="replace")
        except Exception: pass
    if os.name == "nt":
        try: os.system("chcp 65001 >nul")
        except Exception: pass

    os.makedirs(LOOT, exist_ok=True)
    store = IntelStore(args.package)
    brain = LLMBrain()
    store.add("package", args.package, source="input")

    log(C + B + "\n╔══ HAYO Cipher-7 — الحملة الموحّدة (Static → Blackboard → Dynamic → Report) ══╗" + X)
    log(f"  target: {args.package}   device: {args.device}   "
        f"brain: {'DeepSeek' if brain.available else 'OFFLINE heuristics'}")

    # 1) STATIC
    apk = args.apk
    if not apk:
        log(Y + "  [*] pulling APK from device…" + X)
        apk = pull_apk(args.device, args.package, os.path.join(LOOT, "apk", args.package))
    if apk and os.path.isfile(apk):
        run_static(store, apk)
    else:
        log(R + "  [!] no APK to analyze statically — continuing with dynamic only." + X)
    seed_goals(store)

    # 2) FEEDBACK correlator (subscribe BEFORE dynamic so it reacts to live facts)
    corr = Correlator(store)
    store.on_new(corr.on_fact)
    # fire correlator over what static already seeded
    for f in store.query("secret"):
        corr.on_fact("secret", f["value"], f)

    if args.static_only:
        write_report(store, brain, args.package, {"visited": [], "explore_steps": 0})
        return

    # 3) DYNAMIC (shares the blackboard + brain)
    log(C + B + "\n══ [2/3] DYNAMIC — deep instrumentation + AI-guided exploration ══" + X)
    eng = DynamicEngine(args.package, args.device, args.adb, args.duration,
                        use_ai=not args.no_ai, goal=args.goal,
                        store=store, brain=brain, report=False)
    dyn_meta = eng.run()

    # 4) REPORT over the whole blackboard
    time.sleep(1.5)   # let last correlator probes land
    write_report(store, brain, args.package, dyn_meta or {})


if __name__ == "__main__":
    main()
