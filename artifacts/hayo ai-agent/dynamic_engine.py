#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Unified Dynamic Engine (dynamic_engine.py)
==========================================================
ONE engine that supersedes the fragmented launchers. It:
  1) spawns the target ONCE and loads the deep instrumentation (scripts/instrument.js:
     crypto transparency, native TLS, network, storage, memory scavenger, subscription/
     billing bypass) via the reliable Frida Python API,
  2) drives the app with an AI brain (DeepSeek) instead of random taps — the brain
     navigates toward login / premium / cloud screens to trigger the interesting code,
  3) streams every runtime finding to console + loot, then
  4) has the brain TRIAGE the findings and write a prioritized JSON + Markdown report.

Usage:
  py -3.12 dynamic_engine.py --package com.app --device emulator-5554 --duration 180
  Options: --no-ai (heuristic explorer), --goal "...", --adb PATH,
           --server URL --token dyn_xxx  (optional: merge into the HAYO platform report)
"""
import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime

try:
    import frida
except ImportError:
    sys.exit("[!] frida missing for this interpreter. Run:\n"
             "    py -3.12 -m pip install \"frida==16.7.19\" \"frida-tools\" requests")

try:
    import requests
except ImportError:
    requests = None

from llm_brain import LLMBrain
try:
    from ai_explorer import AIExplorer
    _HAS_EXPLORER = True
except Exception as e:
    print(f"[!] ai_explorer unavailable: {e}")
    _HAS_EXPLORER = False

# New advanced components
try:
    from pipeline_orchestrator import PipelineOrchestrator, PhaseStatus
    _HAS_PIPELINE = True
except Exception as e:
    print(f"[!] pipeline_orchestrator unavailable: {e}")
    _HAS_PIPELINE = False

try:
    from working_memory import WorkingMemory, Priority
    _HAS_WORKING_MEMORY = True
except Exception as e:
    print(f"[!] working_memory unavailable: {e}")
    _HAS_WORKING_MEMORY = False

try:
    from realtime_decision_engine import RealtimeDecisionEngine, Event
    _HAS_DECISION_ENGINE = True
except Exception as e:
    print(f"[!] realtime_decision_engine unavailable: {e}")
    _HAS_DECISION_ENGINE = False

try:
    from live_data_extractor import LiveDataExtractor
    _HAS_DATA_EXTRACTOR = True
except Exception as e:
    print(f"[!] live_data_extractor unavailable: {e}")
    _HAS_DATA_EXTRACTOR = False

try:
    from phase_manager_brain import PhaseManagerBrain, PhaseContext
    _HAS_PHASE_BRAIN = True
except Exception as e:
    print(f"[!] phase_manager_brain unavailable: {e}")
    _HAS_PHASE_BRAIN = False

try:
    from adaptive_exploitation_engine import AdaptiveExploitationEngine
    _HAS_EXPLOIT_ENGINE = True
except Exception as e:
    print(f"[!] adaptive_exploitation_engine unavailable: {e}")
    _HAS_EXPLOIT_ENGINE = False

try:
    from feedback_loop import FeedbackLoop
    _HAS_FEEDBACK_LOOP = True
except Exception as e:
    print(f"[!] feedback_loop unavailable: {e}")
    _HAS_FEEDBACK_LOOP = False

HERE = os.path.dirname(os.path.abspath(__file__))


def _pick_instrumentation():
    """يُفضّل السكربت العميق (instrument_ultimate.js: 100+ hooks) على instrument_deep.js على instrument.js."""
    ultimate = os.path.join(HERE, "scripts", "instrument_ultimate.js")
    deep = os.path.join(HERE, "scripts", "instrument_deep.js")
    basic = os.path.join(HERE, "scripts", "instrument.js")
    return ultimate if os.path.isfile(ultimate) else (deep if os.path.isfile(deep) else basic)


SCRIPT_PATH = _pick_instrumentation()
LOOT = os.path.join(HERE, "loot")

E = chr(27)
G = E + "[92m"; R = E + "[91m"; Y = E + "[93m"; C = E + "[96m"; B = E + "[1m"; X = E + "[0m"


def _utf8():
    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(encoding="utf-8", errors="replace")
        except Exception: pass
    if os.name == "nt":
        try: os.system("chcp 65001 >nul")
        except Exception: pass
        try:
            import ctypes; k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception: pass


def _ensure_frida_server(adb, device):
    import subprocess as _sp
    dev_args = [adb] + (["-s", device] if device else [])
    try:
        out = _sp.run(dev_args + ["shell", "su -c 'ps -A'"],
                      capture_output=True, text=True, timeout=10, errors="ignore").stdout
        if "frida-server" in out:
            return True
    except Exception:
        return False
    print(Y + "  [*] frida-server not running — starting it…" + X)
    for path in ("/data/local/tmp/frida-server", "/data/local/tmp/frida-bin/fs-bin.1-android-x86"):
        try:
            _sp.run(dev_args + ["shell", f"su -c 'chmod 755 {path} && {path} -D &'"],
                    timeout=5, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            import time; time.sleep(2)
            out = _sp.run(dev_args + ["shell", "su -c 'ps -A'"],
                          capture_output=True, text=True, timeout=10, errors="ignore").stdout
            if "frida-server" in out:
                print(G + f"  [+] frida-server started from {path}" + X)
                return True
        except Exception:
            continue
    print(R + "  [!] could not start frida-server automatically." + X)
    return False


class DynamicEngine:
    def __init__(self, package, device, adb="adb", duration=180, use_ai=True,
                 goal="reach login, premium/subscription and cloud-sync screens",
                 store=None, brain=None, report=True,
                 until_goal=True, max_steps=160, stagnation_limit=20,
                 use_pipeline=False):
        self.package = package; self.device = device; self.adb = adb
        self.duration = duration; self.use_ai = use_ai; self.goal = goal
        # القيادة التقارُبية: حتى النجاح (نتيجة حرجة) أو الركود أو سقف الخطوات؛
        # duration يصبح شبكة أمان قصوى فقط عندما until_goal=True.
        self.until_goal = until_goal
        self.max_steps = max_steps
        self.stagnation_limit = stagnation_limit
        self.findings = []
        self._seen = set()
        self._mem_classes = set()   # ضجيج «memory scavenger»: أصناف محمّلة (ليست نتائج)
        self._alloc_counts = {}     # عدّاد تخصيص/تحرير الذاكرة الخام (malloc/free) بدل نتيجة/استدعاء
        self.use_pipeline = use_pipeline  # Enable new pipeline orchestrator
        
        # WarRoomBrain يوفّر triage()/summarize()/decide_action() التي يحتاجها المحرك؛
        # LLMBrain العام لا يملك triage/summarize → كان التقرير ينهار في التشغيل المستقل.
        if brain is None:
            try:
                from warroom_brain import WarRoomBrain
                brain = WarRoomBrain(package, store=store)
            except Exception as _e:
                print(Y + f"  [*] WarRoomBrain غير متاح ({_e}) — ارتداد إلى LLMBrain" + X)
                brain = LLMBrain()
        self.brain = brain
        self.store = store           # optional shared blackboard (campaign mode)
        self.report = report         # False → campaign writes the unified report
        self.explorer = None
        os.makedirs(LOOT, exist_ok=True)
        
        # Try to use ExtendedBrain if available (supports all advanced components)
        try:
            from extended_brain import ExtendedBrain
            # Wrap the existing brain with ExtendedBrain
            brain = ExtendedBrain(base_brain=brain, verbose=True)
            print(G + "  [+] Using ExtendedBrain for advanced components" + X)
        except ImportError:
            print(Y + "  [*] ExtendedBrain not available - advanced components disabled" + X)
        
        # Initialize new advanced components (only if brain supports required methods)
        brain_has_required_methods = hasattr(brain, 'decide') and hasattr(brain, 'select_exploit') and hasattr(brain, 'update_strategy')
        
        self.working_memory = WorkingMemory() if _HAS_WORKING_MEMORY else None
        self.phase_manager_brain = PhaseManagerBrain(package) if _HAS_PHASE_BRAIN else None
        # أُعيد تفعيله: عطل التكامل (تمرير نص بدل Event + .get() على كائن Decision +
        # إغراق الـ LLM) أُصلح — الآن يمرّر Event ويُرجع Decision ويُحدّد معدّل الاستشارة.
        self.realtime_decision_engine = RealtimeDecisionEngine(brain, self.working_memory) if (_HAS_DECISION_ENGINE and self.working_memory and brain_has_required_methods) else None
        self.live_data_extractor = LiveDataExtractor(self.working_memory) if (_HAS_DATA_EXTRACTOR and self.working_memory) else None
        self.adaptive_exploitation_engine = AdaptiveExploitationEngine(brain, self.working_memory) if (_HAS_EXPLOIT_ENGINE and self.working_memory and brain_has_required_methods) else None
        self.feedback_loop = FeedbackLoop(brain, self.working_memory) if (_HAS_FEEDBACK_LOOP and self.working_memory and brain_has_required_methods) else None
        self.pipeline_orchestrator = PipelineOrchestrator(package, device, brain, adb) if (_HAS_PIPELINE and self.phase_manager_brain and brain_has_required_methods) else None
        
        # Cloud bypass integration
        self.cloud_bypass_enabled = False  # Disabled in favor of final script
        self.cloud_bypass_script = os.path.join(os.path.dirname(__file__), "scripts", "cloud_bypass_frida.js")
        self.premium_unlock_enabled = True
        self.premium_unlock_script = os.path.join(os.path.dirname(__file__), "scripts", "final_premium_unlock.js")
        self.native_bypass_script = os.path.join(os.path.dirname(__file__), "scripts", "native_premium_bypass.js")
        # اعتراض الرسائل بين التطبيق والسحابة (OkHttp/HttpURLConnection/org.json) →
        # إعادة كتابة إشارة الاشتراك إلى «premium مسموح»، مع أدلة حقيقية «قبل/بعد».
        self.entitlement_interceptor_script = os.path.join(os.path.dirname(__file__), "scripts", "cloud_entitlement_interceptor.js")

    def _brain_online(self):
        """يكتشف مزوّد LLM حيّاً سواء كان brain = LLMBrain (self.engine) أو
        WarRoomBrain (self.brain = LLMBrain داخلي)."""
        for obj in (self.brain, getattr(self.brain, "brain", None)):
            if obj is None:
                continue
            eng = getattr(obj, "engine", None)
            if eng is not None and getattr(eng, "providers", []):
                return True
        return False

    # ── finding shaping ─────────────────────────────────────────────────────
    _SEV_CRIT = ("key", "secret", "token", "password", "credential",
                 "private", "seed", "mnemonic", "apikey", "api_key")
    # ملاحظة: لا نضع "native" وحدها هنا — كانت تُصنّف كل native_malloc/native_free
    # كـ HIGH وتُغرق التقرير بعشرات الآلاف من الإيجابيات الكاذبة. نكتفي بالأنواع
    # الأصلية ذات المعنى الأمني فقط (SSL/تحميل مكتبات ديناميكي/تحميل DEX أصلي).
    _SEV_HIGH = ("auth", "billing", "premium", "purchase", "subscription",
                 "cloud", "firebase", "ssl", "pinning", "dex_load",
                 "webview_js", "native_ssl", "native_dlopen", "native_dlsym",
                 "native_exec", "response_body", "jwt")

    def _infer_severity(self, ftype, payload):
        explicit = payload.get("severity")
        if explicit:
            return str(explicit).lower()
        t = (ftype or "").lower()
        if any(k in t for k in self._SEV_CRIT):
            return "critical"
        if any(k in t for k in self._SEV_HIGH):
            return "high"
        return "medium"

    def _shape_finding(self, p):
        """يحوّل payload الغني من instrument_deep.js إلى نتيجة موحّدة تحافظ على كل
        البيانات (المفتاح/الرابط/القيمة) وتُسند خطورة حسب النوع."""
        ftype = p.get("type", "unknown")
        reserved = {"kind", "type", "ts", "severity", "title", "detail", "evidence", "phase"}
        extra = {k: v for k, v in p.items() if k not in reserved}
        evidence = p.get("evidence")
        if not evidence:
            evidence = [f"{k}={v}" for k, v in extra.items()] or []
        detail = p.get("detail") or "; ".join(f"{k}={str(v)[:160]}" for k, v in extra.items())
        return {
            "type": ftype,
            "title": p.get("title") or ftype.replace("_", " ").title(),
            "severity": self._infer_severity(ftype, p),
            "detail": detail,
            "why": detail,
            "data": detail,
            "evidence": evidence,
            "phase": p.get("phase", "dynamic"),
            "raw": extra,
        }

    # ── frida message pump ─────────────────────────────────────────────────
    def _on_message(self, message, data):
        if message.get("type") == "error":
            print(R + "  [js-error] " + str(message.get("description", ""))[:120] + X)
            return
        p = message.get("payload") or {}
        # instrument_deep.js يغلّف بطبقة زائدة {type:"message", payload:{...}} — نفكّها
        if p.get("type") == "message" and isinstance(p.get("payload"), dict):
            p = p["payload"]
        kind = p.get("kind")
        if kind == "ready":
            print(G + "  [*] hooks active — الاستكشاف يقود التطبيق الآن." + X)
        elif kind == "finding":
            # كبت ضجيج تعداد الأصناف (memory_class / bypass_target_class / *_class):
            # وجود صنف محمّل في الذاكرة ليس نتيجة — المزوّد/النظام يحمّل آلاف الأصناف
            # بغضّ النظر عن استخدام التطبيق، فتعدادها يُنتج إيجابيات كاذبة «high».
            ftype = p.get("type", "")
            if ftype.endswith("_class"):
                cls = p.get("class") or p.get("name") or ""
                if cls:
                    self._mem_classes.add(cls)
                return
            # كبت ضجيج تخصيص/تحرير الذاكرة الخام: أي تطبيق يستدعي malloc/free
            # ملايين المرات، وكانت تُنتج ~99.9% من النتائج (عشرات الآلاف). نجمّعها
            # في عدّاد واحد بدل نتيجة لكل استدعاء، ونُصدر ملخّصاً واحداً في النهاية.
            if ftype in ("native_malloc", "native_free", "native_calloc",
                         "native_realloc"):
                self._alloc_counts[ftype] = self._alloc_counts.get(ftype, 0) + 1
                return
            f = self._shape_finding(p)
            key = f["type"] + "|" + json.dumps(f["evidence"], ensure_ascii=False, sort_keys=True)[:200]
            if key in self._seen:
                return
            self._seen.add(key)
            self.findings.append(f)
            if self.store is not None:
                try: self.store.add_finding(f)
                except Exception: pass
            sev = f["severity"]; col = R if sev in ("critical", "high") else (Y if sev == "medium" else X)
            print(col + f"  [+] [{sev:<8}] {f['type']:<26} {(f['detail'] or '')[:70]}" + X)
            
            # Extract live data using new component
            if self.live_data_extractor:
                try:
                    self.live_data_extractor.extract({
                        "type": ftype,
                        "data": f.get("raw", {}),
                        "source": "frida",
                    })
                except Exception as e:
                    pass
            
            # Feed into feedback loop — النجاح يعكس **قيمة النتيجة الحقيقية** لا مجرد
            # أن الخطاف أُطلق. (عالٍ/حرِج ومؤكَّد = نجاح؛ متوسط = نجاح جزئي؛
            # منخفض/معلومة/إيجابية-كاذبة = لا). سابقاً كان success=True دائماً فيصير
            # مقياس معدّل النجاح 100% بلا معنى.
            if self.feedback_loop:
                try:
                    fp = bool(f.get("false_positive", False))
                    valuable = (sev in ("critical", "high")) and not fp
                    partial = (sev == "medium") and not fp
                    self.feedback_loop.collect_feedback(
                        action=f"frida_hook_{ftype}",
                        result={"success": valuable, "partial_success": partial,
                                "severity": sev, "false_positive": fp,
                                "type": ftype, "data": f.get("raw", {})},
                        context={"severity": sev, "finding_type": ftype}
                    )
                except Exception as e:
                    pass
            
            # Real-time decision making
            if self.realtime_decision_engine:
                try:
                    from realtime_decision_engine import Event
                    event = Event(
                        type="finding",
                        data={"type": ftype, "severity": sev, "raw": f.get("raw", {})},
                        source="frida"
                    )
                    decision = self.realtime_decision_engine.decide(event)
                    if decision and hasattr(decision, 'type') and decision.type.value == "escalate":
                        print(C + f"  [ai] Decision: {decision.action} ({decision.reasoning})" + X)
                except AttributeError as e:
                    # Brain doesn't have required methods - skip AI decision
                    pass
                except Exception as e:
                    pass
            
            # keep the explorer's context fresh so the brain reacts آنياً لما أطلقه
            if self.explorer:
                crit = sum(1 for x in self.findings if x["severity"] in ("critical", "high"))
                self.explorer.findings_summary = f"{len(self.findings)} findings so far ({crit} high/critical)"
                self.explorer.finding_count = len(self.findings)   # يُغذّي تتبّع التقدّم
                if sev == "critical":
                    self.explorer.goal_reached = True              # نجاح → يوقف التقارب
        elif kind == "crawler_target":
            act = p.get("activity", "")
            if act:
                if self.store is not None:
                    try: self.store.add("ui_screen", act, source="frida")
                    except Exception: pass
                print(C + f"  [→] activity reached: {act}" + X)

    def _on_step(self, kind, data):
        if kind == "action":
            print(C + f"  [ai] {data.get('action','?'):<7} — {data.get('reason','')[:70]}" + X)
        elif kind == "screen":
            print(Y + f"  [ai] new screen: {data.get('activity','?')} ({data.get('elements',0)} elements)" + X)
        elif kind == "done":
            print(G + f"  [ai] exploration done: {data.get('steps')} steps, {data.get('screens')} screens" + X)

    # ── run ────────────────────────────────────────────────────────────────
    def run(self):
        print(C + B + f"\n══ HAYO Cipher-7 — Unified Dynamic Engine ══" + X)
        print(f"  target : {self.package}")
        print(f"  device : {self.device}")
        brain_online = self._brain_online()
        print(f"  brain  : {'DeepSeek ('+str(getattr(self.brain,'model','?'))+')' if brain_online else 'OFFLINE heuristics (no DEEPSEEK_API_KEY)'}")
        print(f"  window : {self.duration}s")
        if self.use_pipeline:
            print(f"  pipeline: ENABLED (new sequential orchestration)")
        print()
        if not os.path.isfile(SCRIPT_PATH):
            sys.exit(f"[!] instrumentation script not found: {SCRIPT_PATH}")

        _ensure_frida_server(self.adb, self.device)

        try:
            device = frida.get_device(self.device, timeout=10) if self.device else frida.get_usb_device(timeout=10)
        except Exception as e:
            sys.exit(R + f"[!] cannot reach device '{self.device}': {e}" + X)
        try:
            pid = device.spawn([self.package])
            session = device.attach(pid)
        except Exception as e:
            sys.exit(R + f"[!] spawn failed for '{self.package}': {e}\n    (installed? frida-server up?)" + X)

        src = open(SCRIPT_PATH, "r", encoding="utf-8").read()
        script = session.create_script(src)
        script.on("message", self._on_message)
        script.load()
        
        # Load cloud bypass script if enabled
        if self.cloud_bypass_enabled and os.path.exists(self.cloud_bypass_script):
            try:
                print(C + f"  [*] Loading cloud bypass script from: {self.cloud_bypass_script}" + X)
                bypass_src = open(self.cloud_bypass_script, "r", encoding="utf-8").read()
                bypass_script = session.create_script(bypass_src)
                bypass_script.on("message", self._on_message)
                bypass_script.load()
                print(G + "  [+] Cloud bypass script loaded successfully." + X)
            except Exception as e:
                print(Y + f"  [*] Failed to load cloud bypass script: {e}" + X)
                import traceback
                traceback.print_exc()
        else:
            print(Y + f"  [*] Cloud bypass script not found or disabled" + X)
        
        # Load premium unlock script if enabled
        if self.premium_unlock_enabled and os.path.exists(self.premium_unlock_script):
            try:
                print(C + f"  [*] Loading premium unlock script from: {self.premium_unlock_script}" + X)
                premium_src = open(self.premium_unlock_script, "r", encoding="utf-8").read()
                premium_script = session.create_script(premium_src)
                premium_script.on("message", self._on_message)
                premium_script.load()
                print(G + "  [+] Premium unlock script loaded successfully." + X)
            except Exception as e:
                print(Y + f"  [*] Failed to load premium unlock script: {e}" + X)
                import traceback
                traceback.print_exc()
        else:
            print(Y + f"  [*] Premium unlock script not found or disabled" + X)
        
        # Load native bypass script if enabled
        if hasattr(self, 'native_bypass_script') and os.path.exists(self.native_bypass_script):
            try:
                print(C + f"  [*] Loading native bypass script from: {self.native_bypass_script}" + X)
                native_src = open(self.native_bypass_script, "r", encoding="utf-8").read()
                native_script = session.create_script(native_src)
                native_script.on("message", self._on_message)
                native_script.load()
                print(G + "  [+] Native bypass script loaded successfully." + X)
            except Exception as e:
                print(Y + f"  [*] Failed to load native bypass script: {e}" + X)
                import traceback
                traceback.print_exc()
        else:
            print(Y + f"  [*] Native bypass script not found or disabled" + X)

        # Load cloud entitlement interceptor (اعتراض إشارة الاشتراك السحابية)
        if os.path.exists(self.entitlement_interceptor_script):
            try:
                print(C + f"  [*] Loading cloud entitlement interceptor: {self.entitlement_interceptor_script}" + X)
                ent_src = open(self.entitlement_interceptor_script, "r", encoding="utf-8").read()
                ent_script = session.create_script(ent_src)
                ent_script.on("message", self._on_message)
                ent_script.load()
                print(G + "  [+] Cloud entitlement interceptor loaded (OkHttp/HttpURLConnection/org.json)." + X)
            except Exception as e:
                print(Y + f"  [*] Failed to load entitlement interceptor: {e}" + X)
                import traceback
                traceback.print_exc()
        else:
            print(Y + f"  [*] Cloud entitlement interceptor not found" + X)

        device.resume(pid)
        print(G + B + "  [+] app launched + instrumentation loaded." + X)

        # Use new pipeline orchestrator if enabled
        if self.use_pipeline and self.pipeline_orchestrator:
            print(C + "  [pipeline] Running sequential orchestration...\n" + X)
            self._run_with_pipeline()
        else:
            # Original AI-guided exploration
            self._run_with_exploration()
        
        # Apply feedback loop if available
        if self.feedback_loop:
            try:
                self.feedback_loop.apply_feedback()
                analysis = self.feedback_loop.analyze_feedback()
                print(C + f"  [feedback] Applied {len(analysis.get('recommendations', []))} improvements" + X)
            except Exception as e:
                pass
        
        # Print working memory stats if available
        if self.working_memory:
            try:
                stats = self.working_memory.get_stats()
                print(C + f"  [memory] {stats['total_items']} items stored" + X)
            except Exception as e:
                pass
        
        if self._mem_classes:
            print(C + f"  [i] رصد الـ scavenger {len(self._mem_classes)} صنفاً محمّلاً "
                  f"في الذاكرة (معلومة استطلاعية, لا تُحتسب نتائج)." + X)
        if self._alloc_counts:
            _total_alloc = sum(self._alloc_counts.values())
            _brk = ", ".join(f"{k}={v}" for k, v in sorted(self._alloc_counts.items()))
            print(C + f"  [i] تخصيص/تحرير ذاكرة خام: {_total_alloc} استدعاء ({_brk}) "
                  f"— مجمّعة كعدّاد واحد, لا تُحتسب نتائج." + X)
            # نتيجة استطلاعية واحدة (منخفضة) تلخّص النشاط بدل عشرات الآلاف
            self.findings.append({
                "type": "native_alloc_summary",
                "title": "Native Memory Allocation (aggregated)",
                "severity": "low",
                "detail": f"total={_total_alloc}; {_brk}",
                "why": "ملخّص مجمّع لنشاط malloc/free/calloc/realloc الخام (ضجيج معتاد لأي تطبيق).",
                "data": self._alloc_counts,
                "evidence": [_brk],
                "phase": "dynamic",
                "raw": dict(self._alloc_counts),
            })
        # Teardown can block: the memory-scavenger may be mid-scan on the agent
        # thread, so unload()/detach() would wait for it. Force-stop the app to
        # release the agent, then tear down under a watchdog so reporting always runs.
        self._safe_teardown(device, script, session)
        return self._finish(device)
    
    def _run_with_pipeline(self):
        """Run using new pipeline orchestrator"""
        # Update pipeline context with current state
        self.pipeline_orchestrator.context = {
            "package": self.package,
            "device": self.device,
            "duration": self.duration,
            "goal": self.goal,
        }
        
        # Run pipeline
        results = self.pipeline_orchestrator.run()
        
        # Collect findings from pipeline
        for phase_name, result in results.items():
            if result.status == PhaseStatus.COMPLETED and "findings" in result.data:
                for finding in result.data["findings"]:
                    self.findings.append(finding)
        
        # Print summary
        summary = self.pipeline_orchestrator.get_summary()
        print(C + f"  [pipeline] Completed: {summary['completed']}/{summary['total_phases']} phases" + X)
    
    def _run_with_exploration(self):
        """Run using original AI-guided exploration"""
        # AI-guided exploration in parallel — قيادة تقارُبية (حتى النجاح/الركود)
        self._explorer_thread = None
        if self.use_ai and _HAS_EXPLORER:
            self.explorer = AIExplorer(self.adb, self.device, self.package, self.brain,
                                       goal=self.goal, duration=self.duration, on_step=self._on_step,
                                       store=self.store, until_goal=self.until_goal,
                                       max_steps=self.max_steps, stagnation_limit=self.stagnation_limit)
            self._explorer_thread = threading.Thread(target=self.explorer.run, daemon=True, name="ai-explorer")
            self._explorer_thread.start()
            mode = "حتى النجاح/التقارب (بلا سقف زمني)" if self.until_goal else f"{self.duration}s"
            print(C + f"  [ai] بدأ الاستكشاف بقيادة العقل — الوضع: {mode}.\n" + X)
        else:
            print(Y + "  [*] AI disabled — interact with the app manually now.\n" + X)

        try:
            if self._explorer_thread is not None:
                # ننتظر تقارب المستكشف (نجاح أو ركود أو سقف خطوات)؛ duration = شبكة أمان قصوى
                self._explorer_thread.join(timeout=self.duration)
            else:
                waited = 0
                while waited < self.duration:
                    time.sleep(2); waited += 2
        except KeyboardInterrupt:
            print(Y + "\n[*] stopped early." + X)
        if self.explorer:
            self.explorer.stop()

    def _safe_teardown(self, device, script, session, timeout=6):
        import subprocess as _sp
        try:
            _sp.run([self.adb] + (["-s", self.device] if self.device else []) +
                    ["shell", "am", "force-stop", self.package],
                    timeout=8, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        except Exception:
            pass

        def _t():
            try: script.unload()
            except Exception: pass
            try: session.detach()
            except Exception: pass
        th = threading.Thread(target=_t, daemon=True); th.start(); th.join(timeout)
        if th.is_alive():
            print(Y + "  [*] teardown watchdog: agent busy, proceeding to report." + X)

    # ── secret hunting (واسع وعميق قبل التقرير) ──────────────────────────────
    def _run_secret_hunt(self):
        """بحث شامل عن الأسرار بكل أنواعها في: أدلة النتائج + بيانات التطبيق على
        الجهاز (root) + logcat — ودمج المُكتشَف في النتائج (مع إزالة التكرار)."""
        try:
            from secret_hunter import SecretHunter
        except Exception as e:
            print(Y + f"  [*] secret_hunter غير متاح: {e}" + X)
            return
        hunter = SecretHunter(self.adb, self.device, self.package, verbose=True)
        try:
            hits = hunter.hunt(self.findings, store=self.store)
        except Exception as e:
            print(Y + f"  [*] secret-hunt خطأ: {e}" + X)
            return
        added = 0
        for h in hits:
            key = h["type"] + "|" + json.dumps(h["evidence"], ensure_ascii=False, sort_keys=True)[:200]
            if key in self._seen:
                continue
            self._seen.add(key)
            h.setdefault("raw", {})
            self.findings.append(h)
            added += 1
            if self.store is not None:
                try: self.store.add_finding(h)
                except Exception: pass
        if added:
            print(G + f"  [+] صيد الأسرار أضاف {added} سرّاً/مفتاحاً جديداً إلى النتائج." + X)

    def _run_crypto_solve(self):
        """يفكّ الأسرار المشفّرة: يأخذ المفاتيح والنصوص المشفّرة الملتقطة وقت التشغيل
        ويحاول فكّها → يكشف الأسرار حتى لو خزّنها التطبيق مشفّرة."""
        try:
            from crypto_solver import CryptoSolver
        except Exception:
            return
        try:
            decrypted = CryptoSolver(verbose=True).solve(self.findings)
        except Exception as e:
            print(Y + f"  [*] crypto-solver خطأ: {e}" + X)
            return
        added = 0
        for d in decrypted:
            key = d["type"] + "|" + json.dumps(d["evidence"], ensure_ascii=False, sort_keys=True)[:200]
            if key in self._seen:
                continue
            self._seen.add(key)
            d.setdefault("raw", {})
            self.findings.append(d)
            added += 1
            if self.store is not None:
                try: self.store.add_finding(d)
                except Exception: pass
        if added:
            print(G + f"  [+] فكّاك التشفير كشف {added} سرّاً مشفّراً." + X)

    def _run_cloud_raid(self):
        """يأخذ الأسرار المُستخرَجة ويستغلّها فعلياً للوصول لبيانات السحابة (الهدف
        النهائي). يعمل بعد الالتقاط مباشرةً — فالعقل يتابع الاستغلال لا يكتفي بالجمع."""
        try:
            from cloud_raider import CloudRaider
        except Exception:
            return
        try:
            raider = CloudRaider(store=self.store, verbose=True, aggressive=True, package=self.package)
            reached = raider.raid(self.findings)
        except Exception as e:
            print(Y + f"  [*] cloud-raider خطأ: {e}" + X)
            return
        added = 0
        for h in reached:
            key = h["type"] + "|" + json.dumps(h["evidence"], ensure_ascii=False, sort_keys=True)[:200]
            if key in self._seen:
                continue
            self._seen.add(key)
            h.setdefault("raw", {})
            self.findings.append(h)
            added += 1
        if added:
            print(G + B + f"  [+] الاستغلال السحابي وصل إلى {added} هدف/بيانات." + X)

    # ── premium unlock verification ─────────────────────────────────────────
    def _verify_premium_unlock(self):
        """يؤكّد فتح المميّز من **أحداث اعتراض حقيقية** فقط.

        الدليل: كل نتيجة من نوع `premium_entitlement_intercepted` تعني أن التطبيق
        طلب نقطة نهاية اشتراك/مصادقة فعلاً، واعترضنا استجابتها الحقيقية وأعدنا
        كتابتها إلى «مسموح» (مع «قبل/بعد»). لا نُعلن الفتح دون هذا الدليل."""
        hits = [f for f in self.findings
                if f.get("type") == "premium_entitlement_intercepted"]
        layers, evidence = set(), []
        for f in hits:
            raw = f.get("raw", {}) or {}
            if raw.get("layer"):
                layers.add(raw["layer"])
            evidence.append({
                "layer": raw.get("layer"),
                "url": raw.get("url"),
                "changes": raw.get("changes"),
                "detail": f.get("detail"),
            })
        return {
            "verified": bool(hits),
            "intercepted_signals": len(hits),
            "layers": sorted(layers),
            "evidence": evidence[:25],
            "method": "real interception of app↔cloud entitlement responses",
        }

    # ── reporting ──────────────────────────────────────────────────────────
    def _finish(self, device):
        self._run_secret_hunt()
        self._run_crypto_solve()   # فكّ الأسرار المشفّرة بالمفاتيح الملتقطة
        self._run_cloud_raid()     # استغلال الأسرار للوصول لبيانات السحابة
        
        # Cloud exposure analysis with ExtendedBrain
        cloud_analysis = None
        if hasattr(self.brain, 'analyze_cloud_exposure'):
            try:
                # Extract secrets from findings
                secrets = []
                for f in self.findings:
                    if f.get("type") in ["secret", "key", "token", "credential"]:
                        secrets.append(f)
                cloud_analysis = self.brain.analyze_cloud_exposure(secrets)
                print(G + f"  [+] Cloud exposure analysis: {cloud_analysis['risk_level']} risk level" + X)
            except Exception as e:
                print(Y + f"  [*] Cloud analysis error: {e}" + X)
        
        # تأكيد فتح المميّز من أحداث الاعتراض الحقيقية فقط (لا ادّعاء)
        premium_unlock = self._verify_premium_unlock()
        if premium_unlock["verified"]:
            print(G + B + f"  [✓] premium unlock مُؤكَّد: اعتُرضت "
                  f"{premium_unlock['intercepted_signals']} إشارة اشتراك حقيقية "
                  f"عبر {', '.join(premium_unlock['layers']) or '?'}." + X)
        else:
            print(Y + "  [*] لم تُعترَض أي إشارة اشتراك سحابية بعد — لم يُؤكَّد فتح المميّز." + X)

        if not self.report:
            # campaign mode: the campaign orchestrator triages + writes the unified
            # report over the whole blackboard, so just hand back the raw findings.
            print(C + f"\n[*] dynamic phase captured {len(self.findings)} raw findings "
                  f"(campaign will triage + report)." + X)
            result = {"package": self.package, "findings": self.findings,
                    "visited": self.explorer.visited if self.explorer else [],
                    "explore_steps": self.explorer.steps if self.explorer else 0,
                    "premium_unlock": premium_unlock}
            if cloud_analysis:
                result["cloud_analysis"] = cloud_analysis
            return result
        print(C + B + f"\n[*] captured {len(self.findings)} raw findings. Triaging via brain…" + X)
        triaged = self.brain.triage(self.findings)
        session = {
            "package": self.package,
            "device": getattr(device, "id", self.device),
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "duration_s": self.duration,
            "brain": ("deepseek:" + str(getattr(self.brain, 'model', '?'))) if self._brain_online() else "offline",
            "visited": self.explorer.visited if self.explorer else [],
            "explore_steps": self.explorer.steps if self.explorer else 0,
            "raw_count": len(self.findings),
            "findings": self.findings,
            "triaged": triaged,
            "premium_unlock": premium_unlock,
        }
        if cloud_analysis:
            session["cloud_analysis"] = cloud_analysis
        summary = self.brain.summarize(session)
        session["summary"] = summary

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(LOOT, f"deep_{self.package}_{ts}")
        json_path = base + ".json"
        md_path = base + ".md"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(session, f, ensure_ascii=False, indent=2)
        self._write_markdown(md_path, session, summary, triaged)

        sev_counts = {}
        for t in triaged:
            s = str(t.get("severity", "info")).lower(); sev_counts[s] = sev_counts.get(s, 0) + 1
        print(G + B + f"\n[✓] done — {len(triaged)} triaged findings "
              f"(critical={sev_counts.get('critical',0)} high={sev_counts.get('high',0)} "
              f"medium={sev_counts.get('medium',0)})." + X)
        print(Y + f"    report : {md_path}" + X)
        print(Y + f"    json   : {json_path}" + X)
        print(C + "\n── ملخّص ──\n" + X + summary + "\n")
        return session

    def _write_markdown(self, path, session, summary, triaged):
        L = []
        L.append(f"# HAYO Cipher-7 — تقرير التحليل الديناميكي")
        L.append("")
        L.append(f"- **التطبيق:** `{session['package']}`")
        L.append(f"- **الجهاز:** {session['device']}")
        L.append(f"- **التاريخ:** {session['timestamp']}")
        L.append(f"- **العقل:** {session['brain']}")
        L.append(f"- **شاشات زُرِت:** {len(session['visited'])} — خطوات الاستكشاف: {session['explore_steps']}")
        L.append(f"- **نتائج خام:** {session['raw_count']} — بعد الفرز: {len(triaged)}")
        L.append("")
        
        # Cloud exposure analysis
        if "cloud_analysis" in session:
            ca = session["cloud_analysis"]
            L.append("## تحليل التعرض السحابي")
            L.append("")
            L.append(f"- **مستوى الخطر:** `{ca['risk_level'].upper()}`")
            L.append(f"- **إجمالي الأسرار السحابية:** {ca['total_secrets']}")
            L.append("")
            if ca["cloud_services"]:
                L.append("### الخدمات السحابية المكتشفة")
                L.append("")
                for service, data in ca["cloud_services"].items():
                    L.append(f"#### {service.upper()}")
                    L.append(f"- **العدد:** {data['count']}")
                    for secret in data["secrets"]:
                        L.append(f"  - `{secret['type']}`: {secret['value']} ({secret['severity']})")
                L.append("")
        
        # Premium unlock verification (اعتراض إشارة الاشتراك السحابية)
        pu = session.get("premium_unlock")
        if pu:
            L.append("## تأكيد فتح المميّز (اعتراض الإشارة السحابية)")
            L.append("")
            if pu["verified"]:
                L.append(f"- **الحالة:** ✅ مُؤكَّد — اعتُرضت **{pu['intercepted_signals']}** "
                         f"إشارة اشتراك حقيقية وأُعيدت كـ«مسموح».")
                L.append(f"- **الطبقات:** {', '.join(pu['layers']) or '—'}")
                L.append(f"- **الطريقة:** {pu['method']}")
                L.append("")
                L.append("### أدلة الاعتراض (قبل/بعد)")
                L.append("")
                for e in pu["evidence"]:
                    L.append(f"- `[{e.get('layer','?')}]` {e.get('url') or ''} — "
                             f"{', '.join(e.get('changes') or [])}")
            else:
                L.append("- **الحالة:** ❌ غير مُؤكَّد — لم تُعترَض أي إشارة اشتراك سحابية "
                         "خلال الجلسة (قد لا يستعلم التطبيق عن الاشتراك عبر الشبكة، أو لم "
                         "يُبلَغ المسار المُختبَر).")
            L.append("")

        L.append("## الملخّص التنفيذي")
        L.append("")
        L.append(summary)
        L.append("")
        L.append("## النتائج (مرتّبة حسب الخطورة)")
        L.append("")
        for i, t in enumerate(triaged, 1):
            fp = " *(محتمل إيجابية كاذبة)*" if t.get("false_positive") else ""
            L.append(f"### {i}. [{str(t.get('severity','info')).upper()}] {t.get('title','')}{fp}")
            if t.get("why"):
                L.append(f"- **الوصف:** {t['why']}")
            if t.get("exploitation"):
                L.append(f"- **الاستغلال:** {t['exploitation']}")
            if t.get("type"):
                L.append(f"- **النوع:** `{t['type']}`")
            L.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(L))

    # ── optional platform merge ────────────────────────────────────────────
    def post(self, server, token):
        if requests is None:
            print(Y + "[*] requests missing — skip platform post." + X); return
        url = server.rstrip("/") + "/api/pentest/dynamic/" + token
        try:
            r = requests.post(url, json={"package": self.package, "agentVersion": "engine-1.0",
                                         "findings": self.findings}, timeout=30)
            print((G if r.status_code == 200 else R) + f"[*] platform post: HTTP {r.status_code}" + X)
        except Exception as e:
            print(R + f"[!] platform post failed: {e}" + X)


def main():
    _utf8()
    ap = argparse.ArgumentParser(description="HAYO unified dynamic engine (Frida + AI brain)")
    ap.add_argument("--package", required=True)
    ap.add_argument("--device", default=os.environ.get("HAYO_DEV", "emulator-5554"))
    ap.add_argument("--adb", default=os.environ.get("HAYO_ADB", "C:/Users/PT/Downloads/platform-tools/adb.exe"))
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--no-ai", action="store_true", help="disable AI exploration (manual interaction)")
    # الهدف/التعليمات التنفيذية: يقرأها العقل المدبّر وينفّذها بدقة. تُمرَّر صراحةً
    # عبر --goal، أو من متغيّر البيئة HAYO_GOAL (يضبطه حقل التعليمات في اللوحة) فيصل
    # الأمر حتى عبر مسارات .bat التي لا تمرّر --goal.
    ap.add_argument("--goal",
                    default=(os.environ.get("HAYO_GOAL", "").strip()
                             or "reach login, premium/subscription and cloud-sync screens"))
    ap.add_argument("--server", help="optional HAYO platform URL to merge findings")
    ap.add_argument("--token", help="dyn_ token for the platform merge")
    ap.add_argument("--use-pipeline", action="store_true", help="use new sequential pipeline orchestrator")
    args = ap.parse_args()

    eng = DynamicEngine(args.package, args.device, args.adb, args.duration,
                        use_ai=not args.no_ai, goal=args.goal, use_pipeline=args.use_pipeline)
    eng.run()
    if args.server and args.token:
        eng.post(args.server, args.token)


if __name__ == "__main__":
    main()
