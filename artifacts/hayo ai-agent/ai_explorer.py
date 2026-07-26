#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — AI-Guided UI Explorer (ai_explorer.py)
======================================================
A brain-driven replacement for random monkey fuzzing. Each step it:
  1) OBSERVES the current screen (uiautomator dump -> parsed clickable/edit/scroll
     elements + current activity),
  2) asks the LLMBrain for the single best next ACTION toward a security goal
     (login / premium / cloud / settings),
  3) EXECUTES it via adb (tap / input / swipe / back / launch),
  4) records visited screens so it explores broadly instead of looping.

Runs in its own thread from the DynamicEngine while Frida captures what each action
triggers. Degrades gracefully to deterministic heuristics when no LLM key is set.
"""
import re
import subprocess
import time
import xml.etree.ElementTree as ET


def _sh(adb, device, *args, timeout=20, capture=False, combine=True):
    cmd = [adb] + (["-s", device] if device else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="ignore")
        if capture:
            return (r.stdout or "") + ((r.stderr or "") if combine else "")
        return r.returncode
    except subprocess.TimeoutExpired:
        return "(TIMEOUT)" if capture else 124
    except Exception:
        return "" if capture else 1


def _center(bounds):
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2


class AIExplorer:
    def __init__(self, adb, device, package, brain, goal="reach login, premium and cloud screens",
                 duration=180, on_step=None, store=None,
                 max_steps=160, stagnation_limit=20, until_goal=True):
        self.adb = adb; self.device = device; self.package = package
        self.brain = brain; self.goal = goal
        # duration = شبكة أمان قصوى فقط (وليس المتحكّم الأساسي). التحكّم الأساسي
        # تقارُبي: يستمر حتى بلوغ الهدف أو ركود التقدّم أو بلوغ سقف الخطوات.
        self.duration = duration
        self.max_steps = max_steps           # سقف خطوات (ليس زمناً) يمنع اللانهاية
        self.stagnation_limit = stagnation_limit  # خطوات بلا شاشة/نتيجة جديدة → تقارب
        self.until_goal = until_goal
        self.store = store           # optional shared blackboard
        self.on_step = on_step or (lambda *a, **k: None)
        self.visited = []            # ordered unique screen fingerprints
        self.visited_texts = set()   # labels already tapped
        self.steps = 0
        self._stop = False
        self._ui_ok = False
        self.findings_summary = "(none yet)"
        # يُحدّثهما المحرك الديناميكي آنياً من الرسائل الحيّة:
        self.finding_count = 0       # عدد النتائج الملتقطة حتى الآن
        self.goal_reached = False    # يُرفع عند التقاط نتيجة حرجة (نجاح)
        self._no_progress = 0        # عدّاد الركود (يُصفَّر عند أي تقدّم)

    def stop(self):
        self._stop = True

    # ── observation ────────────────────────────────────────────────────────
    def _dump_xml(self):
        # uiautomator can transiently return "null root node" (splash / WebView /
        # secure surface), especially on LDPlayer. Retry with backoff.
        # NOTE: --compressed is REMOVED — it hangs for 20+ seconds on some Android
        # versions and provides no benefit for our parser.
        for attempt in range(8):
            cmd = ["uiautomator", "dump", "/sdcard/hayo_ui.xml"]
            out = _sh(self.adb, self.device, "shell", *cmd, capture=True, timeout=20)
            if "dumped" in out.lower() or "hierarchy" in out.lower():
                xml = _sh(self.adb, self.device, "shell", "cat", "/sdcard/hayo_ui.xml",
                          capture=True, timeout=15)
                if xml.strip().startswith("<"):
                    self._ui_ok = True
                    return xml
            # If we see "null root node", the accessibility service is busy —
            # kill and restart uiautomator to unstick it.
            if "null root" in out.lower() or "error" in out.lower():
                _sh(self.adb, self.device, "shell", "uiautomator", "force-stop",  # best-effort
                    capture=False, timeout=5)
            # Exponential backoff: 0.5, 1, 2, 4, 6, 8, 10, 12
            delay = min(12, 0.5 * (2 ** attempt))
            time.sleep(delay)
        return ""

    def _blind_probe(self):
        """Fallback when the accessibility tree is unreadable: drive the app with
        coarse taps/swipes so instrumentation still sees triggered code paths."""
        w, h = 1080, 1920
        spots = [(w // 2, int(h * 0.5)), (w // 2, int(h * 0.85)), (int(w * 0.85), int(h * 0.9)),
                 (w // 2, int(h * 0.35)), (int(w * 0.15), int(h * 0.08))]
        x, y = spots[self.steps % len(spots)]
        self._tap((x, y)); time.sleep(0.4)
        if self.steps % 3 == 0:
            self._swipe()

    def _force_launch_app(self, max_retries=3):
        """Force-start the target app's main activity, retrying until it's the
        foreground activity. This ensures we're inside the app, not on the launcher."""
        for attempt in range(max_retries):
            # Launch main activity
            _sh(self.adb, self.device, "shell", "am", "start",
                "-n", self.package + "/.MainActivity", timeout=12)
            time.sleep(2.0)
            # Also try com.google.android.apps.claude.MainActivity (Claude-specific)
            _sh(self.adb, self.device, "shell", "am", "start",
                "-n", self.package + "/com.google.android.apps.claude.MainActivity", timeout=12)
            time.sleep(1.5)
            _sh(self.adb, self.device, "shell", "am", "start",
                "-n", self.package + "/com.anthropic.claude.MainActivity", timeout=12)
            time.sleep(1.5)
            current = self._current_activity()
            if self.package in current:
                return True
            # If it's on the launcher, try the standard intent
            _sh(self.adb, self.device, "shell", "monkey", "-p", self.package, "-c",
                "android.intent.category.LAUNCHER", "1", timeout=12)
            time.sleep(2.0)
            current = self._current_activity()
            if self.package in current:
                return True
        return False

    def _current_activity(self):
        out = _sh(self.adb, self.device, "shell", "dumpsys", "activity", "activities",
                  capture=True, timeout=12)
        for line in out.splitlines():
            if "mResumedActivity" in line or "topResumedActivity" in line:
                m = re.search(r"([A-Za-z][\w.]+/[\w.$]+)", line)
                if m:
                    return m.group(1)
        return "?"

    def _parse(self, xml):
        elements, scrollable = [], False
        try:
            root = ET.fromstring(xml)
        except Exception:
            return elements, scrollable
        # Pre-scan: build a lookup of child text/desc for each parent node
        child_texts = {}
        for node in root.iter("node"):
            texts = []
            for child in node:
                t = (child.get("text") or "").strip()
                d = (child.get("content-desc") or "").strip()
                if t: texts.append(t)
                if d: texts.append(d)
            if texts:
                child_texts[id(node)] = " | ".join(texts)
        i = 0
        for node in root.iter("node"):
            a = node.attrib
            txt = (a.get("text") or "").strip()
            desc = (a.get("content-desc") or "").strip()
            cls = a.get("class", "")
            bounds = a.get("bounds", "")
            c = _center(bounds)
            if a.get("scrollable") == "true":
                scrollable = True
            kind = None
            if a.get("clickable") == "true" or "Button" in cls:
                kind = "clickable"
            if "EditText" in cls or (a.get("focusable") == "true" and "Edit" in cls):
                kind = "edit"
            if "EditText" in cls:
                kind = "edit"
            # If clickable but no text/desc, inherit from first child that has text
            if kind and not txt and not desc:
                ct = child_texts.get(id(node), "")
                if ct:
                    txt = ct[:60]
            if kind and c and (txt or desc or kind == "edit"):
                elements.append({"i": i, "kind": kind, "text": txt[:60], "desc": desc[:60],
                                 "_xy": c, "_pw": a.get("password") == "true"})
                i += 1
        return elements[:40], scrollable

    def _screen_fp(self, activity, elements):
        labels = "|".join(sorted((e["text"] or e["desc"]) for e in elements if (e["text"] or e["desc"])))[:400]
        return activity + "#" + str(abs(hash(labels)) % 10_000_000)

    # ── actions ────────────────────────────────────────────────────────────
    def _tap(self, xy):
        _sh(self.adb, self.device, "shell", "input", "tap", str(xy[0]), str(xy[1]))

    def _input(self, xy, text):
        self._tap(xy); time.sleep(0.3)
        safe = text.replace(" ", "%s").replace("'", "").replace('"', "")
        _sh(self.adb, self.device, "shell", "input", "text", safe)
        _sh(self.adb, self.device, "shell", "input", "keyevent", "66")  # ENTER

    def _swipe(self):
        _sh(self.adb, self.device, "shell", "input", "swipe", "540", "1400", "540", "500", "300")

    def _back(self):
        _sh(self.adb, self.device, "shell", "input", "keyevent", "4")

    def _sh_key(self, keycode):
        _sh(self.adb, self.device, "shell", "input", "keyevent", str(keycode))

    # ── vision (للواجهات الحديثة التي يعطي فيها uiautomator 0 عناصر) ──────────
    def _screenshot_b64(self):
        """لقطة شاشة PNG → base64 (لتحليلها بصرياً بواسطة gpt-4o)."""
        import base64
        cmd = [self.adb] + (["-s", self.device] if self.device else []) + ["exec-out", "screencap", "-p"]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=15)
            if r.returncode == 0 and r.stdout and len(r.stdout) > 1000:
                return base64.b64encode(r.stdout).decode("ascii")
        except Exception:
            pass
        return None

    def _screen_size(self):
        out = _sh(self.adb, self.device, "shell", "wm", "size", capture=True) or ""
        m = re.search(r"(\d+)x(\d+)", out)
        return (int(m.group(1)), int(m.group(2))) if m else (1080, 1920)

    def _exec_vision(self, va):
        """تنفيذ قرار الرؤية (إحداثيات بكسل من لقطة الشاشة)."""
        act = va.get("action")
        x, y = va.get("x"), va.get("y")
        xy = (int(x), int(y)) if isinstance(x, (int, float)) and isinstance(y, (int, float)) else None
        if act == "tap" and xy:
            self._tap(xy)
        elif act == "input" and xy:
            self._input(xy, va.get("text") or "hayo.test@example.com")
        elif act == "key":
            try: self._sh_key(int(va.get("keycode", 4)))
            except Exception: self._back()
        elif act == "back":
            self._back()

    def _launch(self, activity):
        if activity and "/" in activity:
            _sh(self.adb, self.device, "shell", "am", "start", "-n", activity, timeout=12)

    # ── main loop ──────────────────────────────────────────────────────────
    def _launch_known_activities(self):
        """Try to directly launch known security-relevant activities from static intel.
        This bypasses navigation and jumps straight to login/settings/premium screens."""
        if self.store is None:
            return False
        try:
            activities = self.store.values("klass") + self.store.values("ui_screen")
            # Also get specific activities from intel
            ctx = self.store.brain_context(50)
            intel_activities = ctx.get("activities", [])
            all_activities = list(set(activities + intel_activities))
        except Exception:
            return False

        launched = 0
        priority_patterns = [
            ".login.", ".signin.", ".auth.", ".account.",
            ".settings.", ".preference.",
            ".subscription.", ".premium.", ".upgrade.",
            ".profile.", ".user.",
            ".splash.", ".main.", ".home.",
        ]
        # Prioritize login/auth activities
        for act in sorted(all_activities, key=lambda x: 
                0 if any(p in x.lower() for p in [".login",".signin",".auth",".account"])
                else 1 if any(p in x.lower() for p in [".settings",".profile",".user"])
                else 2):
            if self._stop:
                break
            if launched >= 8:
                break
            if "/" not in act and "." in act:
                act = self.package + "/" + act
            if "/" in act:
                self.on_step("action", {"action": "launch", "activity": act,
                                        "reason": "direct-launch from static intel"})
                self._launch(act)
                time.sleep(1.5)
                launched += 1
        return launched > 0

    def _launch_app_main(self):
        """Directly launch the app via monkey (most reliable way for any Android app)."""
        _sh(self.adb, self.device, "shell", "monkey", "-p", self.package, "-c",
            "android.intent.category.LAUNCHER", "1", timeout=12)
        time.sleep(2.0)

    def run(self):
        t0 = time.time()
        idle = 0
        blind = 0
        self._sw, self._sh = self._screen_size()   # لسياق إحداثيات الرؤية
        # Phase 1: Force-launch the target app (ensures we're in the app, not launcher)
        self.on_step("action", {"action": "phase1", "reason": "force-launching target app"})
        in_app = self._force_launch_app()
        if in_app:
            self.on_step("screen", {"activity": self._current_activity(), "elements": 0})
        
        # Phase 2: Try direct activity launches from static analysis intel
        self._launch_known_activities()
        time.sleep(1.0)
        
        # Phase 3: Pre-loop — wait until UI elements appear or we timeout
        wait_start = time.time()
        while not self._stop and (time.time() - wait_start) < 20:
            xml = self._dump_xml()
            elements, scrollable = self._parse(xml)
            if elements:
                break
            time.sleep(1.5)
        
        # حلقة تقارُبية: تستمر حتى النجاح (goal_reached) أو الركود (stagnation) أو
        # سقف الخطوات؛ duration مجرّد شبكة أمان قصوى. لا تحكّم زمني أساسي.
        while not self._stop and self.steps < self.max_steps and (time.time() - t0) < self.duration:
            # نجاح: التُقطت نتيجة حرجة → أنجزنا الهدف
            if self.until_goal and self.goal_reached:
                self.on_step("action", {"action": "stop",
                             "reason": "🎯 بلوغ الهدف — التُقطت نتيجة حرجة"})
                break
            # ركود: لا شاشات ولا نتائج جديدة منذ stagnation_limit خطوة → تقارب
            if self._no_progress >= self.stagnation_limit:
                self.on_step("action", {"action": "stop",
                             "reason": f"تقارب — لا تقدّم منذ {self.stagnation_limit} خطوة"})
                break

            screens_before = len(self.visited)
            finds_before = self.finding_count

            # حارس المقدّمة: إن غادرنا التطبيق (سطح مكتب المحاكي أو تطبيق آخر) أعِده
            # للمقدّمة ولا تنقر خارجه أبداً (كان يختبر السطح الخطأ وينقر أيقونات السطح)
            activity = self._current_activity()
            if activity not in ("?", "") and self.package not in activity:
                self.on_step("action", {"action": "relaunch",
                             "reason": f"غادرنا التطبيق ({activity[:40]}) — إعادته للمقدّمة"})
                self._launch_app_main()
                self._force_launch_app(max_retries=1)
                self._no_progress += 1
                time.sleep(1.0)
                continue

            xml = self._dump_xml()
            elements, scrollable = self._parse(xml)
            fp = self._screen_fp(activity, elements)
            if fp not in self.visited:
                self.visited.append(fp)
                if self.store is not None:
                    try: self.store.add("ui_screen", activity, source="explorer")
                    except Exception: pass
                self.on_step("screen", {"activity": activity, "elements": len(elements)})

            if not elements and not scrollable:
                # الواجهة غير مقروءة عبر uiautomator (WebView/Compose/لعبة/إعلان).
                # الحل للتطبيقات الحديثة: رؤية بصرية — لقطة شاشة يحلّلها gpt-4o ويُرجع
                # إحداثيات النقر. نستعملها كل تكرار ثانٍ (لضبط الكلفة)، وإلا blind-probe.
                blind += 1
                used_vision = False
                if self.use_ai and (blind % 2 == 1) and hasattr(self.brain, "decide_action_vision"):
                    shot = self._screenshot_b64()
                    if shot:
                        vobs = {"goal": self.goal, "stuck": self._no_progress,
                                "visited": self.visited, "screen_w": self._sw, "screen_h": self._sh}
                        if self.store is not None:
                            try: vobs["intel"] = self.store.brain_context(10)
                            except Exception: pass
                        va = self.brain.decide_action_vision(shot, vobs)
                        if isinstance(va, dict) and va.get("action"):
                            self.on_step("action", {"action": "vision·" + str(va.get("action")),
                                         "reason": (va.get("reason") or "")[:70]})
                            self._exec_vision(va)
                            used_vision = True
                if not used_vision:
                    if blind == 1:
                        self.on_step("action", {"action": "blind", "reason": "UI tree unreadable — coarse taps/swipes"})
                    self._blind_probe()
                self.steps += 1
                # تقدّم إذا التقط الـ blind-probe نتيجة جديدة
                if self.finding_count > finds_before or len(self.visited) > screens_before:
                    self._no_progress = 0
                else:
                    self._no_progress += 1
                time.sleep(0.8); continue
            blind = 0

            obs = {
                "goal": self.goal,
                "current_activity": activity,
                "visited": self.visited[-12:],
                "visited_texts": list(self.visited_texts)[-40:],
                "scrollable": scrollable,
                "elements": [{"i": e["i"], "kind": e["kind"], "text": e["text"], "desc": e["desc"]}
                             for e in elements],
                "findings_summary": self.findings_summary,
                "stuck": self._no_progress,   # يُعلم العقل بمستوى التعطّل لتفعيل الحِيَل
            }
            if self.store is not None:
                # feed the shared blackboard so the agent navigates toward
                # statically-discovered targets (login/cloud/premium).
                try: obs["intel"] = self.store.brain_context(10)
                except Exception: pass
            action = self.brain.decide_action(obs)
            self.steps += 1
            self.on_step("action", action)

            act = action.get("action")
            if act == "stop":
                break
            elif act == "tap":
                idx = action.get("index")
                if isinstance(idx, int) and 0 <= idx < len(elements):
                    e = elements[idx]
                    lab = (e["text"] or e["desc"]).lower().strip()
                    if lab:
                        self.visited_texts.add(lab)
                    self._tap(e["_xy"])
                elif elements:
                    self._tap(elements[0]["_xy"])   # فهرس غير صالح → انقر أول عنصر
            elif act == "key":
                try:
                    self._sh_key(int(action.get("keycode", 4)))   # حيلة: keyevent (4=BACK,66=ENTER)
                except Exception:
                    self._back()
            elif act == "input":
                idx = action.get("index")
                e = elements[idx] if isinstance(idx, int) and 0 <= idx < len(elements) else \
                    next((x for x in elements if x["kind"] == "edit"), None)
                if e:
                    self._input(e["_xy"], action.get("text") or "hayo.test@example.com")
            elif act == "launch":
                self._launch(action.get("activity"))
            elif act == "swipe":
                self._swipe()
            else:  # back / wait
                self._back() if act == "back" else time.sleep(1.0)
            time.sleep(1.2)
            # تتبّع التقدّم (بعد إمهال وصول نتائج هذا الفعل من خيط Frida)
            if len(self.visited) > screens_before or self.finding_count > finds_before:
                self._no_progress = 0
            else:
                self._no_progress += 1
        reason = ("goal" if self.goal_reached else
                  "converged" if self._no_progress >= self.stagnation_limit else
                  "max_steps" if self.steps >= self.max_steps else "stopped")
        self.on_step("done", {"steps": self.steps, "screens": len(self.visited), "reason": reason})
        return self.visited, self.steps
