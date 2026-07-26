#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — AutoPwn (core/auto_pwn.py)
============================================
محرك الاختراق التلقائي الكامل غير المقيد بقيادة DeepSeek.
يعمل بدون حدود زمنية، بدون قيود أخلاقية، تنفيذ كامل.

Usage:
    python core/auto_pwn.py --package com.target.app
    python core/auto_pwn.py --package com.target.app --aggressive
    python core/auto_pwn.py --package com.target.app --unlimited
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime

# ── المسارات ───────────────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "core"))

# ── الألوان ────────────────────────────────────────────────────────────────
E = chr(27)
G = E + "[92m"; R = E + "[91m"; Y = E + "[93m"; C = E + "[96m"; M = E + "[95m"
B = E + "[1m"; X = E + "[0m"

# ── الاستيرادات ────────────────────────────────────────────────────────────
try:
    from core.deepseek_brain import DeepSeekBrain
    from core.exploit_engine import ExploitEngine
    _HAVE_CORE = True
except ImportError as e:
    _HAVE_CORE = False
    _CORE_ERROR = str(e)


class AutoPwn:
    """
    AutoPwn — محرك اختراق تلقائي كامل غير مقيد
    يعمل بقيادة DeepSeik كعقل مدبر
    """

    def __init__(self, package, adb_path="adb", device=None, aggressive=False, unlimited=True):
        self.package = package
        self.adb = adb_path
        self.device = device
        self.aggressive = aggressive
        self.unlimited = unlimited

        # تهيئة المكونات
        self.brain = DeepSeekBrain() if _HAVE_CORE else None
        self.engine = ExploitEngine(
            deepseek_brain=self.brain,
            adb_path=adb_path,
            device=device,
            package=package
        ) if _HAVE_CORE else None

        # حالة التشغيل
        self.running = True
        self.round = 0
        self.max_rounds = 0 if unlimited else 100
        self.start_time = time.time()
        self.stats = {
            "rounds": 0,
            "actions_taken": 0,
            "exploits_run": 0,
            "secrets_found": 0,
            "screens_visited": set(),
            "premium_unlocked": False,
            "cloud_breached": False,
            "tokens_captured": 0,
        }

        # مخزن المعلومات المحلي
        self.intel = {
            "secrets": [],
            "endpoints": [],
            "credentials": [],
            "screens": [],
            "findings": [],
        }

    def print_banner(self):
        """طباعة الشعار"""
        print(f"""{R}{B}
  ╔═══════════════════════════════════════════════╗
  ║  {C}HAYO Cipher-7 — AutoPwn{R}                  ║
  ║  {Y}محرك اختراق تلقائي غير مقيد{R}               ║
  ║  {M}بقيادة DeepSeek AI{R}                        ║
  ╚═══════════════════════════════════════════════╝{X}
""")
        print(f"  {G}[*] الهدف: {self.package}{X}")
        print(f"  {G}[*] الوضع: {'غير مقيد' if self.unlimited else 'مقيد'}{X}")
        print(f"  {G}[*] العدوانية: {'قصوى' if self.aggressive else 'قياسية'}{X}")
        print(f"  {G}[*] العقل المدبر: {'DeepSeek نشط' if self.brain and self.brain.api_key else 'وضع الطوارئ'}{X}")
        print()

    def run(self):
        """حلقة التشغيل الرئيسية — تعمل بدون توقف"""
        self.print_banner()

        if not _HAVE_CORE:
            print(f"  {R}[!] خطأ في تحميل المكونات الأساسية: {_CORE_ERROR}{X}")
            print(f"  {Y}[*] تأكد من تشغيلك من المجلد الصحيح: python core/auto_pwn.py{X}")
            return

        print(f"  {C}{B}[*] بدء الاختراق التلقائي...{X}")
        print(f"  {Y}[*] اضغط Ctrl+C للإيقاف{X}")
        print()

        try:
            while self.running:
                self.round += 1

                # التحقق من الحد الأقصى
                if self.max_rounds > 0 and self.round > self.max_rounds:
                    print(f"  {Y}[!] تم الوصول للحد الأقصى من الجولات ({self.max_rounds}){X}")
                    break

                # جولة الاختراق
                self._run_pwn_round()

                # انتظار قصير بين الجولات
                time.sleep(1.0)

        except KeyboardInterrupt:
            print(f"\n  {Y}[!] تم الإيقاف بواسطة المستخدم{X}")
        finally:
            self._print_summary()

    def _run_pwn_round(self):
        """جولة اختراق واحدة"""
        print(f"{C}{B}─── الجولة #{self.round} ───{X}")

        # 1. تحليل الوضع الحالي
        state = self._capture_state()

        # 2. DeepSeek يقرر الإجراء التالي
        decision = self.brain.decide_action(state) if self.brain else {"action": "tap", "reasoning": "وضع الطوارئ"}

        print(f"  {M}[DeepSeek]{X} {decision.get('reasoning', 'تنفيذ...')}")

        # 3. تنفيذ القرار
        result = self._execute_decision(decision)

        # 4. تحليل النتيجة
        if result.get("success"):
            self.stats["actions_taken"] += 1
            if "secret" in str(result):
                self.stats["secrets_found"] += 1
            if "premium" in str(result):
                self.stats["premium_unlocked"] = True
            if "cloud" in str(result):
                self.stats["cloud_breached"] = True
            if "token" in str(result):
                self.stats["tokens_captured"] += 1

        # 5. إذا كان الوضع عدواني — نفذ استغلالاً إضافياً
        if self.aggressive and self.round % 3 == 0:
            self._run_aggressive_exploit()

        # تحديث الإحصائيات
        self.stats["rounds"] = self.round

    def _capture_state(self):
        """التقاط الحالة الحالية للتطبيق"""
        state = {
            "goal": f"اختراق تطبيق {self.package} بالكامل",
            "current_activity": self._get_current_activity(),
            "elements": self._get_ui_elements(),
            "visited": list(self.stats["screens_visited"])[-20:],
            "scrollable": False,
            "secrets_found": self.intel["secrets"][-10:],
            "findings_summary": self._get_findings_summary(),
            "intel": {
                "known_secrets": [{"masked": s[:20] + "..." if len(s) > 20 else s} for s in self.intel["secrets"][-5:]],
                "backend_urls": self.intel["endpoints"][-5:],
                "visited_screens": list(self.stats["screens_visited"])[-10:],
            }
        }
        return state

    def _get_current_activity(self):
        """الحصول على النشاط الحالي للتطبيق"""
        try:
            r = subprocess.run(
                [self.adb] + (["-s", self.device] if self.device else []) +
                ["shell", "dumpsys", "activity", "activities"],
                capture_output=True, text=True, timeout=10
            )
            for line in r.stdout.splitlines():
                if "mResumedActivity" in line or "topResumedActivity" in line:
                    m = __import__('re').search(r"([A-Za-z][\w.]+/[\w.$]+)", line)
                    if m:
                        activity = m.group(1)
                        self.stats["screens_visited"].add(activity)
                        return activity
        except:
            pass
        return "unknown"

    def _get_ui_elements(self):
        """الحصول على عناصر واجهة المستخدم"""
        try:
            # تفريغ UI عبر uiautomator
            r = subprocess.run(
                [self.adb] + (["-s", self.device] if self.device else []) +
                ["shell", "uiautomator", "dump", "/sdcard/hayo_ui.xml"],
                capture_output=True, text=True, timeout=15
            )
            if "dumped" in r.stdout.lower():
                # قراءة ملف XML
                r2 = subprocess.run(
                    [self.adb] + (["-s", self.device] if self.device else []) +
                    ["shell", "cat", "/sdcard/hayo_ui.xml"],
                    capture_output=True, text=True, timeout=10
                )
                if r2.stdout.strip().startswith("<"):
                    # تحليل XML
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(r2.stdout)
                    elements = []
                    i = 0
                    for node in root.iter("node"):
                        a = node.attrib
                        txt = (a.get("text") or "").strip()
                        desc = (a.get("content-desc") or "").strip()
                        cls = a.get("class", "")
                        bounds = a.get("bounds", "")

                        kind = None
                        if a.get("clickable") == "true" or "Button" in cls:
                            kind = "clickable"
                        if "EditText" in cls:
                            kind = "edit"

                        if kind and (txt or desc or kind == "edit"):
                            elements.append({
                                "i": i, "kind": kind,
                                "text": txt[:60], "desc": desc[:60]
                            })
                            i += 1
                    return elements[:30]
        except:
            pass
        return []

    def _execute_decision(self, decision):
        """تنفيذ قرار DeepSeek"""
        action = decision.get("action", "tap")
        target = decision.get("target", {})
        exploit_type = decision.get("exploit_type")

        if action == "exploit" and exploit_type:
            # تنفيذ استغلال
            self.stats["exploits_run"] += 1
            return self.engine.run_exploit(exploit_type, {
                "package": self.package,
                "api_key": self.intel["secrets"][0] if self.intel["secrets"] else "",
            })

        elif action == "tap":
            # النقر على عنصر
            idx = target.get("element_index", 0)
            elements = self._get_ui_elements()
            if idx < len(elements):
                return self._adb_tap_by_index(idx)
            return {"success": False, "error": "Element not found"}

        elif action == "input":
            # إدخال نص
            text = decision.get("text", "test@example.com")
            return self._adb_input_text(text)

        elif action == "swipe":
            # تمرير
            return self._adb_swipe()

        elif action == "back":
            # رجوع
            return self._adb_back()

        else:
            return {"success": False, "error": f"Unknown action: {action}"}

    def _adb_tap_by_index(self, idx):
        """النقر على عنصر بواسطة الفهرس"""
        try:
            # الحصول على إحداثيات العنصر
            r = subprocess.run(
                [self.adb] + (["-s", self.device] if self.device else []) +
                ["shell", "uiautomator", "dump", "/sdcard/hayo_ui.xml"],
                capture_output=True, text=True, timeout=10
            )
            if "dumped" in r.stdout.lower():
                r2 = subprocess.run(
                    [self.adb] + (["-s", self.device] if self.device else []) +
                    ["shell", "cat", "/sdcard/hayo_ui.xml"],
                    capture_output=True, text=True, timeout=10
                )
                if r2.stdout.strip().startswith("<"):
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(r2.stdout)
                    clickable_nodes = []
                    for node in root.iter("node"):
                        if node.attrib.get("clickable") == "true":
                            clickable_nodes.append(node)
                    if idx < len(clickable_nodes):
                        bounds = clickable_nodes[idx].attrib.get("bounds", "")
                        m = __import__('re').match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
                        if m:
                            x1, y1, x2, y2 = map(int, m.groups())
                            cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
                            subprocess.run(
                                [self.adb] + (["-s", self.device] if self.device else []) +
                                ["shell", "input", "tap", str(cx), str(cy)],
                                timeout=5
                            )
                            return {"success": True, "method": "tap", "x": cx, "y": cy}
        except:
            pass
        return {"success": False, "error": "Cannot tap"}

    def _adb_input_text(self, text):
        """إدخال نص عبر ADB"""
        try:
            safe_text = text.replace(" ", "%s").replace("'", "").replace('"', "")
            subprocess.run(
                [self.adb] + (["-s", self.device] if self.device else []) +
                ["shell", "input", "text", safe_text],
                timeout=5
            )
            return {"success": True, "method": "input", "text": text[:20]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _adb_swipe(self):
        """تمرير الشاشة"""
        try:
            subprocess.run(
                [self.adb] + (["-s", self.device] if self.device else []) +
                ["shell", "input", "swipe", "540", "1400", "540", "500", "300"],
                timeout=5
            )
            return {"success": True, "method": "swipe"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _adb_back(self):
        """الرجوع"""
        try:
            subprocess.run(
                [self.adb] + (["-s", self.device] if self.device else []) +
                ["shell", "input", "keyevent", "4"],
                timeout=5
            )
            return {"success": True, "method": "back"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_aggressive_exploit(self):
        """تنفيذ استغلال عدواني إضافي"""
        print(f"  {R}{B}[!] وضع عدواني — تنفيذ استغلال إضافي{X}")

        exploits = ["firebase", "premium", "token", "cloud"]
        exploit = exploits[self.round % len(exploits)]

        self.engine.run_exploit(exploit, {
            "package": self.package,
            "api_key": self.intel["secrets"][0] if self.intel["secrets"] else "",
        })

    def _get_findings_summary(self):
        """ملخص النتائج"""
        parts = []
        if self.stats["secrets_found"] > 0:
            parts.append(f"secrets:{self.stats['secrets_found']}")
        if self.stats["premium_unlocked"]:
            parts.append("premium:UNLOCKED")
        if self.stats["cloud_breached"]:
            parts.append("cloud:BREACHED")
        if self.stats["tokens_captured"] > 0:
            parts.append(f"tokens:{self.stats['tokens_captured']}")
        return ", ".join(parts) if parts else "جاري الاستكشاف..."

    def _print_summary(self):
        """طباعة الملخص النهائي"""
        elapsed = time.time() - self.start_time
        print(f"\n{'='*60}")
        print(f"  {C}{B}ملخص الاختراق النهائي{X}")
        print(f"{'='*60}")
        print(f"  {G}المدة:{X} {elapsed:.0f} ثانية")
        print(f"  {G}الجولات:{X} {self.stats['rounds']}")
        print(f"  {G}الإجراءات:{X} {self.stats['actions_taken']}")
        print(f"  {G}الاستغلالات:{X} {self.stats['exploits_run']}")
        print(f"  {G}المفاتيح السرية:{X} {self.stats['secrets_found']}")
        print(f"  {G}الشاشات التي تمت زيارتها:{X} {len(self.stats['screens_visited'])}")
        print(f"  {G}البريميوم مفتوح:{X} {'✓' if self.stats['premium_unlocked'] else '✗'}")
        print(f"  {G}السحابة مخترقة:{X} {'✓' if self.stats['cloud_breached'] else '✗'}")
        print(f"  {G}التوكنات الملتقطة:{X} {self.stats['tokens_captured']}")
        print(f"{'='*60}")

        # حفظ التقرير
        report = {
            "timestamp": datetime.now().isoformat(),
            "package": self.package,
            "duration": elapsed,
            "stats": self.stats,
            "intel": {
                "secrets_count": len(self.intel["secrets"]),
                "endpoints_count": len(self.intel["endpoints"]),
                "screens_count": len(self.stats["screens_visited"]),
            }
        }
        report_path = os.path.join(LOOT_DIR, f"autopwn_report_{self.package.replace('.', '_')}.json")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"\n  {G}[✓] التقرير محفوظ: {report_path}{X}")
        except:
            pass


def main():
    ap = argparse.ArgumentParser(description="HAYO Cipher-7 — AutoPwn (محرك اختراق غير مقيد)")
    ap.add_argument("--package", required=True, help="حزمة التطبيق المستهدف")
    ap.add_argument("--adb", default="adb", help="مسار adb")
    ap.add_argument("--device", help="معرف الجهاز (اختياري)")
    ap.add_argument("--aggressive", action="store_true", help="وضع عدواني — استغلال إضافي")
    ap.add_argument("--unlimited", action="store_true", default=True, help="وضع غير مقيد (افتراضي)")
    ap.add_argument("--max-rounds", type=int, default=0, help="الحد الأقصى للجولات (0 = غير محدود)")

    args = ap.parse_args()

    pwn = AutoPwn(
        package=args.package,
        adb_path=args.adb,
        device=args.device,
        aggressive=args.aggressive,
        unlimited=args.unlimited or args.max_rounds == 0
    )
    pwn.max_rounds = args.max_rounds
    pwn.run()


if __name__ == "__main__":
    main()
