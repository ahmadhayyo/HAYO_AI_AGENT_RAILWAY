#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — WAR ROOM AI BRAIN (warroom_brain.py)
======================================================
العقل الذكي المدبر - يدير غرفة العمليات بالكامل:
  - يستقبل المعلومات من المحرك الساكن والمحرك الديناميكي
  - يحلل البيانات ويصنفها حسب الأهمية
  - يقرر خطوات الاستغلال والتحليل التالية
  - يدير التنسيق بين الخدمات والمحركات
  - يوفر محرك تشخيص الأخطاء والتكيف التلقائي (Auto-Adaptation & Solution Engine)

متصل بـ Multi-Provider LLM Brain (OpenAI / DeepSeek / Ollama).
"""

import json
import os
import re
import sys
import time
import threading
from datetime import datetime

# Configure UTF-8 output on Windows streams if available
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))

try:
    import requests
except ImportError:
    requests = None

from llm_brain import LLMBrain, extract_json_from_text


def safe_print(text):
    """Safely print text handling Windows console encoding issues."""
    try:
        print(text)
    except UnicodeEncodeError:
        try:
            cleaned = text.encode("ascii", "ignore").decode("ascii")
            print(cleaned)
        except Exception:
            pass


class WarRoomBrain:
    """
    غرفة العمليات الذكية - العقل المدير الشامل
    """

    def __init__(self, package="com.anthropic.claude", store=None, verbose=True):
        self.package = package
        self.store = store
        self.verbose = verbose

        # Core LLM Brain Engine
        self.brain = LLMBrain(verbose=verbose)
        self.api_key = self.brain.api_key
        self.base_url = self.brain.base_url
        self.model = self.brain.model

        # Intelligence containers
        self.all_findings = []
        self.all_secrets = {}
        self.all_endpoints = []
        self.attack_plan = []
        self.executed_attacks = []
        self.cloud_targets = []
        self.critical_findings = []

        # Status flags
        self.static_done = False
        self.dynamic_done = False
        self.cloud_breach_done = False
        self.exploitation_done = False
        self.firewall_bypass_done = False

        # Thread safety & timing
        self._lock = threading.RLock()
        self.start_time = time.time()
        self.available = True  # Flag for DynamicEngine compatibility

        self.log("تم تفعيل غرفة العمليات الذكية - AI WarRoom Mastermind Engine")
        self.log(f"النموذج النشط: {self.model}")

    def log(self, msg, prefix="[WARROOM]"):
        if self.verbose:
            safe_print(f"{prefix} {msg}")

    def _call_ai(self, system_prompt, user_prompt, temperature=0.3):
        """استدعاء الذكاء الاصطناعي لاتخاذ القرارات عبر العقل المدبر"""
        return self.brain.chat(system_prompt, user_prompt, temperature=temperature)

    def triage(self, findings):
        """
        تحليل وتصنيف النتائج الخام من المحرك الديناميكي.
        """
        triaged = []
        for i, f in enumerate(findings):
            if isinstance(f, dict):
                severity = f.get("severity", "info")
                title = f.get("title", f.get("name", f"Finding #{i+1}"))
                triaged.append({
                    "severity": severity,
                    "title": title,
                    "false_positive": f.get("false_positive", False),
                    "why": f.get("why", f.get("description", "")),
                    "exploitation": f.get("exploitation", f.get("exploit", "")),
                    "type": f.get("type", f.get("category", "general")),
                    "data": f.get("data", ""),
                    "source": f.get("source", "dynamic")
                })
            else:
                triaged.append({
                    "severity": "info",
                    "title": str(f),
                    "false_positive": False,
                    "why": "",
                    "exploitation": "",
                    "type": "raw",
                    "data": str(f),
                    "source": "dynamic"
                })

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        triaged.sort(key=lambda x: severity_order.get(str(x.get("severity", "info")).lower(), 99))

        self.log(f"تصنيف {len(findings)} نتيجة -> {len(triaged)} نتائج مرتبة")
        return triaged

    def summarize(self, session):
        """
        توليد ملخص تنفيذي للجلسة.
        """
        package = session.get("package", self.package)
        visited = session.get("visited", [])
        steps = session.get("explore_steps", 0)
        raw_count = session.get("raw_count", 0)
        triaged = session.get("triaged", [])

        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in triaged:
            s = str(t.get("severity", "info")).lower()
            if s in sev:
                sev[s] += 1

        summary = (
            f"التحليل الشامل للتطبيق {package}\n"
            f"- عدد النتائج الخام: {raw_count}\n"
            f"- النتائج المصنفة: {len(triaged)}\n"
            f"  - حرجة: {sev['critical']} | عالية: {sev['high']} | متوسطة: {sev['medium']} | منخفضة: {sev['low']}\n"
            f"- الشاشات التي تم زيارتها: {len(visited)}\n"
            f"- خطوات الاستكشاف: {steps}\n"
        )

        system = "لخص نتائج التحليل والتفاعل في 2-3 جمل باللغة العربية."
        ai_result = self._call_ai(system, json.dumps(session, ensure_ascii=False, indent=2)[:2000], temperature=0.3)
        if ai_result:
            summary += f"\nتحليل AI:\n{ai_result}"

        return summary

    def ingest_static_findings(self, static_report):
        """استقبال نتائج التحليل الساكن"""
        self.log("استقبال نتائج المحرك الساكن...")

        secrets = static_report.get("secrets", {})
        endpoints = static_report.get("endpoints", [])

        for cat, vals in secrets.items():
            if vals:
                self.all_secrets[cat] = vals
                for v in vals:
                    severity = "critical" if any(k in cat for k in ["key", "token", "secret", "private"]) else "high"
                    self.critical_findings.append({
                        "type": f"static_{cat}",
                        "value": v,
                        "severity": severity,
                        "source": "static"
                    })
                    if self.store:
                        self.store.add("secret", v, source="static", note=cat)

        for ep in endpoints:
            self.all_endpoints.append(ep)
            if any(domain in ep for domain in ["firebase", "googleapis", "amazonaws", "supabase"]):
                self.cloud_targets.append(ep)
                if self.store:
                    self.store.add("endpoint", ep, source="static", note="cloud")

        self.static_done = True
        self.log(f"تم استيعاب: {sum(len(v) for v in secrets.values())} سر, {len(endpoints)} نقطة نهاية")

    def ingest_dynamic_findings(self, findings):
        """استقبال نتائج المحرك الديناميكي"""
        self.log("استقبال نتائج المحرك الديناميكي...")

        for f in findings:
            self.all_findings.append(f)
            sev = f.get("severity", "medium")
            if sev in ("critical", "high"):
                self.critical_findings.append(f)

            evidence = f.get("evidence", [])
            for ev in evidence:
                if isinstance(ev, dict) and ev.get("sensitive"):
                    val = ev.get("value", "")
                    if val:
                        self.all_secrets.setdefault("dynamic", []).append(val)
                        if self.store:
                            self.store.add("secret", val, source="dynamic", note=f.get("type", "unknown"))

        self.dynamic_done = True
        self.log(f"تم استيعاب: {len(findings)} نتيجة, {len(self.critical_findings)} حرجة")

    def decide_next_action(self):
        """اتخاذ القرار التالي بناءً على الوضع الراهن"""
        with self._lock:
            if not self.static_done:
                return {"action": "run_static", "reason": "يجب تشغيل المحرك الساكن أولاً"}
            if not self.dynamic_done:
                return {"action": "run_dynamic", "reason": "يجب تشغيل المحرك الديناميكي"}
            if not self.cloud_breach_done:
                return {"action": "run_cloud_breach", "reason": "يجب تنفيذ مرحلة التحليل السحابي"}
            if not self.exploitation_done:
                return {"action": "run_exploitation", "reason": "يجب بدء مرحلة التحليل المتقدم"}
            return {"action": "all_done", "reason": "جميع المراحل مكتملة"}

    def decide_action(self, obs):
        """توجيه استكشاف الواجهة عبر العقل المدبر"""
        return self.brain.decide_action(obs)

    def diagnose_obstacle(self, problem_description, logs=""):
        """تشخيص أي مشكلة أو عقبة تقنية وتقديم خطة حلول شاملة (A, B, C)"""
        return self.brain.diagnose_and_solve(problem_description, error_logs=logs, environment_context={"package": self.package})

    def synthesize_report(self):
        """تجميع تقرير نهائي شامل من جميع المحركات"""
        self.log("تجميع التقرير النهائي الشامل...")

        report = {
            "package": self.package,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(time.time() - self.start_time, 1),
            "phases": {
                "static_analysis": self.static_done,
                "dynamic_analysis": self.dynamic_done,
                "cloud_analysis": self.cloud_breach_done,
                "exploitation": self.exploitation_done
            },
            "summary": {
                "total_secrets": sum(len(v) if isinstance(v, list) else 1 for v in self.all_secrets.values()),
                "total_endpoints": len(self.all_endpoints),
                "total_findings": len(self.all_findings),
                "critical_findings": len(self.critical_findings),
                "cloud_targets": len(self.cloud_targets)
            },
            "secrets": self.all_secrets,
            "critical_findings": self.critical_findings[:20]
        }

        report_dir = os.path.join(HERE, "loot")
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, f"warroom_report_{self.package.replace('.', '_')}.json")

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        self.log(f"تمت كتابة التقرير النهائي إلى: {report_path}")

        system = "لخص التقرير المرفق في 3-5 نقاط بالعربية موضحاً أهم النتائج والحلول الموصى بها."
        result = self._call_ai(system, json.dumps(report, ensure_ascii=False, indent=2)[:3000], temperature=0.3)
        if result:
            report["ai_summary"] = result

        return report


if __name__ == "__main__":
    wb = WarRoomBrain("com.anthropic.claude")
    safe_print(f"WarRoom Brain state: {wb.decide_next_action()}")
    safe_print("Diagnosing sample issue...")
    diag = wb.diagnose_obstacle("UI element click failed due to overlay")
    safe_print(f"Recommended Plan: {diag.get('recommended_plan')}")
