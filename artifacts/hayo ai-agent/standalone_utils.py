#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Standalone helpers
==================================
مساعدات مشتركة تجعل المكوّنات الداخلية (Working Memory / Decision Engine /
Live Data Extractor / Adaptive Exploitation / Feedback Loop / Phase Manager)
قابلة للتشغيل المنفصل من اللوحة **على بيانات جلسة حقيقية** — لا على بيانات ديمو.

القاعدة الذهبية: لا تلفيق. إن لم توجد جلسة حقيقية سابقة للهدف، تُبلّغ الوحدة
بذلك وتخرج، بدل اختراع نتائج (راجع مبدأ "لا نتائج ملفّقة" في المشروع).
"""
import os
import sys
import glob
import json
import argparse

HERE = os.path.dirname(os.path.abspath(__file__))
LOOT = os.path.join(HERE, "loot")


def enable_utf8():
    """يضبط ترميز الطرفية على UTF-8 حتى لا ينهار الإخراج العربي في نافذة cmd
    (نفس منهج dynamic_engine.py)."""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        try:
            os.system("chcp 65001 >nul")
        except Exception:
            pass


def parse_target_args(description=""):
    """يقرأ --package/--device/--adb الممرّرة من اللوحة (يتسامح مع الزائد)."""
    enable_utf8()
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--package", "-p", default=None, help="اسم حزمة الهدف")
    ap.add_argument("--device", "-D", default=os.environ.get("HAYO_DEV", "emulator-5554"))
    ap.add_argument("--adb", default=os.environ.get("HAYO_ADB", "adb"))
    ap.add_argument("--session", default=None, help="مسار ملف جلسة deep_*.json محدّد")
    args, _unknown = ap.parse_known_args()
    return args


def find_sessions(package=None):
    """يُعيد كل ملفات جلسات المحرّك الديناميكي الحقيقية، الأحدث أولاً."""
    files = glob.glob(os.path.join(LOOT, "deep_*.json"))
    if package:
        safe = package.strip()
        files = [f for f in files if safe in os.path.basename(f)]
    return sorted(files, key=lambda f: os.path.getmtime(f), reverse=True)


def load_latest_session(package=None, explicit_path=None):
    """يحمّل أحدث جلسة حقيقية. يُعيد (path, session_dict) أو (None, None)."""
    if explicit_path:
        if os.path.isfile(explicit_path):
            with open(explicit_path, "r", encoding="utf-8") as f:
                return explicit_path, json.load(f)
        return None, None
    files = find_sessions(package)
    if not files:
        return None, None
    path = files[0]
    try:
        with open(path, "r", encoding="utf-8") as f:
            return path, json.load(f)
    except Exception:
        return None, None


def require_session(package=None, explicit_path=None):
    """يحمّل جلسة أو يطبع إرشاداً صادقاً ويُنهي العملية إن لم توجد."""
    path, session = load_latest_session(package, explicit_path)
    if not session:
        tgt = f" للهدف «{package}»" if package else ""
        print("=" * 64)
        print(f"[!] لا توجد جلسة تحليل ديناميكي حقيقية سابقة{tgt} في loot/.")
        print("    هذه الوحدة تعالج نتائج جلسة حقيقية — لا تولّد بيانات وهمية.")
        print("    شغّل أولاً: «المسار الكامل بقيادة AI» أو المحرّك الديناميكي،")
        print("    ثم أعد فتح هذا الزر ليعمل على المخرجات الفعلية.")
        print("=" * 64)
        raise SystemExit(2)
    print(f"[+] جلسة حقيقية: {os.path.basename(path)}")
    print(f"    الهدف: {session.get('package','?')} | الوقت: {session.get('timestamp','?')} "
          f"| نتائج خام: {session.get('raw_count', len(session.get('findings', [])))}")
    return path, session


def severity_to_priority(sev):
    """يحوّل شدّة الـ finding إلى Priority (يُستورد كسلاً لتفادي دورات الاستيراد)."""
    from working_memory import Priority
    return {
        "critical": Priority.CRITICAL,
        "high": Priority.HIGH,
        "medium": Priority.MEDIUM,
        "low": Priority.LOW,
    }.get(str(sev).lower(), Priority.MEDIUM)


def build_brain(verbose=False):
    """يبني الـbrain الحقيقي (ExtendedBrain حول LLMBrain). يُعيد None إن تعذّر.

    لا يستخدم أبداً DummyBrain — الوحدات التي تتطلّب brain تُبلّغ وتخرج بدلاً من
    إنتاج قرارات مزيّفة.
    """
    try:
        from llm_brain import LLMBrain
        from extended_brain import ExtendedBrain
    except Exception as e:
        print(f"[!] العقل المدبّر (LLMBrain/ExtendedBrain) غير متاح: {e}")
        return None
    try:
        base = LLMBrain(verbose=verbose)
    except TypeError:
        base = LLMBrain()
    except Exception as e:
        print(f"[!] تعذّر تهيئة LLMBrain: {e}")
        return None
    try:
        brain = ExtendedBrain(base_brain=base, verbose=verbose)
    except Exception as e:
        print(f"[!] تعذّر تهيئة ExtendedBrain: {e}")
        return None
    if not (hasattr(brain, "decide") and hasattr(brain, "select_exploit") and hasattr(brain, "update_strategy")):
        print("[!] العقل المدبّر لا يوفّر الطرق المطلوبة (decide/select_exploit/update_strategy).")
        return None
    return brain


def session_targets(session):
    """يستخرج أهدافاً حقيقية للاستغلال من النتائج المُصنّفة (triaged) للجلسة."""
    targets = []
    for t in session.get("triaged", []):
        ftype = str(t.get("type", "")).lower()
        sev = str(t.get("severity", "info")).lower()
        target = {
            "type": t.get("type", "unknown"),
            "priority": sev,
            "description": t.get("title") or t.get("detail") or t.get("type", ""),
            "data": t.get("evidence", {}) or t.get("data", {}),
        }
        # تعيين نوع الهدف لقوالب الاستغلال الحقيقية عند التطابق
        if "cloud" in ftype or "aws" in ftype or "s3" in ftype or "firebase" in ftype:
            target["type"] = "cloud_credentials"
            target["secrets"] = t.get("evidence", {}) or {}
        elif "token" in ftype or "jwt" in ftype:
            target["type"] = "token_theft"
        targets.append(target)
    return targets
