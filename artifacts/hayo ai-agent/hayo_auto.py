#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Static Entry — hayo_auto.py
================================
غلاف رفيع (thin wrapper) يستدعي المحرك الساكن الحقيقي الوحيد: static_engine.StaticEngine.

سابقاً كان هذا الملف "وهمياً": يتجاهل الـ APK ويمسح ملفات .md/.json/.txt في مجلد
الوكيل. تم اعتماد المحرك الحقيقي (static_engine.py: سحب APK + androguard) وتحويل هذا
المدخل ليفوّض إليه — دون تغيير الواجهة أو ملفات .bat التي تستدعيه بالاسم.

يقبل الاستدعاءات التالية كما هي:
  hayo_auto.py "<apk>" --test-keys          (زر الواجهة «① التحليل الساكن»)
  hayo_auto.py --package <pkg>              (خطوة Static في deepseek_pipeline.py)
  hayo_auto.py "<apk>" --package <pkg> --device <serial>
"""
import argparse
import os
import sys

if os.name == "nt":
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from static_engine import StaticEngine
try:
    from intel_store import IntelStore
except Exception:
    IntelStore = None


def _derive_package(apk_path):
    """اشتقاق اسم الحزمة من الـ APK عبر androguard (عند غياب --package)."""
    try:
        from androguard.core.apk import APK
        return APK(apk_path).get_package()
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="HAYO static entry → static_engine.StaticEngine")
    ap.add_argument("apk", nargs="?", default=None, help="مسار ملف APK (اختياري)")
    ap.add_argument("--package", "-p", default=None, help="اسم الحزمة")
    ap.add_argument("--device", "-d", default=os.getenv("HAYO_DEV") or "emulator-5554")
    # نتجاهل أي أعلام قديمة (مثل --test-keys) دون كسر الاستدعاء
    args, _unknown = ap.parse_known_args()

    apk = args.apk if (args.apk and os.path.isfile(args.apk)) else None
    package = args.package

    if not package and apk:
        package = _derive_package(apk)
    if not package:
        print("\033[91m[hayo_auto] يلزم --package أو مسار APK صالح لاشتقاق الحزمة.\033[0m")
        return 2

    print(f"\033[96m[hayo_auto] تفويض للمحرك الساكن الحقيقي (static_engine) → "
          f"package={package} device={args.device} apk={apk or '(سحب من الجهاز)'}\033[0m")

    store = IntelStore(package=package) if IntelStore else None
    engine = StaticEngine(package, store=store, device=args.device, apk_path=apk)
    engine.run_full_static()
    if store:
        store.save()
        print(f"\033[92m[hayo_auto] تم حفظ الاستخبارات الساكنة للحزمة {package}.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
