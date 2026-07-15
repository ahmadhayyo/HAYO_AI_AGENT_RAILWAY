#!/usr/bin/env python3
"""
HAYO Cipher-7 — Standalone Dynamic Demo
=======================================
A self-contained live demo of the runtime differentiator: it attaches Frida to
the target app and prints, IN REAL TIME, the encryption keys / secrets / tokens
the app uses — captured from memory at the moment of use, defeating obfuscation
and encryption that DEFEAT static tools.

No platform / token / internet needed — pure local demo for the committee.

Usage:
    py -3.12 demo.py --package com.target.app [--spawn] [--duration 120]

Prereqs: emulator online (adb), frida-server (matching version) running as root,
target app installed.
"""
import argparse
import json
import os
import sys
import time

# Force UTF-8 output so Arabic + emoji render on any console/redirect (Windows
# defaults to a legacy codepage that crashes on non-Latin output).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    import frida
except ImportError:
    sys.exit("[!] frida غير مثبّت — شغّل: py -3.12 -m pip install frida frida-tools")

SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "instrument.js")

# ── pretty console (ANSI) ───────────────────────────────────────────────────
R = "\033[0m"; BOLD = "\033[1m"
RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"; CYN = "\033[96m"; GRY = "\033[90m"
SEV_COLOR = {"critical": RED, "high": YEL, "medium": CYN, "low": GRY, "info": GRY}
# The highest-value captures for the demo headline.
KEY_TYPES = {
    "static_key_runtime": "🔑 مفتاح تشفير حقيقي (من الذاكرة)",
    "secret_captured": "🎫 توكن/سر مُرسَل فعلياً",
    "cleartext_request": "🌐 طلب HTTP غير مشفّر",
    "ssl_pinning_bypassed": "🔓 تجاوز تثبيت الشهادات",
    "ecb_at_runtime": "⚠️ تشفير ECB وقت التشغيل",
    "weak_hash_runtime": "⚠️ تجزئة ضعيفة وقت التشغيل",
}

_count = 0
_keys_found = 0


def on_message(message, data):
    global _count, _keys_found
    if message.get("type") == "error":
        print(f"{GRY}[frida] {message.get('description','')}{R}")
        return
    p = message.get("payload") or {}
    kind = p.get("kind")
    if kind == "ready":
        print(f"\n{GRN}{BOLD}[✓] الخطافات نشطة — تفاعل مع التطبيق الآن (سجّل دخول/افتح الشاشات){R}\n")
        return
    if kind != "finding":
        return
    _count += 1
    t = p.get("type", "?")
    sev = p.get("severity") or "info"
    col = SEV_COLOR.get(sev, GRY)
    detail = (p.get("detail") or "")[:120]
    label = KEY_TYPES.get(t)
    if label:  # headline capture
        _keys_found += 1
        print(f"{col}{BOLD}  ┌─ {label}{R}")
        print(f"{col}  │  {detail}{R}")
        for e in (p.get("evidence") or [])[:4]:
            v = str(e.get("value", ""))[:200]
            print(f"{col}  │    {e.get('label','')}: {BOLD}{v}{R}")
        print(f"{col}  └─{R}")
    else:
        print(f"{col}  [+] [{sev:<8}] {t:<26}{R} — {detail}")


def get_device(device_id):
    if device_id:
        return frida.get_device(device_id, timeout=8)
    for d in frida.enumerate_devices():
        if d.type == "usb" or "emulator" in (d.id or "").lower():
            return d
    return frida.get_usb_device(timeout=5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", required=True)
    ap.add_argument("--spawn", action="store_true", help="إطلاق التطبيق من جديد (أفضل لالتقاط الإقلاع)")
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--device", default=None)
    args = ap.parse_args()

    if not os.path.exists(SCRIPT_PATH):
        sys.exit(f"[!] لم يُعثر على سكربت الحقن: {SCRIPT_PATH}")
    with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
        src = f.read()

    print(f"{CYN}{BOLD}══ HAYO Cipher-7 — عرض التحليل الديناميكي الحيّ ══{R}")
    print(f"{GRY}الهدف: {args.package}{R}")
    device = get_device(args.device)
    print(f"{GRY}الجهاز: {getattr(device,'id','?')} ({getattr(device,'name','?')}){R}")

    try:
        if args.spawn:
            pid = device.spawn([args.package]); session = device.attach(pid)
        else:
            session = device.attach(args.package); pid = None
    except Exception as e:
        sys.exit(f"{RED}[!] تعذّر الإرفاق: {e}\n    تأكّد أن frida-server يعمل (كروت) والتطبيق مفتوح.{R}")

    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    if args.spawn and pid is not None:
        device.resume(pid)

    print(f"{GRY}الرصد لمدة {args.duration}ث — Ctrl+C للإنهاء المبكر…{R}")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print(f"\n{GRY}[*] إنهاء مبكر.{R}")
    finally:
        try:
            script.unload(); session.detach()
        except Exception:
            pass

    print(f"\n{GRN}{BOLD}══ انتهى العرض ══{R}")
    print(f"{GRN}إجمالي المشاهدات: {_count} · التقاطات مفاتيح/أسرار حيّة: {BOLD}{_keys_found}{R}")
    if _keys_found:
        print(f"{GRN}✓ الأداة استخرجت أسراراً وقت التشغيل — وهو ما يعجز عنه التحليل الساكن والأدوات العادية.{R}")


if __name__ == "__main__":
    main()
