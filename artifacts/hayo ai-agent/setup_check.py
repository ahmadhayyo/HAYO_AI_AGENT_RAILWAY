#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Environment Setup Check & Auto-Fix (setup_check.py)
=================================================================
Implements evaluator recommendation #3.2 ("simplify setup"): one command that
verifies and auto-repairs the whole environment before the exam —
  • finds adb + reconnects the LDPlayer emulator if it dropped
  • checks Python/Frida client version vs on-device frida-server (must MATCH)
  • starts frida-server on the device if it isn't running
  • checks apktool.jar / uber-apk-signer.jar / java
Prints a clear green/red checklist.
"""
import os, subprocess, sys

for s in (sys.stdout, sys.stderr):
    try: s.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
if os.name == "nt":
    try: os.system("chcp 65001 >nul")
    except Exception: pass
    try:
        import ctypes; ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception: pass
G, R, Y, C, X = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[0m"
OK, BAD, WARN = G + "  ✓ " + X, R + "  ✗ " + X, Y + "  ! " + X

ADB = r"C:\Users\PT\Downloads\platform-tools\adb.exe"
PY312 = r"C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
TOOLDIR = r"C:\Users\PT\Desktop\APK"
LD_PORTS = ["127.0.0.1:5555", "127.0.0.1:5557", "127.0.0.1:5559",
            "127.0.0.1:62001", "127.0.0.1:62025", "127.0.0.1:62026", "emulator-5554"]

def run(cmd, timeout=25):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except Exception as e:
        class R: returncode = 1; stdout = ""; stderr = str(e)
        return R()

def devices():
    out = run([ADB, "devices"]).stdout
    return [l.split("\t")[0] for l in out.splitlines()[1:] if "\tdevice" in l]

def main():
    print(C + "\n══════ HAYO Cipher-7 — فحص البيئة ══════\n" + X)

    # 1) adb
    if not os.path.isfile(ADB):
        print(BAD + f"adb غير موجود في {ADB}"); print(Y + "    ثبّت platform-tools." + X); return
    print(OK + "adb موجود")

    # 2) device / reconnect
    devs = devices()
    if not devs:
        print(WARN + "لا يوجد جهاز — محاولة إعادة الاتصال بـ LDPlayer ...")
        for p in LD_PORTS:
            run([ADB, "connect", p], timeout=8)
        devs = devices()
    if not devs:
        print(BAD + "لا يوجد محاكي متصل. افتح LDPlayer وانتظر إقلاعه ثم أعد التشغيل.")
        return
    dev = next((d for d in devs if "emulator" in d or "127.0.0.1" in d), devs[0])
    print(OK + f"الجهاز متصل: {dev}")

    def sh(args):
        return run([ADB, "-s", dev] + args)

    # 3) root
    rid = sh(["shell", "su -c id"]).stdout
    print((OK if "uid=0" in rid else WARN) + ("صلاحية root متاحة" if "uid=0" in rid else "root غير مؤكّد (قد يلزم لـ frida-server)"))

    # 4) frida client version (py312)
    cv = run([PY312, "-c", "import frida;print(frida.__version__)"]).stdout.strip()
    print((OK if cv else BAD) + f"عميل Frida (Python 3.12): {cv or 'غير مثبّت'}")

    # 5) frida-server on device: present, version, running
    srv_ver = sh(["shell", "su -c '/data/local/tmp/frida-server --version'"]).stdout.strip()
    if srv_ver:
        print(OK + f"frida-server على الجهاز: {srv_ver}")
        if cv and srv_ver != cv:
            print(BAD + f"عدم تطابق! العميل {cv} ≠ الخادم {srv_ver} — استخدم Python 3.12 (المطابق).")
        else:
            print(OK + "الإصدارات متطابقة ✅")
    else:
        print(BAD + "frida-server غير موجود في /data/local/tmp/ على الجهاز.")

    running = "frida-server" in sh(["shell", "ps -A"]).stdout
    if not running:
        print(WARN + "frida-server لا يعمل — جارٍ تشغيله ...")
        sh(["shell", "su -c 'setsid /data/local/tmp/frida-server >/data/local/tmp/f.log 2>&1 &'"])
        import time; time.sleep(2)
        running = "frida-server" in sh(["shell", "ps -A"]).stdout
    print((OK if running else BAD) + ("frida-server يعمل الآن" if running else "تعذّر تشغيل frida-server"))

    # 6) build tools
    for name in ["apktool.jar", "uber-apk-signer.jar"]:
        p = os.path.join(TOOLDIR, name)
        print((OK if os.path.isfile(p) else BAD) + f"{name} {'موجود' if os.path.isfile(p) else 'مفقود في '+TOOLDIR}")
    jv = run(["java", "-version"]).stderr
    print((OK if "version" in jv else BAD) + ("java متاح" if "version" in jv else "java غير متاح"))

    print(C + "\n══════ انتهى الفحص — إن كانت كل الأسطر خضراء فأنت جاهز ══════\n" + X)
    print(Y + f"تلميح: استخدم دائمًا Python 3.12 لأوامر Frida (المطابق للخادم).\nالجهاز الهدف: {dev}\n" + X)

if __name__ == "__main__":
    main()
