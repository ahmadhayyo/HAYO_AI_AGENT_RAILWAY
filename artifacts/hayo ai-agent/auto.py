#!/usr/bin/env python3
"""
HAYO Cipher-7 — One-Click Auto Runner
=====================================
Zero-fumble dynamic analysis for a live demo. You run ONE thing (or double-click
HAYO-Dynamic.bat) and it figures everything out automatically:

  1. locates adb (PATH or common LDPlayer/emulator install paths),
  2. connects to your running emulator (auto adb connect if needed),
  3. makes sure frida-server is running (starts an existing one if it's not),
  4. auto-detects the TARGET PACKAGE (the app currently open on the emulator),
  5. launches the deep instrumentation agent and streams the findings,
  6. the agent posts them to the platform where they merge into your report.

Only input you ever need: the one-time --token from the report.
Everything else is automatic. Server + package are auto-filled/detected.

    python auto.py --token dyn_XXXX
    (or just double-click HAYO-Dynamic.bat and paste the token once)
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

# Pre-filled so the runner only ever needs the token.
DEFAULT_SERVER = "https://hayoaiagentrailway-production.up.railway.app"

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "agent.py")

# Common Windows locations for a bundled adb (LDPlayer / Nox / BlueStacks / SDK).
ADB_CANDIDATES = [
    r"C:\Users\PT\Downloads\platform-tools\adb.exe",   # verified on this machine
    r"D:\LDPlayer\LDPlayer9\adb.exe",                   # LDPlayer bundled adb
    r"C:\LDPlayer\LDPlayer9\adb.exe",
    r"C:\LDPlayer\LDPlayer4.0\adb.exe",
    r"C:\Program Files\LDPlayer\LDPlayer9\adb.exe",
    r"C:\Program Files (x86)\Nox\bin\nox_adb.exe",
    r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe",
    os.path.expanduser(r"~\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
]
# frida-server on the device is pinned to 16.7.19, which needs the matching
# Frida *client*. On this machine that client lives in Python 3.12 (the default
# `python` is 3.14 with Frida 17, which CANNOT talk to a 16.x server). Prefer an
# interpreter that actually has a matching Frida over whatever launched us.
PY312_CANDIDATES = [
    r"C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe",
]
# LDPlayer/emulator default loopback adb endpoints.
CONNECT_PORTS = ["127.0.0.1:5555", "127.0.0.1:5554", "127.0.0.1:5556", "emulator-5554"]


def log(msg):
    print(msg, flush=True)


def find_adb(explicit=None):
    if explicit and os.path.exists(explicit):
        return explicit
    for c in ADB_CANDIDATES:
        if os.path.exists(c):
            return c
    p = shutil.which("adb")
    if p:
        return p
    return "adb"  # last resort; may fail with a clear message later


def _frida_ok(python_cmd):
    """True if the given interpreter has a Frida client that can drive a 16.x
    server (i.e. Frida 16.x, not 17.x)."""
    try:
        r = subprocess.run(python_cmd + ["-c", "import frida;print(frida.__version__)"],
                           capture_output=True, text=True, timeout=15)
        ver = (r.stdout or "").strip()
        return ver.startswith("16.")
    except Exception:
        return False


def find_python():
    """Return the interpreter (as an argv list) whose Frida matches frida-server.
    Prefer the known Python 3.12, then `py -3.12`, then fall back to whatever is
    running us — but warn loudly if that fall-back has a mismatched Frida."""
    for c in PY312_CANDIDATES:
        if os.path.exists(c) and _frida_ok([c]):
            return [c]
    if _frida_ok(["py", "-3.12"]):
        return ["py", "-3.12"]
    # last resort: current interpreter
    if not _frida_ok([sys.executable]):
        log("[!] تحذير: مفسّر بايثون الحالي لا يملك Frida 16.x المطابق لـ frida-server 16.7.19.")
        log("    ثبّت: py -3.12 -m pip install \"frida==16.7.19\" \"frida-tools\"  ثم أعد التشغيل.")
    return [sys.executable]


def adb(adb_path, *args, timeout=15):
    try:
        r = subprocess.run([adb_path, *args], capture_output=True, text=True,
                           timeout=timeout, errors="ignore")
        return (r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip())
    except Exception as e:
        return (1, "", str(e))


def list_devices(adb_path):
    _, out, _ = adb(adb_path, "devices")
    devs = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devs.append(parts[0])
    return devs


def _pick_emulator(devs):
    """Prefer an emulator over a physically-attached phone. A real device
    (e.g. a Samsung serial like R5CRB32H4WY) must NEVER be the default target —
    we only ever instrument the emulator."""
    for d in devs:
        if d.startswith("emulator-") or d.startswith("127.0.0.1:"):
            return d
    return devs[0]


def ensure_device(adb_path):
    log("[*] البحث عن محاكي متصل…")
    devs = list_devices(adb_path)
    if not devs:
        log("[*] لا يوجد جهاز — محاولة الاتصال بالمحاكي تلقائياً…")
        for endpoint in CONNECT_PORTS:
            adb(adb_path, "connect", endpoint, timeout=8)
        time.sleep(1.5)
        devs = list_devices(adb_path)
    if not devs:
        log("[!] لم يُعثر على محاكي. تأكّد أن LDPlayer/المحاكي يعمل، ثم أعد المحاولة.")
        return None
    dev = _pick_emulator(devs)
    if len(devs) > 1:
        others = [d for d in devs if d != dev]
        log(f"[*] أجهزة أخرى متصلة (تُتجاهَل): {', '.join(others)}")
    log(f"[✓] الجهاز (المحاكي): {dev}")
    return dev


def frida_running(adb_path, dev):
    _, out, _ = adb(adb_path, "-s", dev, "shell", "pidof", "frida-server")
    return bool(out.strip())


def ensure_frida(adb_path, dev):
    if frida_running(adb_path, dev):
        log("[✓] frida-server يعمل.")
        return True
    log("[*] frida-server متوقّف — محاولة تشغيله تلقائياً…")
    # Try to start an already-pushed frida-server (common location) as root.
    for cmd in (
        'su -c "/data/local/tmp/frida-server &"',
        "/data/local/tmp/frida-server &",
        'su 0 sh -c "/data/local/tmp/frida-server &"',
    ):
        adb(adb_path, "-s", dev, "shell", cmd, timeout=6)
        time.sleep(2.0)
        if frida_running(adb_path, dev):
            log("[✓] تم تشغيل frida-server.")
            return True
    log("[!] تعذّر تشغيل frida-server تلقائياً. شغّله يدوياً مرّة واحدة:")
    log('    adb shell "su -c \'/data/local/tmp/frida-server &\'"')
    return False


def detect_package(adb_path, dev):
    """The app currently in the foreground on the emulator = the target."""
    probes = [
        ("shell", "dumpsys", "activity", "activities"),
        ("shell", "dumpsys", "window", "windows"),
        ("shell", "dumpsys", "window"),
    ]
    import re
    pat = re.compile(r"([a-zA-Z][\w]+(?:\.[\w]+){2,})/")
    ignore = ("com.android.", "com.google.android.", "android", "com.ldmnq", "com.miui")
    for pr in probes:
        _, out, _ = adb(adb_path, "-s", dev, *pr, timeout=12)
        for kw in ("mResumedActivity", "mCurrentFocus", "mFocusedApp", "topResumedActivity"):
            for line in out.splitlines():
                if kw in line:
                    m = pat.search(line)
                    if m and not m.group(1).startswith(ignore):
                        return m.group(1)
    return None


def main():
    ap = argparse.ArgumentParser(description="HAYO one-click dynamic auto-runner")
    ap.add_argument("--token", required=True, help="الرمز من التقرير (dyn_...)")
    ap.add_argument("--server", default=DEFAULT_SERVER, help="عنوان المنصة (تلقائي)")
    ap.add_argument("--package", help="اسم الحزمة (يُكتشف تلقائياً إن تُرك فارغاً)")
    ap.add_argument("--duration", type=int, default=150, help="مدة الرصد بالثواني")
    ap.add_argument("--adb", help="مسار adb (يُكتشف تلقائياً)")
    ap.add_argument("--no-crawl", action="store_true", help="عطّل الاستكشاف الآلي")
    args = ap.parse_args()

    log("=" * 60)
    log("  HAYO Cipher-7 — التحليل الديناميكي التلقائي")
    log("=" * 60)

    adb_path = find_adb(args.adb)
    log(f"[*] adb: {adb_path}")

    dev = ensure_device(adb_path)
    if not dev:
        sys.exit(1)

    ensure_frida(adb_path, dev)  # best-effort; agent gives a clear error if truly down

    package = args.package
    if not package:
        log("[*] اكتشاف التطبيق المفتوح تلقائياً…")
        package = detect_package(adb_path, dev)
        if package:
            log(f"[✓] التطبيق الهدف: {package}")
        else:
            log("[!] لم أتمكّن من كشف التطبيق تلقائياً.")
            log("    افتح تطبيق اللجنة على المحاكي الآن، ثم اضغط Enter…")
            try:
                input()
            except EOFError:
                pass
            package = detect_package(adb_path, dev)
            if not package:
                sys.exit("[!] ما زال غير مكتشف. أعد التشغيل بعد فتح التطبيق، أو مرّر --package.")
            log(f"[✓] التطبيق الهدف: {package}")

    py = find_python()
    log(f"[*] مفسّر Frida: {' '.join(py)}")
    cmd = [
        *py, AGENT,
        "--server", args.server,
        "--token", args.token,
        "--package", package,
        "--spawn",
        "--duration", str(args.duration),
        "--adb", adb_path,
        "--device", dev,
    ]
    if not args.no_crawl:
        cmd.append("--crawl")

    log("[*] بدء الحقن والرصد التلقائي… (تفاعل مع التطبيق: سجّل دخول/افتح الشاشات لأفضل التقاط)")
    log("-" * 60)
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    log("-" * 60)
    log("[✓] انتهى. حدّث التقرير في المنصة لرؤية النتائج الديناميكية مدموجة.")


if __name__ == "__main__":
    main()
