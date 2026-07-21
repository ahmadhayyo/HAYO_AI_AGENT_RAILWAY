#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Local APK Modify + Rebuild + Sign pipeline (modify_apk.py)
=========================================================================
Fully LOCAL executive arm (no Railway needed). Takes the committee APK and:
  1) decompiles it (apktool)
  2) patches premium/subscription gates (isPremium/isPro/... -> return true)
     [and optional root-detection bypass with --root]
  3) rebuilds it (apktool)
  4) zip-aligns + signs it with a fresh key (uber-apk-signer)
  5) outputs  <name>-aligned-debugSigned.apk  ready to `adb install`.


USAGE:  python modify_apk.py  committee.apk  [--root]
"""
import argparse
import os
import re
import subprocess
import sys

# ── console UTF-8 + colors ─────────────────────────────────────────────────
for s in (sys.stdout, sys.stderr):
    try: s.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
if os.name == "nt":
    try: os.system("chcp 65001 >nul")
    except Exception: pass
    try:
        import ctypes; ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception: pass
R, G, Y, C, B, X = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"

# ── locate tools (edit here if you moved them) ─────────────────────────────
TOOL_DIRS = [r"C:\Users\PT\Desktop\APK", os.path.dirname(os.path.abspath(__file__)), os.getcwd()]

def find_tool(names):
    for d in TOOL_DIRS:
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    return None

APKTOOL = find_tool(["apktool.jar"])
SIGNER = find_tool(["uber-apk-signer.jar"])

# ── premium/subscription boolean gates -> force TRUE ───────────────────────
PREMIUM_METHODS = [
    "isPremium", "isPro", "isVip", "isSubscribed", "hasSubscription", "hasPurchased",
    "isUnlocked", "isPaid", "isActivated", "isBought", "isFullVersion", "checkPremium",
    "verifyPremium", "isPremiumUser", "isProUser", "isPurchased", "isProVersion",
    "isAdFree", "isAdsRemoved", "hasPremium", "isMember", "isSubscriber", "isEntitled",
]
# root-detection gates -> force FALSE  (only with --root)
ROOT_METHODS = [
    "isRooted", "isDeviceRooted", "detectRoot", "checkRoot", "isRooted", "hasRoot",
    "isJailBroken", "isEmulator", "detectEmulator", "isDebuggable", "isDebuggerConnected",
]

def patch_smali_tree(root_dir, methods, ret_true):
    """Rewrite each boolean method <name>()Z to return a constant."""
    const = "0x1" if ret_true else "0x0"
    body = f"    .locals 1\n    const/4 v0, {const}\n    return v0\n"
    total = 0
    files = 0
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            if not fn.endswith(".smali"):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                txt = open(fp, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            changed = False
            for name in methods:
                pat = re.compile(r"(\.method\b[^\n]*\b" + re.escape(name) + r"\b[^\n]*\)Z[^\n]*\n)(.*?)(\.end method)", re.S)
                def repl(m):
                    nonlocal changed
                    changed = True
                    return m.group(1) + body + m.group(3)
                new = pat.sub(repl, txt)
                if new != txt:
                    total += len(pat.findall(txt))
                    txt = new
            if changed:
                try:
                    open(fp, "w", encoding="utf-8").write(txt)
                    files += 1
                except Exception:
                    pass
    return total, files

def run(cmd, label):
    print(C + f"[*] {label} ..." + X)
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(R + B + f"[!] {label} FAILED (exit {r.returncode})" + X)
        print(R + (r.stderr or r.stdout or "")[-1500:] + X)
        return False
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", help="Path to the committee APK")
    ap.add_argument("--root", action="store_true", help="Also bypass root/emulator detection")
    args = ap.parse_args()

    apk = os.path.abspath(args.apk)
    if not os.path.isfile(apk):
        print(R + f"[!] APK not found: {apk}" + X); sys.exit(1)
    if not APKTOOL or not SIGNER:
        print(R + f"[!] Missing tool. apktool.jar={APKTOOL}  uber-apk-signer.jar={SIGNER}" + X)
        print(Y + "    Put both .jar files in C:\\Users\\PT\\Desktop\\APK\\ (or next to this script)." + X); sys.exit(1)

    base = os.path.splitext(os.path.basename(apk))[0]
    workdir = os.path.join(os.path.dirname(apk), base + "_decoded")
    built = os.path.join(os.path.dirname(apk), base + "_modified.apk")

    print(G + B + f"\n🔧 HAYO Cipher-7 — modifying {os.path.basename(apk)}\n" + X)

    # 1) decompile
    if not run(["java", "-jar", APKTOOL, "d", apk, "-o", workdir, "-f"], "1/4  Decompiling (apktool)"):
        sys.exit(1)

    # 2) patch
    print(C + "[*] 2/4  Patching premium/subscription gates -> true ..." + X)
    p_total, p_files = patch_smali_tree(workdir, PREMIUM_METHODS, ret_true=True)
    print(G + f"    🔓 premium methods patched: {p_total} in {p_files} files" + X)
    if args.root:
        r_total, r_files = patch_smali_tree(workdir, ROOT_METHODS, ret_true=False)
        print(G + f"    🛡️  root/emulator checks neutralized: {r_total} in {r_files} files" + X)
    if p_total == 0 and not args.root:
        print(Y + "    (no local premium boolean methods found — the app may validate on the SERVER;\n"
                  "     a local patch would then be cosmetic — use the Frida cloud-MITM path instead.)" + X)

    # 3) rebuild
    if not run(["java", "-jar", APKTOOL, "b", workdir, "-o", built], "3/4  Rebuilding (apktool)"):
        sys.exit(1)

    # 4) align + sign (uber-apk-signer does BOTH)
    if not run(["java", "-jar", SIGNER, "-a", built, "--allowResign", "--overwrite"], "4/4  Aligning + signing (uber-apk-signer)"):
        sys.exit(1)

    # uber-apk-signer with --overwrite replaces `built` in place with the signed one
    out = built
    if not os.path.isfile(out):
        # fallback default naming
        cand = os.path.join(os.path.dirname(apk), base + "_modified-aligned-debugSigned.apk")
        out = cand if os.path.isfile(cand) else built

    print(G + B + "\n✅ DONE — modified, aligned, freshly signed APK:" + X)
    print(C + B + f"   {out}\n" + X)
    print(Y + "Install on the committee chairman's phone:" + X)
    print(f'   adb devices')
    print(f'   adb -s <PHONE_SERIAL> uninstall <package.name>     (original signature differs)')
    print(f'   adb -s <PHONE_SERIAL> install -r "{out}"')
    print(Y + "\nThen OPEN the app and actually USE the premium feature to prove the unlock is REAL." + X)

if __name__ == "__main__":
    main()
