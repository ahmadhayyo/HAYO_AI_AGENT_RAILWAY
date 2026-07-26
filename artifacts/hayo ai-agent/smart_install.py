#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Smart APK Installer (smart_install.py)
=====================================================
Fixes the #1 cause of "There is a problem parsing the package": SPLIT APKs /
App Bundles. Modern apps ship as base.apk + config.<abi>.apk + config.<dpi>.apk +
config.<lang>.apk (or as an .xapk/.apks/.apkm zip). Installing ONE split alone
always fails. This tool:

  • single .apk            -> adb install -r -d
  • folder of split .apks  -> re-sign ALL with ONE key -> adb install-multiple
  • .xapk/.apks/.apkm zip  -> extract -> re-sign ALL -> adb install-multiple

USAGE:
  python smart_install.py  app.apk
  python smart_install.py  C:/path/to/splits_folder
  python smart_install.py  app.xapk
  optional:  -D emulator-5554   (target device)   --package com.x (uninstall first)
"""
import argparse, glob, os, subprocess, sys, tempfile, zipfile

from modify_apk import find_tool, SIGNER, R, G, Y, C, B, X

ADB = None
for _c in [r"C:\Users\PT\Downloads\platform-tools\adb.exe", "adb"]:
    if _c == "adb" or os.path.isfile(_c):
        ADB = _c; break

def sh(cmd, timeout=300):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)

def sign_folder(folder):
    """Sign every .apk in the folder with the SAME debug key (required for splits)."""
    if not SIGNER:
        print(Y + "  [*] uber-apk-signer.jar not found — will try installing unsigned/original splits." + X)
        return
    print(C + "  [*] Signing all splits with one key (uber-apk-signer) ..." + X)
    r = sh(["java", "-jar", SIGNER, "-a", folder, "--allowResign", "--overwrite"])
    if r.returncode != 0:
        print(Y + "  [*] signer warning:\n" + (r.stderr or r.stdout)[-600:] + X)

def collect_apks(folder):
    return sorted(glob.glob(os.path.join(folder, "*.apk")))

def install_multiple(apks, dev, package):
    if package:
        print(C + f"  [*] Removing any existing '{package}' (signature will differ) ..." + X)
        sh(base_adb(dev) + ["uninstall", package])
    print(C + f"  [*] adb install-multiple ({len(apks)} splits) ..." + X)
    r = sh(base_adb(dev) + ["install-multiple", "-r", "-d"] + apks, timeout=600)
    out = (r.stdout + r.stderr).strip()
    print(out[-800:])
    return "Success" in out

def install_single(apk, dev, package):
    if package:
        sh(base_adb(dev) + ["uninstall", package])
    print(C + "  [*] adb install ..." + X)
    r = sh(base_adb(dev) + ["install", "-r", "-d", apk], timeout=600)
    out = (r.stdout + r.stderr).strip()
    print(out[-800:])
    return "Success" in out

def base_adb(dev):
    return [ADB] + (["-s", dev] if dev else [])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="single .apk | folder of splits | .xapk/.apks/.apkm")
    ap.add_argument("-D", "--device", help="adb serial (e.g. emulator-5554)")
    ap.add_argument("--package", help="package name to uninstall first (recommended)")
    ap.add_argument("--no-resign", action="store_true", help="do not re-sign (use as-is)")
    args = ap.parse_args()

    p = os.path.abspath(args.path)
    if not os.path.exists(p):
        print(R + f"[!] Not found: {p}" + X); sys.exit(1)
    if not ADB:
        print(R + "[!] adb not found." + X); sys.exit(1)

    print(G + B + f"\n📲 HAYO Smart Install — {os.path.basename(p)}\n" + X)

    # Case 1: a bundle zip (.xapk/.apks/.apkm) -> extract to temp folder
    if os.path.isfile(p) and p.lower().endswith((".xapk", ".apks", ".apkm", ".zip")):
        tmp = tempfile.mkdtemp(prefix="hayo_splits_")
        print(C + f"  [*] Extracting bundle to {tmp} ..." + X)
        with zipfile.ZipFile(p) as z:
            for n in z.namelist():
                if n.lower().endswith(".apk"):
                    # flatten: write every split into the tmp root by basename
                    with z.open(n) as src, open(os.path.join(tmp, os.path.basename(n)), "wb") as dst:
                        dst.write(src.read())
        if not args.no_resign:
            sign_folder(tmp)
        apks = collect_apks(tmp)
        signed = [a for a in apks if a.endswith("-aligned-debugSigned.apk")]
        apks = signed if signed else apks
        ok = install_multiple(apks, args.device, args.package)

    # Case 2: a folder of splits
    elif os.path.isdir(p):
        if not args.no_resign:
            sign_folder(p)
        apks = collect_apks(p)
        # prefer the signed copies if present
        signed = [a for a in apks if a.endswith("-aligned-debugSigned.apk")]
        apks = signed if signed else apks
        if not apks:
            print(R + "  [!] No .apk files in the folder." + X); sys.exit(1)
        ok = install_multiple(apks, args.device, args.package) if len(apks) > 1 else install_single(apks[0], args.device, args.package)

    # Case 3: single apk — but detect nearby config.* splits automatically
    else:
        folder = os.path.dirname(p)
        siblings = [a for a in collect_apks(folder) if os.path.basename(a).lower().startswith(("config.", "split_")) or "config." in os.path.basename(a).lower()]
        if siblings:
            print(Y + f"  [!] Detected {len(siblings)} sibling split(s) — this app is SPLIT; installing ALL together." + X)
            group = sorted(set([p] + siblings))
            if not args.no_resign:
                sign_folder(folder)
                group = [a.replace(".apk", "-aligned-debugSigned.apk") if os.path.isfile(a.replace(".apk", "-aligned-debugSigned.apk")) else a for a in group]
            ok = install_multiple(group, args.device, args.package)
        else:
            ok = install_single(p, args.device, args.package)

    if ok:
        print(G + B + "\n✅ INSTALLED SUCCESSFULLY. Open the app on the device.\n" + X)
    else:
        print(R + B + "\n[!] Install failed. Common fixes:" + X)
        print(Y + "  • Make sure you have ALL splits incl. the BASE apk (the biggest one).\n"
                  "  • Pass --package <name> to uninstall the original first.\n"
                  "  • For a phone: enable 'Install via USB' + 'USB debugging' in Developer Options." + X)

if __name__ == "__main__":
    main()
