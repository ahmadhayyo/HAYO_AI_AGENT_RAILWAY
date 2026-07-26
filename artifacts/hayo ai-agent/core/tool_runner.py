#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepSeek Core v5 — core/tool_runner.py
Universal tool execution framework. Can execute:
  - Python scripts (with arguments)
  - PowerShell scripts
  - ADB commands
  - curl requests
  - Arbitrary shell commands
All output captured and saved to loot/tool_outputs/.
"""
import argparse, json, os, subprocess, sys, time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_DIR = os.path.join(ROOT, "loot", "tool_outputs")
os.makedirs(OUT_DIR, exist_ok=True)

E = chr(27); G = E + "[92m"; R = E + "[91m"; Y = E + "[93m"; X = E + "[0m"


def run_python(script_path, *args, timeout=60):
    """Execute a Python script and return output."""
    cmd = [sys.executable or "python3", script_path] + list(args)
    return run_command(cmd, timeout)


def run_powershell(script_path, *args, timeout=60):
    """Execute a PowerShell script."""
    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path] + list(args)
    return run_command(cmd, timeout)


def run_adb(adb_path, device, *args, timeout=30):
    """Execute an ADB command."""
    cmd = [adb_path]
    if device:
        cmd += ["-s", device]
    cmd += list(args)
    return run_command(cmd, timeout)


def run_curl(url, method="GET", headers=None, data=None, timeout=30):
    """Execute a curl command."""
    cmd = ["curl", "-s", "-X", method]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if data:
        cmd += ["-d", json.dumps(data) if isinstance(data, dict) else data]
    cmd.append(url)
    return run_command(cmd, timeout)


def run_python_code(code, timeout=30):
    """Execute a Python code snippet."""
    cmd = [sys.executable or "python3", "-c", code]
    return run_command(cmd, timeout)


def run_command(cmd, timeout=60, shell=False):
    """Execute any command and capture output."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    cmd_label = " ".join(str(c) for c in cmd)[:80]

    result = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "command": cmd_label,
        "returncode": -1,
        "stdout": "",
        "stderr": "",
        "success": False,
        "duration_ms": 0,
    }

    start = time.time()
    try:
        p = subprocess.run(
            cmd if not shell else " ".join(str(c) for c in cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        result["returncode"] = p.returncode
        result["stdout"] = (p.stdout or "")[:50000]
        result["stderr"] = (p.stderr or "")[:10000]
        result["success"] = p.returncode == 0
    except subprocess.TimeoutExpired:
        result["stderr"] = f"TIMEOUT after {timeout}s"
    except FileNotFoundError as e:
        result["stderr"] = f"Command not found: {e}"
    except Exception as e:
        result["stderr"] = str(e)

    result["duration_ms"] = int((time.time() - start) * 1000)

    # Save output with timestamp
    import re
    safe_name = re.sub(r'[<>:"/\\|?*\s]', "_", cmd_label)[:50]
    out_path = os.path.join(OUT_DIR, f"{ts}_{safe_name}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result


def run_tool(tool_name, **kwargs):
    """Convenience wrapper: run a named tool with keyword arguments.
    Example: run_tool("cloud_raider.py", api_key="AIza...", package="com.app")
    """
    tool_map = {
        "cloud_raider.py": os.path.join(ROOT, "tools", "cloud_raider.py"),
        "ai_key_tester.py": os.path.join(ROOT, "tools", "ai_key_tester.py"),
        "premium_unlocker.py": os.path.join(ROOT, "tools", "premium_unlocker.py"),
        "decryptor.py": os.path.join(ROOT, "tools", "decryptor.py"),
        "firebase_exploit.py": os.path.join(ROOT, "tools", "firebase_exploit.py"),
    }

    script = tool_map.get(tool_name)
    if not script or not os.path.exists(script):
        return {"error": f"Tool '{tool_name}' not found"}

    args = []
    for k, v in kwargs.items():
        key = "--" + k.replace("_", "-")
        if isinstance(v, bool):
            if v:
                args.append(key)
        elif isinstance(v, (list, tuple)):
            for item in v:
                args.append(key)
                args.append(str(item))
        else:
            args.append(key)
            args.append(str(v))

    return run_python(script, *args)


def main():
    ap = argparse.ArgumentParser(description="DeepSeek Core v5 Tool Runner")
    ap.add_argument("--tool", help="Tool name (cloud_raider.py, ai_key_tester.py, etc.)")
    ap.add_argument("--cmd", help="Raw command to run")
    ap.add_argument("--python", help="Python code to execute")
    ap.add_argument("--adb", nargs="+", help="ADB command parts")
    ap.add_argument("--device", help="ADB device serial")
    ap.add_argument("--adb-path", default=os.environ.get("HAYO_ADB", "adb"),
                    help="ADB executable path")
    ap.add_argument("--timeout", type=int, default=60)
    a = ap.parse_args()

    if a.tool:
        kwargs = {}
        # Parse remaining args as key=value pairs
        for arg in a.tool.split():
            if "=" in arg:
                k, v = arg.split("=", 1)
                kwargs[k] = v
        result = run_tool(a.tool.split()[0], **kwargs)
    elif a.cmd:
        result = run_command(a.cmd.split(), a.timeout)
    elif a.python:
        result = run_python_code(a.python, a.timeout)
    elif a.adb:
        result = run_adb(a.adb_path, a.device, *a.adb, timeout=a.timeout)
    else:
        print("No action specified. Use --tool, --cmd, --python, or --adb")
        return

    print(f"{G if result.get('success') else Y}  [tool] {result.get('command', '')[:60]}X")
    print(f"  exit: {result.get('returncode')}  duration: {result.get('duration_ms', 0)}ms")
    if result.get("stdout"):
        print(result["stdout"][:2000])


if __name__ == "__main__":
    main()
