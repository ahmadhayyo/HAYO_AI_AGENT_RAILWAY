#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepSeek Core v5 — deepseek_pipeline.py (Production Ready)
Fixed argparse to include --aggressive flag.
"""
import argparse, os, subprocess, sys, time
from datetime import datetime

# Fix for Windows console encoding
if os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8')

HERE = os.path.dirname(os.path.abspath(__file__))

def log(tag, msg):
    print(f"\n[PIPELINE] [{datetime.now().strftime('%H:%M:%S')}] [{tag}] {msg}")

def run_step(cmd, tag):
    log(tag, f"STARTING PHASE: {' '.join(cmd)}")
    try:
        # Use current python executable
        cmd[0] = sys.executable
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", cwd=HERE)
        for line in process.stdout:
            print(f"  [{tag}] {line.strip()}")
        process.wait()
        if process.returncode == 0:
            log(tag, f"PHASE COMPLETED SUCCESSFULLY.")
            return True
        else:
            log(tag, f"PHASE FAILED (Exit Code: {process.returncode})")
            return False
    except Exception as e:
        log(tag, f"ERROR: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="DeepSeek Core v5 Automated Pipeline")
    parser.add_argument("apk", help="Path to the APK file to test", nargs='?', default="target.apk")
    parser.add_argument("--package", help="Target package name", required=True)
    parser.add_argument("--device", default="emulator-5554", help="ADB device serial")
    parser.add_argument("--duration", type=int, default=60, help="Duration for dynamic phase")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive exploitation")
    args = parser.parse_args()

    print("="*60)
    print(f" DEEPSEEK CORE v5 - AUTOMATED MISSION CONTROL")
    print(f" Target: {args.package}")
    print(f" Mode: {'AGGRESSIVE' if args.aggressive else 'STANDARD'}")
    print("="*60)

    # Step 1: Static Intelligence
    run_step([sys.executable, "hayo_auto.py", "--package", args.package], "STATIC")

    # Step 2: Dynamic Interception
    log("PIPELINE", "Transitioning to Dynamic Phase...")
    time.sleep(2)
    run_step([sys.executable, "orchestrator.py", "--full-assault", args.package, "--device", args.device, "--duration", str(args.duration)], "DYNAMIC")

    # Step 3: Brain Exploitation
    log("PIPELINE", "Handing over to DeepSeek Brain for final exploitation...")
    time.sleep(2)
    brain_cmd = [sys.executable, "core/brain.py", "--package", args.package, "--duration", "30"]
    if args.aggressive:
        brain_cmd.append("--aggressive")
    run_step(brain_cmd, "BRAIN")

    print("\n" + "="*60)
    print(" MISSION COMPLETE. ALL FINDINGS IN loot/ FOLDER.")
    print("="*60)

if __name__ == "__main__":
    main()
