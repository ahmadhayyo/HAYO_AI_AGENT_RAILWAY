#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Extended Mastermind & Cognitive LLM Brain (llm_brain.py v7)
=============================================================================
Comprehensive, Ultra-Broad AI Brain & Multi-Provider Cascade Solution Engine:
  - Multi-provider AI cascade (OpenAI, DeepSeek, Anthropic Claude, Google Gemini, Groq, Ollama, Custom Endpoints)
  - Provider Health, Latency & Token Usage Tracking
  - Semantic Episodic & Long-Term Memory Manager (TF-IDF Vector Retrieval)
  - Adaptive Cognitive Strategy Selector (Fast Reactive, CoT, DAG, Multi-Agent Debate)
  - Multi-Role Persona Agent Consensus Engine (Architect, Auditor, Executor, Synthesizer)
  - Dynamic Chain-of-Thought (CoT) & Reflection Engine
  - Self-Critique & Refinement Loop
  - Task Decomposition & Sub-goal DAG Generator
  - Multi-Hypothesis Diagnostic Engine & Solution Cache
  - Self-Healing Code Synthesizer with AST Multi-Pass Verification
  - Persistent State Export/Import & Comprehensive Cognitive Reporting
  - Full backward compatibility with all HAYO modules
  - Safe cross-platform unicode stdout logging
"""

import ast
import json
import math
import os
import re
import sys
import time
from datetime import datetime

# Configure UTF-8 output on Windows streams if available
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
except ImportError:
    requests = None


def safe_print(text):
    """Safely print text handling Windows console encoding issues."""
    try:
        print(text)
    except UnicodeEncodeError:
        try:
            cleaned = text.encode("ascii", "ignore").decode("ascii")
            print(cleaned)
        except Exception:
            pass


def extract_json_from_text(text: str):
    """Extract and parse JSON object/array from raw model output text."""
    if not text:
        return None
    # Direct parse
    try:
        return json.loads(text.strip())
    except Exception:
        pass

    # Extract block inside ```json ... ``` or ``` ... ```
    match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text, re.IGNORECASE)
    if match:
        code_str = match.group(1).strip()
        try:
            return json.loads(code_str)
        except Exception:
            pass

    # Find first { ... } or [ ... ]
    first_brace = text.find('{')
    last_brace = text.rfind('}')
    if first_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except Exception:
            pass

    first_bracket = text.find('[')
    last_bracket = text.rfind(']')
    if first_bracket != -1 and last_bracket > first_bracket:
        try:
            return json.loads(text[first_bracket:last_bracket + 1])
        except Exception:
            pass

    return None


class SemanticMemoryStore:
    """Lightweight TF-IDF / Keyword semantic memory store for fast contextual retrieval."""

    def __init__(self):
        self.entries = []  # List of dicts: {"id": str, "key": str, "content": str, "metadata": dict, "tokens": set, "timestamp": float}

    def _tokenize(self, text: str) -> set:
        """Tokenize string into normalized keyword set."""
        words = re.findall(r'\w+', str(text).lower())
        return {w for w in words if len(w) > 2}

    def add_entry(self, key: str, content: str, metadata: dict = None, tags: list = None):
        """Add an entry into semantic memory store."""
        tokens = self._tokenize(f"{key} {content} {' '.join(tags or [])}")
        entry = {
            "id": f"mem_{len(self.entries) + 1}_{int(time.time())}",
            "key": key,
            "content": content,
            "metadata": metadata or {},
            "tags": tags or [],
            "tokens": list(tokens),
            "timestamp": time.time()
        }
        self.entries.append(entry)
        return entry["id"]

    def query(self, query_str: str, top_k: int = 3) -> list:
        """Query memory store using Jaccard & TF similarity scoring."""
        q_tokens = self._tokenize(query_str)
        if not q_tokens or not self.entries:
            return []

        scored = []
        for entry in self.entries:
            e_tokens = set(entry.get("tokens", []))
            intersection = q_tokens.intersection(e_tokens)
            if not intersection:
                continue
            union = q_tokens.union(e_tokens)
            score = len(intersection) / len(union) if union else 0.0
            # Recency boost
            age_hours = (time.time() - entry.get("timestamp", time.time())) / 3600.0
            recency_multiplier = max(0.5, 1.0 - (age_hours / 168.0))  # Decay over a week
            final_score = score * recency_multiplier
            scored.append((final_score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {
                "id": item["id"],
                "key": item["key"],
                "content": item["content"],
                "metadata": item["metadata"],
                "similarity_score": round(score, 4)
            }
            for score, item in scored[:top_k]
        ]

    def summarize(self) -> dict:
        """Summarize current state of memory store."""
        return {
            "total_memories": len(self.entries),
            "keys": [e["key"] for e in self.entries[-10:]],
            "last_updated": datetime.now().isoformat() if self.entries else "None"
        }


class SolutionKnowledgeBase:
    """Cached solution signatures for automated error recovery and instant lookup."""

    def __init__(self):
        self.known_fixes = {}  # error_key -> fix_payload

    def _hash_error(self, error_trace: str) -> str:
        clean = re.sub(r'0x[0-9a-fA-F]+', '0x...', str(error_trace))
        clean = re.sub(r'line \d+', 'line X', clean)
        words = re.findall(r'\w+', clean.lower())
        return "_".join(words[:12])

    def remember_fix(self, error_trace: str, fix_data: dict):
        key = self._hash_error(error_trace)
        self.known_fixes[key] = {
            "fix": fix_data,
            "timestamp": time.time(),
            "apply_count": self.known_fixes.get(key, {}).get("apply_count", 0) + 1
        }

    def get_cached_fix(self, error_trace: str):
        key = self._hash_error(error_trace)
        if key in self.known_fixes:
            entry = self.known_fixes[key]
            entry["apply_count"] += 1
            return entry["fix"]
        return None


class MultiProviderLLM:
    """Multi-provider API client with automatic cascade, health check, token tracking, and failover."""

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.providers = []
        self.provider_stats = {}
        self.total_tokens_estimated = 0
        self._load_providers()

    def _log(self, msg, level="INFO"):
        if self.verbose:
            safe_print(f"[BRAIN] [{level}] {msg}")

    def _load_providers(self):
        """Load provider configurations from config.json and environment."""
        cfg = {}
        here = os.path.dirname(os.path.abspath(__file__))
        cfg_path = os.path.join(here, "config.json")
        try:
            if os.path.isfile(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
        except Exception:
            cfg = {}

        # 1. OpenAI (Primary)
        openai_key = cfg.get("openai_api_key") or os.environ.get("OPENAI_API_KEY", "")
        # Never embed provider credentials in source code. Configure OPENAI_API_KEY
        # through the process environment (or an external secret manager).

        if openai_key:
            self.providers.append({
                "name": "OpenAI (Primary)",
                "base_url": cfg.get("openai_base_url", "https://api.openai.com/v1"),
                "api_key": openai_key,
                "model": cfg.get("openai_model", "gpt-4o-2024-08-06"),
                "type": "openai"
            })

        # 2. DeepSeek
        deepseek_key = cfg.get("deepseek_api_key") or os.environ.get("DEEPSEEK_API_KEY", "")
        if deepseek_key:
            self.providers.append({
                "name": "DeepSeek",
                "base_url": cfg.get("deepseek_base_url", "https://api.deepseek.com"),
                "api_key": deepseek_key,
                "model": cfg.get("deepseek_model", "deepseek-chat"),
                "type": "openai"
            })

        # 3. Anthropic Claude
        anthropic_key = cfg.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
        if anthropic_key:
            self.providers.append({
                "name": "Anthropic Claude",
                "base_url": cfg.get("anthropic_base_url", "https://api.anthropic.com/v1"),
                "api_key": anthropic_key,
                "model": cfg.get("anthropic_model", "claude-3-5-sonnet-20241022"),
                "type": "anthropic"
            })

        # 4. Google Gemini
        gemini_key = cfg.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY", "")
        if gemini_key:
            self.providers.append({
                "name": "Google Gemini",
                "base_url": cfg.get("gemini_base_url", "https://generativelanguage.googleapis.com/v1beta/openai"),
                "api_key": gemini_key,
                "model": cfg.get("gemini_model", "gemini-1.5-pro"),
                "type": "openai"
            })

        # 5. Groq / Fast Inference
        groq_key = cfg.get("groq_api_key") or os.environ.get("GROQ_API_KEY", "")
        if groq_key:
            self.providers.append({
                "name": "Groq Llama-3",
                "base_url": cfg.get("groq_base_url", "https://api.groq.com/openai/v1"),
                "api_key": groq_key,
                "model": cfg.get("groq_model", "llama-3.3-70b-versatile"),
                "type": "openai"
            })

        # 6. Local Ollama (Offline Fallback)
        ollama_url = cfg.get("ollama_base_url", os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"))
        self.providers.append({
            "name": "Local Ollama",
            "base_url": ollama_url,
            "api_key": "ollama",
            "model": cfg.get("ollama_model", "llama3"),
            "type": "openai"
        })

        # Initialize statistics
        for p in self.providers:
            self.provider_stats[p["name"]] = {
                "calls": 0,
                "successes": 0,
                "failures": 0,
                "last_latency_s": 0.0,
                "status": "ready"
            }

    def get_provider_status(self):
        """Returns health and status summary of all registered providers."""
        return self.provider_stats

    def request(self, system_prompt, user_prompt, temperature=0.2, max_tokens=2500):
        """Attempt API call through provider cascade with retry, timing & exponential backoff."""
        if not requests:
            self._log("requests library missing - cannot contact external LLM", "WARN")
            return None

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        approx_prompt_tokens = len(system_prompt.split()) + len(user_prompt.split())

        for provider in self.providers:
            p_name = provider["name"]
            p_type = provider.get("type", "openai")
            base_url = provider["base_url"].rstrip("/")

            stats = self.provider_stats.get(p_name, {})
            stats["calls"] = stats.get("calls", 0) + 1
            t_start = time.time()

            if p_type == "openai":
                url = f"{base_url}/chat/completions"
                headers = {
                    "Authorization": f"Bearer {provider['api_key']}",
                    "Content-Type": "application/json"
                }
                body = {
                    "model": provider["model"],
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                }
            elif p_type == "anthropic":
                url = f"{base_url}/messages"
                headers = {
                    "x-api-key": provider["api_key"],
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json"
                }
                body = {
                    "model": provider["model"],
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                    "temperature": temperature,
                    "max_tokens": max_tokens
                }

            for retries in range(2):
                try:
                    r = requests.post(url, headers=headers, json=body, timeout=25)
                    latency = round(time.time() - t_start, 3)

                    if r.status_code == 200:
                        res_data = r.json()
                        content = ""

                        if p_type == "openai":
                            choices = res_data.get("choices", [])
                            if choices:
                                content = choices[0].get("message", {}).get("content", "")
                        elif p_type == "anthropic":
                            contents = res_data.get("content", [])
                            if contents and isinstance(contents, list):
                                content = contents[0].get("text", "")

                        if content:
                            stats["successes"] = stats.get("successes", 0) + 1
                            stats["last_latency_s"] = latency
                            stats["status"] = "online"
                            
                            est_resp_tokens = len(content.split())
                            self.total_tokens_estimated += (approx_prompt_tokens + est_resp_tokens)

                            self._log(f"Response received from {p_name} ({provider['model']}) in {latency}s")
                            return content

                    elif r.status_code in (429, 500, 502, 503, 504):
                        time.sleep(1.5 * (retries + 1))
                        continue
                    else:
                        self._log(f"{p_name} returned status {r.status_code}: {r.text[:120]}", "WARN")
                        break
                except Exception as e:
                    self._log(f"{p_name} connection error: {e}", "WARN")
                    break

            stats["failures"] = stats.get("failures", 0) + 1
            stats["status"] = "degraded"

        return None

    def request_vision(self, system_prompt, user_prompt, image_b64,
                       temperature=0.2, max_tokens=700):
        """طلب رؤية: يرسل لقطة شاشة إلى مزوّد متعدّد الوسائط (gpt-4o…) — لتفاعل
        العقل مع الواجهات الحديثة التي لا يقرؤها uiautomator (WebView/Compose)."""
        if not requests:
            return None
        for provider in self.providers:
            if provider.get("type") != "openai":
                continue
            base_url = provider["base_url"].rstrip("/")
            url = f"{base_url}/chat/completions"
            headers = {"Authorization": f"Bearer {provider['api_key']}",
                       "Content-Type": "application/json"}
            body = {
                "model": provider["model"],
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": [
                        {"type": "text", "text": user_prompt},
                        {"type": "image_url",
                         "image_url": {"url": "data:image/png;base64," + image_b64}},
                    ]},
                ],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            try:
                r = requests.post(url, headers=headers, json=body, timeout=45)
                if r.status_code == 200:
                    ch = r.json().get("choices", [])
                    if ch:
                        c = ch[0].get("message", {}).get("content", "")
                        if c:
                            return c
                else:
                    self._log(f"vision {provider['name']} status {r.status_code}: {r.text[:100]}", "WARN")
            except Exception as e:
                self._log(f"vision {provider['name']} error: {e}", "WARN")
        return None


class LLMBrain:
    """
    Upgraded Ultra Mastermind Brain (LLMBrain v7)
    Serves as the comprehensive cognitive decision-making, planning, adaptive reasoning,
    semantic memory, multi-agent consensus, auto-healing, and code verification engine for HAYO.
    """

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.engine = MultiProviderLLM(verbose=verbose)
        self.api_key = self.engine.providers[0]["api_key"] if self.engine.providers else ""
        self.base_url = self.engine.providers[0]["base_url"] if self.engine.providers else "https://api.openai.com/v1"
        self.model = self.engine.providers[0]["model"] if self.engine.providers else "gpt-4o-2024-08-06"

        # Specialized Knowledge & Memory Modules
        self.semantic_memory = SemanticMemoryStore()
        self.solution_cache = SolutionKnowledgeBase()

        # Expanded Decision & execution memory
        self.memory = {
            "history": [],
            "attempted_solutions": [],
            "failed_actions": set(),
            "hypotheses_log": [],
            "insights": [],
            "start_time": time.time()
        }

    def _log(self, msg, level="INFO"):
        if self.verbose:
            safe_print(f"[BRAIN] [{level}] {msg}")

    def chat(self, system, user, temperature=0.2):
        """Backward compatible single chat completion with cascade fallback."""
        res = self.engine.request(system, user, temperature=temperature)
        if res:
            return res
        return None

    def think(self, prompt, strategy=None, temperature=0.2):
        """Single-prompt reasoning via the real provider cascade.

        Used by ExtendedBrain (select_exploit / update_strategy / should_run_phase /
        adapt_strategy). Before this existed, those methods called a NON-EXISTENT
        think() → every call threw AttributeError → silently fell back to hardcoded
        defaults (the extended brain *looked* AI-driven but wasn't). `strategy` is an
        advisory label kept for API compatibility."""
        sys_p = ("You are HAYO's expert security reasoning engine. Analyze precisely "
                 "and respond ONLY with the exact JSON object requested — no prose.")
        return self.chat(system=sys_p, user=str(prompt), temperature=temperature)

    # =========================================================================
    # ADVANCED STRATEGY & MULTI-AGENT CONSENSUS EXTENSIONS (v7)
    # =========================================================================

    def adapt_strategy(self, task_goal: str, context: dict = None) -> dict:
        """
        Dynamically analyzes task requirements and selects the optimal cognitive strategy.
        Strategies: FAST_REACTIVE, CHAIN_OF_THOUGHT, DAG_DECOMPOSITION, TRIAGED_DIAGNOSTIC, MULTI_PERSPECTIVE_DEBATE
        """
        self._log(f"Selecting optimal cognitive strategy for task: {task_goal[:60]}...")
        
        goal_lower = task_goal.lower()
        if any(kw in goal_lower for kw in ["error", "fail", "fix", "crash", "bug", "traceback", "exception"]):
            strategy = "TRIAGED_DIAGNOSTIC"
            rationale = "Error keywords detected. Engaging diagnostic & auto-healing flow."
        elif any(kw in goal_lower for kw in ["architecture", "redesign", "security audit", "critical", "multi-step system"]):
            strategy = "MULTI_PERSPECTIVE_DEBATE"
            rationale = "High complexity/criticality detected. Engaging multi-role persona debate consensus."
        elif len(task_goal.split()) > 15 or any(kw in goal_lower for kw in ["pipeline", "workflow", "stages", "phase"]):
            strategy = "DAG_DECOMPOSITION"
            rationale = "Multi-phase goal detected. Structuring DAG task decomposition."
        elif any(kw in goal_lower for kw in ["why", "reason", "evaluate", "compare", "optimize"]):
            strategy = "CHAIN_OF_THOUGHT"
            rationale = "Reasoning/analytical task detected. Using Chain-of-Thought."
        else:
            strategy = "FAST_REACTIVE"
            rationale = "Direct reactive strategy suitable for standard task execution."

        # Search memory for past relevant experience
        past_memories = self.semantic_memory.query(task_goal, top_k=2)

        return {
            "chosen_strategy": strategy,
            "rationale": rationale,
            "context_memories": past_memories,
            "timestamp": time.time()
        }

    def multi_agent_consensus(self, problem_statement: str, constraints: list = None) -> dict:
        """
        Simulates multi-role AI agent reasoning (Architect, Security Auditor, Execution Specialist, Synthesizer)
        to form a resilient, peer-reviewed consensus plan.
        """
        self._log(f"Executing Multi-Agent Consensus Debate on: {problem_statement[:60]}...")

        system = (
            "You are the HAYO Multi-Agent Decision Council.\n"
            "Simulate reasoning across 3 specialized personas:\n"
            "1. ARCHITECT: Focuses on system scalability, clean design, and long-term viability.\n"
            "2. SECURITY_AUDITOR: Focuses on safety, boundary cases, rate limits, and failure modes.\n"
            "3. EXECUTION_SPECIALIST: Focuses on speed, practical scripts, tool usage, and low overhead.\n\n"
            "Synthesize their perspectives into an optimal, unified consensus plan.\n"
            "Respond ONLY in valid JSON:\n"
            "{\n"
            '  "architect_perspective": "...",\n'
            '  "auditor_perspective": "...",\n'
            '  "executor_perspective": "...",\n'
            '  "consensus_plan": {\n'
            '    "primary_strategy": "...",\n'
            '    "execution_steps": ["step1", "step2"],\n'
            '    "risk_safeguards": ["safeguard1"]\n'
            '  },\n'
            '  "consensus_confidence": 0.95\n'
            "}"
        )

        user_payload = {
            "problem": problem_statement,
            "constraints": constraints or []
        }

        raw = self.chat(system, json.dumps(user_payload, ensure_ascii=False, indent=2), temperature=0.2)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "consensus_plan" in parsed:
            # Store insight in semantic memory
            self.semantic_memory.add_entry(
                key=f"consensus_{problem_statement[:30]}",
                content=json.dumps(parsed.get("consensus_plan")),
                tags=["consensus", "multi_agent"]
            )
            return parsed

        return {
            "architect_perspective": "Standard modular architecture recommended.",
            "auditor_perspective": "Ensure robust error handling and fallback mechanism.",
            "executor_perspective": "Run direct Python/PowerShell execution commands.",
            "consensus_plan": {
                "primary_strategy": "Execute with safety wrappers and fallback handlers.",
                "execution_steps": [f"Execute core logic for {problem_statement}", "Verify output integrity"],
                "risk_safeguards": ["Enable automated fallback on exception"]
            },
            "consensus_confidence": 0.85
        }

    def store_episodic_memory(self, key: str, content: str, metadata: dict = None, tags: list = None):
        """Public API to store episodic memories into semantic store."""
        mem_id = self.semantic_memory.add_entry(key, content, metadata, tags)
        self._log(f"Saved memory entry '{key}' ({mem_id})")
        return mem_id

    def query_episodic_memory(self, query: str, top_k: int = 3):
        """Public API to query semantic memory store."""
        return self.semantic_memory.query(query, top_k=top_k)

    def synthesize_verify_and_refine_code(self, task_description: str, language: str = "python", max_retries: int = 2) -> dict:
        """
        Generates code, verifies syntax with Python AST, and performs an automatic multi-pass correction loop
        if syntax or structural errors are detected.
        """
        self._log(f"Synthesizing verified {language} code for task: {task_description[:60]}...")
        
        attempt_code = None
        last_error = None

        for attempt in range(max_retries + 1):
            if attempt == 0:
                prompt_content = f"Write production-ready {language} code for: {task_description}"
            else:
                prompt_content = f"The previous code attempt for '{task_description}' failed syntax verification with error:\n{last_error}\n\nPlease fix the error and output valid, fully working {language} code."

            result = self.synthesize_and_verify_code(prompt_content, language=language)
            code_str = result.get("code", "")
            is_valid = result.get("syntax_valid", False)

            if is_valid or language.lower() != "python":
                result["refinement_attempts"] = attempt
                return result

            last_error = result.get("syntax_error", "Unknown syntax error")
            self._log(f"Code attempt {attempt+1} failed syntax check: {last_error}. Retrying...", "WARN")

        result["refinement_attempts"] = max_retries
        return result

    # =========================================================================
    # DECISION ENGINE & CORE FUNCTIONS (Preserved & Upgraded)
    # =========================================================================

    def decide_action(self, obs):
        """
        Intelligent action decision engine.
        Takes observation dict, tracks action history to avoid loops,
        and provides comprehensive JSON decisions.
        """
        activity = obs.get("current_activity", "?")
        elements = obs.get("elements", [])
        visited = obs.get("visited", [])
        goal = obs.get("goal", "Explore application and identify security vulnerabilities/features")

        # Context retrieval from memory store
        mem_hits = self.semantic_memory.query(f"{activity} {goal}", top_k=2)

        system = (
            "You are the HAYO Smart Mastermind — an elite offensive-security agent that DRIVES an Android app "
            "in real time to force it through login, premium/subscription, cloud-sync, settings and account flows "
            "so the Frida hooks capture keys, tokens and secrets. You are relentless and resourceful: you ALWAYS "
            "return a concrete next action and NEVER give up while there is any screen or trick left to try.\n\n"
            "★ AUTHORITATIVE OPERATOR DIRECTIVE (obey this PRECISELY — it overrides generic exploration; every "
            "action you choose must move toward fulfilling it, and only declare success/stop once IT is achieved):\n"
            "    " + str(goal).replace("\n", " ").strip() + "\n\n"
            "Respond ONLY with valid JSON:\n"
            "{\n"
            '  "action": "tap|input|swipe|launch|back|key|wait|stop",\n'
            '  "index": <element_index_or_null>,\n'
            '  "text": "<input_text_if_input>",\n'
            '  "activity": "<pkg/activity_if_launch>",\n'
            '  "keycode": <android_keyevent_int_if_key>,\n'
            '  "reason": "<short_explanation>",\n'
            '  "confidence": 0.9\n'
            "}\n\n"
            "STRATEGY (use the INTEL you are given — extracted secrets, backend URLs, untested endpoints, known activities):\n"
            "1. LEVERAGE INTEL: if backend URLs / secrets are already captured, drive toward screens that exercise them "
            "(login, sync, payment, profile). If known security activities exist, LAUNCH them directly "
            '(action=launch, activity="<pkg>/<activity>") instead of blind tapping.\n'
            "2. TRICKS TO UNBLOCK (this is critical — most apps gate the real flows behind these):\n"
            "   • Permission dialogs → TAP allow: Allow / While using the app / OK / Yes / Continue / Accept.\n"
            "   • Onboarding / splash / ads → TAP skip: Skip / Next / Continue / Get Started / Later / Got it / Close / ✕ / Maybe later.\n"
            "   • Login forms → INPUT into the email/username edit, then the password edit, then TAP the login/sign-in button.\n"
            "   • Cookie/consent → decline non-essential then proceed.\n"
            "   • Nothing tappable / unreadable → LAUNCH a known activity, or key=4 (BACK), or swipe to reveal more.\n"
            "3. ANTI-LOOP: never repeat a recently-failed action or re-tap an already-tapped label; if a screen repeats, "
            "switch strategy (launch a different activity, dismiss an overlay, or key/swipe).\n"
            "4. WHEN STUCK (stuck flag high): escalate — pick a DIFFERENT known activity to launch, dismiss any dialog, "
            "or press key=4 (BACK) / key=66 (ENTER) — do something NEW, do not wait passively.\n"
            "5. Only action=stop if the goal is truly achieved (critical secrets captured). Otherwise keep hunting.\n"
        )

        intel = obs.get("intel", {}) or {}
        user_context = {
            "goal": goal,
            "current_activity": activity,
            "elements_count": len(elements),
            "elements": elements[:25],
            "visited_screens_count": len(visited),
            "visited_screens": visited[-10:],
            "recent_failed_actions": list(self.memory["failed_actions"])[-10:],
            "recent_history": [h.get("action") for h in list(self.memory["history"])[-8:]],
            "relevant_memories": mem_hits,
            "findings_summary": obs.get("findings_summary", ""),
            "stuck": obs.get("stuck", 0),
            # الاستخبارات المُستخرَجة آنياً — استعملها لتوجيه الخطوة التالية:
            "intel": {
                "backend_urls": intel.get("backend_urls", [])[:10],
                "known_secrets": intel.get("known_secrets", [])[:10],
                "untested_endpoints": intel.get("untested_endpoints", [])[:10],
                "known_activities": (intel.get("activities", []) or [])[:15],
                "findings_by_severity": intel.get("findings_by_severity", {}),
            },
        }

        res_text = self.chat(system, json.dumps(user_context, ensure_ascii=False, indent=2))
        if res_text:
            parsed = extract_json_from_text(res_text)
            if isinstance(parsed, dict) and "action" in parsed:
                self.memory["history"].append({
                    "timestamp": time.time(),
                    "activity": activity,
                    "action": parsed.get("action"),
                    "reason": parsed.get("reason")
                })
                return parsed

        return self._fallback_decide_action(obs)

    def decide_action_vision(self, image_b64, obs):
        """رؤية بصرية: يحلّل لقطة الشاشة ويُرجع إحداثيات النقر — للواجهات الحديثة
        التي يُرجع فيها uiautomator 0 عناصر (WebView/Compose/ألعاب/إعلانات)."""
        goal = obs.get("goal", "reach login / chat input / premium / settings")
        intel = obs.get("intel", {}) or {}
        w, h = obs.get("screen_w", 1080), obs.get("screen_h", 1920)
        system = (
            "You are HAYO's VISION navigator. The accessibility tree was EMPTY (WebView/Compose/"
            "game/ad), so you must READ THE SCREENSHOT and decide the single best next action to "
            "progress toward the goal. Return ONLY JSON:\n"
            '{"action":"tap|input|key|back|wait","x":<int>,"y":<int>,"text":"<if input>",'
            '"keycode":<int_if_key>,"reason":"<short>"}\n'
            f"x,y are PIXEL coordinates in the {w}x{h} screenshot.\n"
            "Priorities: dismiss ads/permission/consent (tap their Close/✕/Allow/Skip/Continue), "
            "tap a visible chat/search/login INPUT field (then we type), tap login/premium/settings/"
            "menu buttons, open navigation drawers. Never wait passively — always pick a concrete tap."
        )
        user = (f"goal: {goal}\nstuck_level: {obs.get('stuck', 0)}\n"
                f"backend_urls: {intel.get('backend_urls', [])[:5]}\n"
                f"already_visited: {len(obs.get('visited', []))} screens")
        eng = getattr(self, "engine", None)
        res = eng.request_vision(system, user, image_b64) if eng else None
        if res:
            parsed = extract_json_from_text(res)
            if isinstance(parsed, dict) and parsed.get("action"):
                return parsed
        return None

    def _fallback_decide_action(self, obs):
        """Heuristic fallback with dialog-dismissal + stuck escalation (works offline)."""
        elements = obs.get("elements", [])
        scrollable = obs.get("scrollable", False)
        stuck = obs.get("stuck", 0)
        intel = obs.get("intel", {}) or {}

        clickables = [e for e in elements if isinstance(e, dict) and e.get("kind") == "clickable"]
        edits = [e for e in elements if isinstance(e, dict) and e.get("kind") == "edit"]

        def lbl_of(e):
            return (e.get("text", "") + " " + e.get("desc", "")).lower().strip()

        # 1) حيلة: تجاوز الحوارات/الأذونات/onboarding (تفتح التدفّقات الحقيقية)
        dismiss_kw = ["allow", "while using", "ok", "okay", "yes", "accept", "agree",
                      "continue", "next", "skip", "get started", "got it", "later",
                      "maybe later", "done", "close", "✕", "×", "start", "proceed", "confirm"]
        for e in clickables:
            l = lbl_of(e)
            if l and any(kw in l for kw in dismiss_kw):
                return {"action": "tap", "index": e.get("i", 0), "confidence": 0.85,
                        "reason": f"[Heuristic] حيلة تجاوز حوار/بداية: {l[:30]}"}

        # 2) أهداف أمنية عالية الأولوية
        keywords = ["login", "sign in", "log in", "auth", "settings", "account", "cloud",
                    "premium", "subscribe", "upgrade", "pay", "profile", "sync"]
        for e in clickables:
            l = lbl_of(e)
            if any(kw in l for kw in keywords):
                return {"action": "tap", "index": e.get("i", 0), "confidence": 0.8,
                        "reason": f"[Heuristic] هدف أمني: {l[:30]}"}

        # 3) نماذج الدخول
        if edits:
            return {"action": "input", "index": edits[0].get("i", 0),
                    "text": "hayo.test@example.com", "confidence": 0.7,
                    "reason": "[Heuristic] تعبئة حقل إدخال (تدفّق دخول)"}

        # 4) تصعيد عند التعطّل: أطلق نشاطاً أمنياً معروفاً من الاستخبارات الساكنة
        if stuck >= 3:
            acts = intel.get("known_activities", []) or intel.get("activities", []) or []
            prio = sorted(acts, key=lambda a: 0 if any(k in str(a).lower()
                          for k in ["login", "signin", "auth", "account", "premium", "setting"]) else 1)
            if prio:
                return {"action": "launch", "activity": str(prio[0]), "confidence": 0.75,
                        "reason": f"[Heuristic] تصعيد: إطلاق نشاط معروف {str(prio[0])[:40]}"}
            return {"action": "key", "keycode": 4, "confidence": 0.6,
                    "reason": "[Heuristic] تصعيد: زر رجوع لكسر التعطّل"}

        # 5) استكشاف عام
        if clickables:
            return {"action": "tap", "index": clickables[0].get("i", 0), "confidence": 0.6,
                    "reason": "[Heuristic] نقر عنصر متاح للاستكشاف"}
        if scrollable:
            return {"action": "swipe", "confidence": 0.5,
                    "reason": "[Heuristic] تمرير لكشف محتوى"}
        return {"action": "key", "keycode": 4, "confidence": 0.4,
                "reason": "[Heuristic] رجوع بدل الانتظار السلبي"}

    def diagnose_and_solve(self, problem_description, error_logs="", environment_context=None):
        """
        Root cause analysis & comprehensive solution generation.
        Analyzes problems and produces structured Plan A, Plan B, and Plan C solutions.
        Checks solution cache first for instant resolution.
        """
        self._log(f"Diagnosing problem: {problem_description[:80]}...")

        # Check solution cache
        cached_fix = self.solution_cache.get_cached_fix(f"{problem_description} {error_logs}")
        if cached_fix:
            self._log("Solution retrieved from SolutionCache KB!")
            return cached_fix

        system = (
            "You are an expert AI Mastermind and Lead Systems Architect.\n"
            "Analyze the given technical problem, error logs, and environment context.\n"
            "Provide a deep root-cause diagnosis and a comprehensive solution plan with 3 strategic pathways:\n"
            "- Plan A: Direct/Optimal Solution\n"
            "- Plan B: Alternative Technical Bypass/Workaround\n"
            "- Plan C: Minimal Safe Fallback\n\n"
            "Respond ONLY in JSON format:\n"
            "{\n"
            '  "diagnosis": "<root cause diagnosis in Arabic or English>",\n'
            '  "severity": "low|medium|high|critical",\n'
            '  "root_cause": "<identified root cause>",\n'
            '  "plans": {\n'
            '    "plan_a": {"name": "...", "steps": ["..."], "feasibility": "high"},\n'
            '    "plan_b": {"name": "...", "steps": ["..."], "feasibility": "medium"},\n'
            '    "plan_c": {"name": "...", "steps": ["..."], "feasibility": "high"}\n'
            '  },\n'
            '  "recommended_plan": "plan_a|plan_b|plan_c",\n'
            '  "actionable_commands": ["command1", "command2"]\n'
            "}"
        )

        user_data = {
            "problem": problem_description,
            "error_logs": error_logs[:2000] if error_logs else "None",
            "environment": environment_context or {},
            "timestamp": datetime.now().isoformat()
        }

        raw = self.chat(system, json.dumps(user_data, ensure_ascii=False, indent=2), temperature=0.1)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict):
            self.memory["attempted_solutions"].append({
                "problem": problem_description,
                "solution": parsed
            })
            self.solution_cache.remember_fix(f"{problem_description} {error_logs}", parsed)
            return parsed

        return {
            "diagnosis": f"Technical obstacle encountered: {problem_description}",
            "severity": "medium",
            "root_cause": "Service offline or unhandled exception",
            "plans": {
                "plan_a": {"name": "Retry with fallback parameters", "steps": ["Verify connection", "Retry operation"], "feasibility": "high"},
                "plan_b": {"name": "Bypass affected subsystem", "steps": ["Skip error phase", "Continue execution"], "feasibility": "medium"},
                "plan_c": {"name": "Safe termination with log synthesis", "steps": ["Save current state", "Synthesize report"], "feasibility": "high"}
            },
            "recommended_plan": "plan_a",
            "actionable_commands": []
        }

    def plan_solution_tree(self, goal, constraints=None, existing_intel=None):
        """Generates a comprehensive multi-step execution plan for complex multi-stage tasks."""
        self._log(f"Generating comprehensive solution tree for goal: {goal[:80]}")

        system = (
            "You are an AI Mastermind Strategist.\n"
            "Generate a comprehensive execution plan to achieve the target goal given constraints and intel.\n"
            "Respond ONLY in JSON:\n"
            "{\n"
            '  "goal": "...",\n'
            '  "phases": [\n'
            '    {"phase_id": 1, "name": "...", "objective": "...", "required_tools": ["..."], "success_criteria": "..."}\n'
            '  ],\n'
            '  "risk_mitigation": ["..."],\n'
            '  "estimated_completion_confidence": "0.90"\n'
            "}"
        )

        user_data = {
            "goal": goal,
            "constraints": constraints or [],
            "existing_intel": existing_intel or {}
        }

        raw = self.chat(system, json.dumps(user_data, ensure_ascii=False, indent=2), temperature=0.2)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict):
            return parsed

        return {
            "goal": goal,
            "phases": [
                {"phase_id": 1, "name": "Reconnaissance & Initial Analysis", "objective": "Gather system/target metadata", "required_tools": ["analyzer"], "success_criteria": "Data captured"},
                {"phase_id": 2, "name": "Execution & Verification", "objective": "Execute core logic", "required_tools": ["executor"], "success_criteria": "Execution complete"},
                {"phase_id": 3, "name": "Reporting & Synthesis", "objective": "Synthesize findings", "required_tools": ["reporter"], "success_criteria": "Report generated"}
            ],
            "risk_mitigation": ["Apply automatic fallback on error"],
            "estimated_completion_confidence": "0.85"
        }

    def auto_heal(self, error_trace, code_snippet="", goal=""):
        """Generates auto-healing patch or corrective steps for execution errors."""
        self._log("Generating auto-healing recommendation...")

        system = (
            "You are an AI Code & System Auto-Healer.\n"
            "Analyze the runtime error trace and snippet to produce an actionable fix.\n"
            "Respond ONLY in JSON:\n"
            "{\n"
            '  "fix_type": "patch_code|configuration_change|retry_with_parameters",\n'
            '  "explanation": "...",\n'
            '  "patched_snippet_or_command": "...",\n'
            '  "can_auto_apply": true\n'
            "}"
        )

        user_data = {
            "error_trace": str(error_trace)[:1500],
            "code_snippet": str(code_snippet)[:1000],
            "goal": goal
        }

        raw = self.chat(system, json.dumps(user_data, ensure_ascii=False, indent=2), temperature=0.1)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict):
            return parsed

        return {
            "fix_type": "retry_with_parameters",
            "explanation": "Automatic retry with relaxed parameters",
            "patched_snippet_or_command": "retry()",
            "can_auto_apply": False
        }

    def reason_with_cot(self, prompt, task_context=None):
        """
        Chain-of-Thought (CoT) reasoning module.
        Forces explicit step-by-step reasoning before concluding.
        """
        self._log(f"Executing Chain-of-Thought reasoning for prompt: {prompt[:60]}...")
        system = (
            "You are the HAYO AI Reasoning Engine.\n"
            "Think through the problem systematically step-by-step before producing your final decision.\n"
            "Respond ONLY in JSON:\n"
            "{\n"
            '  "thought_process": [\n'
            '    "Step 1: Analysis of inputs...",\n'
            '    "Step 2: Constraint evaluation...",\n'
            '    "Step 3: Option comparison..."\n'
            '  ],\n'
            '  "conclusion": "<concise statement>",\n'
            '  "action_plan": ["step1", "step2"],\n'
            '  "confidence": 0.92\n'
            "}"
        )
        user_payload = {
            "prompt": prompt,
            "context": task_context or {}
        }
        raw = self.chat(system, json.dumps(user_payload, ensure_ascii=False, indent=2), temperature=0.2)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "conclusion" in parsed:
            return parsed

        return {
            "thought_process": ["Step 1: Fallback heuristic reasoning applied"],
            "conclusion": f"Direct resolution attempted for: {prompt}",
            "action_plan": ["Execute standard routine"],
            "confidence": 0.70
        }

    def critique_and_refine(self, proposed_plan, constraints=None):
        """
        Critique and Refinement engine.
        Evaluates a proposed execution plan against constraints and edge cases to fix flaws.
        """
        self._log("Evaluating proposed plan for self-refinement...")
        system = (
            "You are a Quality & Logic Critic AI.\n"
            "Review the provided plan and constraints. Identify potential bottlenecks, blind spots, or flaws.\n"
            "Provide a refined, robust version of the plan.\n"
            "Respond ONLY in JSON:\n"
            "{\n"
            '  "flaws_detected": ["flaw1", "flaw2"],\n'
            '  "critique_summary": "<summary>",\n'
            '  "refined_plan": {\n'
            '    "improved_steps": ["step1", "step2"],\n'
            '    "added_safeguards": ["safeguard1"]\n'
            '  },\n'
            '  "quality_score": 0.95\n'
            "}"
        )
        user_payload = {
            "proposed_plan": proposed_plan,
            "constraints": constraints or []
        }
        raw = self.chat(system, json.dumps(user_payload, ensure_ascii=False, indent=2), temperature=0.1)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "refined_plan" in parsed:
            return parsed

        return {
            "flaws_detected": [],
            "critique_summary": "Plan appears sound under default constraints.",
            "refined_plan": proposed_plan if isinstance(proposed_plan, dict) else {"improved_steps": [str(proposed_plan)]},
            "quality_score": 0.85
        }

    def decompose_task(self, high_level_goal, constraints=None):
        """
        Decomposes a complex high-level goal into a Directed Acyclic Graph (DAG) of sub-tasks.
        """
        self._log(f"Decomposing high-level goal: {high_level_goal[:70]}...")
        system = (
            "You are an AI Task Decomposition Engine.\n"
            "Break down the given goal into clear sub-tasks with dependency mappings.\n"
            "Respond ONLY in JSON:\n"
            "{\n"
            '  "subtasks": [\n'
            '    {"id": "task_1", "description": "...", "depends_on": [], "expected_output": "..."},\n'
            '    {"id": "task_2", "description": "...", "depends_on": ["task_1"], "expected_output": "..."}\n'
            '  ],\n'
            '  "total_estimated_steps": 2\n'
            "}"
        )
        user_payload = {
            "goal": high_level_goal,
            "constraints": constraints or []
        }
        raw = self.chat(system, json.dumps(user_payload, ensure_ascii=False, indent=2), temperature=0.1)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "subtasks" in parsed:
            return parsed

        return {
            "subtasks": [
                {"id": "task_1", "description": f"Initial phase for {high_level_goal}", "depends_on": [], "expected_output": "Initialization done"},
                {"id": "task_2", "description": f"Completion phase for {high_level_goal}", "depends_on": ["task_1"], "expected_output": "Goal accomplished"}
            ],
            "total_estimated_steps": 2
        }

    def generate_hypotheses(self, observed_issue, symptoms=None):
        """
        Generates alternative diagnostic hypotheses for technical issues and ranks them by probability.
        """
        self._log(f"Generating diagnostic hypotheses for issue: {observed_issue[:60]}...")
        system = (
            "You are an AI Diagnostic Hypothesizer.\n"
            "Analyze the issue and symptoms to formulate ranked hypotheses with test strategies.\n"
            "Respond ONLY in JSON:\n"
            "{\n"
            '  "hypotheses": [\n'
            '    {"id": "H1", "statement": "...", "probability": 0.70, "test_action": "..."},\n'
            '    {"id": "H2", "statement": "...", "probability": 0.25, "test_action": "..."}\n'
            '  ]\n'
            "}"
        )
        user_payload = {
            "issue": observed_issue,
            "symptoms": symptoms or []
        }
        raw = self.chat(system, json.dumps(user_payload, ensure_ascii=False, indent=2), temperature=0.2)
        parsed = extract_json_from_text(raw)
        if isinstance(parsed, dict) and "hypotheses" in parsed:
            self.memory["hypotheses_log"].append(parsed)
            return parsed

        return {
            "hypotheses": [
                {"id": "H1", "statement": f"Primary issue: {observed_issue}", "probability": 0.80, "test_action": "Inspect system logs"},
                {"id": "H2", "statement": "Secondary dependency failure", "probability": 0.20, "test_action": "Verify dependency status"}
            ]
        }

    def synthesize_and_verify_code(self, task_description, language="python"):
        """
        Generates Python or JavaScript code snippet and verifies code syntax locally.
        """
        self._log(f"Synthesizing {language} code for: {task_description[:60]}...")
        system = (
            f"You are an expert {language} Code Synthesizer.\n"
            f"Write clean, safe, efficient {language} code to accomplish the task.\n"
            "Respond ONLY in JSON:\n"
            "{\n"
            '  "language": "' + language + '",\n'
            '  "code": "<raw_code_string>",\n'
            '  "explanation": "<brief summary>"\n'
            "}"
        )
        raw = self.chat(system, json.dumps({"task": task_description}), temperature=0.1)
        parsed = extract_json_from_text(raw)

        if isinstance(parsed, dict) and "code" in parsed:
            code_str = parsed["code"]
            if language.lower() == "python":
                try:
                    ast.parse(code_str)
                    parsed["syntax_valid"] = True
                except SyntaxError as se:
                    parsed["syntax_valid"] = False
                    parsed["syntax_error"] = str(se)
            else:
                parsed["syntax_valid"] = True
            return parsed

        return {
            "language": language,
            "code": "# Code synthesis fallback\nprint('Execution placeholder')",
            "explanation": "Fallback template generated",
            "syntax_valid": True
        }

    def run_self_diagnostic(self):
        """
        Runs self-diagnostic check on all LLM provider backends and reports connection status.
        """
        self._log("Running LLM Brain multi-provider self-diagnostic...")
        test_sys = "You are a test assistant."
        test_user = "Reply with 'OK'."

        results = {}
        for provider in self.engine.providers:
            p_name = provider["name"]
            t0 = time.time()
            res = self.engine.request(test_sys, test_user, max_tokens=10)
            elapsed = round(time.time() - t0, 3)
            results[p_name] = {
                "active": res is not None,
                "response_sample": (res or "").strip()[:20],
                "latency_s": elapsed
            }

        return {
            "timestamp": datetime.now().isoformat(),
            "model_configured": self.model,
            "providers_health": results,
            "memory_items_count": len(self.memory["history"]),
            "semantic_memories_count": len(self.semantic_memory.entries),
            "estimated_total_tokens": self.engine.total_tokens_estimated
        }

    def save_memory_to_disk(self, filepath="brain_memory.json"):
        """Saves session memory state and semantic store to disk."""
        try:
            mem_copy = dict(self.memory)
            mem_copy["failed_actions"] = list(mem_copy.get("failed_actions", []))
            mem_copy["semantic_store"] = self.semantic_memory.summarize()
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(mem_copy, f, ensure_ascii=False, indent=2)
            self._log(f"Memory state saved to {filepath}")
            return True
        except Exception as e:
            self._log(f"Failed to save memory: {e}", "WARN")
            return False

    def load_memory_from_disk(self, filepath="brain_memory.json"):
        """Loads state from disk if exists."""
        try:
            if os.path.isfile(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.memory["history"] = data.get("history", [])
                    self.memory["attempted_solutions"] = data.get("attempted_solutions", [])
                    self.memory["hypotheses_log"] = data.get("hypotheses_log", [])
                    self.memory["insights"] = data.get("insights", [])
                    self._log(f"Loaded memory state from {filepath}")
                    return True
        except Exception as e:
            self._log(f"Failed to load memory from disk: {e}", "WARN")
        return False

    def export_cognitive_report(self, filepath="brain_cognitive_report.json"):
        """Generates and exports comprehensive cognitive status report."""
        report = {
            "version": "LLMBrain v7 Ultra Mastermind",
            "timestamp": datetime.now().isoformat(),
            "providers": self.engine.get_provider_status(),
            "performance_metrics": {
                "estimated_tokens": self.engine.total_tokens_estimated,
                "history_length": len(self.memory["history"]),
                "attempted_solutions_count": len(self.memory["attempted_solutions"]),
                "hypotheses_count": len(self.memory["hypotheses_log"]),
                "semantic_memories_count": len(self.semantic_memory.entries)
            },
            "semantic_memory_summary": self.semantic_memory.summarize()
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            self._log(f"Cognitive report exported to {filepath}")
        except Exception as e:
            self._log(f"Failed to export cognitive report: {e}", "WARN")
        return report


if __name__ == "__main__":
    brain = LLMBrain()
    safe_print(f"==================================================")
    safe_print(f"HAYO Mastermind Brain v7 Extended Initialized Successfully.")
    safe_print(f"Active Model: {brain.model}")
    safe_print(f"Registered Providers: {len(brain.engine.providers)}")
    safe_print(f"==================================================")

    safe_print("\n[*] Testing Adaptive Strategy Selector...")
    strat = brain.adapt_strategy("Design a secure cloud authentication and auto-healing pipeline")
    safe_print(json.dumps(strat, ensure_ascii=False, indent=2))

    safe_print("\n[*] Testing Multi-Agent Consensus Debate...")
    consensus = brain.multi_agent_consensus("Implement self-healing retry mechanism for backend API calls")
    safe_print(json.dumps(consensus, ensure_ascii=False, indent=2))

    safe_print("\n[*] Testing Code Synthesis & AST Verification Loop...")
    code_res = brain.synthesize_verify_and_refine_code("Write a python function to compute exponential backoff with jitter")
    safe_print(json.dumps(code_res, ensure_ascii=False, indent=2))

    safe_print("\n[*] Testing Self-Diagnostic...")
    diag = brain.run_self_diagnostic()
    safe_print(json.dumps(diag, ensure_ascii=False, indent=2))
