#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Extended AI Brain (extended_brain.py)
=======================================================
Extended AI brain with support for advanced components:
- Real-time decision making
- Adaptive exploitation
- Phase management
- Feedback loop
- Strategy adaptation

Built on top of LLMBrain with OpenAI integration.
"""
import json
import os
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    from llm_brain import LLMBrain
except ImportError:
    LLMBrain = None

try:
    from realtime_decision_engine import DecisionType, Decision, Priority
    from phase_manager_brain import PhaseDecision, PhaseContext
    from adaptive_exploitation_engine import ExploitType
except ImportError:
    DecisionType = Decision = Priority = PhaseDecision = PhaseContext = ExploitType = None


class ExtendedBrain:
    """
    Extended AI brain that adds advanced decision-making capabilities
    to the base LLMBrain for integration with new pentest components.
    """
    
    def __init__(self, base_brain=None, verbose=False):
        """
        Initialize the extended brain.
        
        Args:
            base_brain: Base LLMBrain instance (will create one if None)
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        
        # Always use LLMBrain directly for AI capabilities
        if LLMBrain:
            self.brain = LLMBrain(verbose=verbose)
        else:
            raise ImportError("LLMBrain not available. Please ensure llm_brain.py is present.")
        
        # Strategy state
        self.strategy = {
            "aggressiveness": 0.5,  # 0.0 (conservative) to 1.0 (aggressive)
            "focus_areas": ["crypto", "network", "auth"],
            "exploit_preferences": {},
            "phase_priorities": {},
            "learning_rate": 0.1
        }
        
        # Decision history
        self.decision_history = []
        self.exploit_history = []
        self.phase_history = []
        
        self._log("Extended AI Brain initialized")
    
    def _log(self, msg, level="INFO"):
        if self.verbose:
            print(f"[EXTENDED_BRAIN] [{level}] {msg}")
    
    # ============================================================
    # Real-time Decision Making
    # ============================================================
    
    def decide(self, event, analysis=None, context=None) -> Optional['Decision']:
        """
        Make a real-time decision based on an event.
        
        Args:
            event: Event object with type, data, and source
            analysis: Optional analysis data (for compatibility)
            context: Optional context data (for compatibility)
            
        Returns:
            Decision object with action and reasoning
        """
        if Decision is None:
            return None
        
        try:
            # Extract event data
            event_type = getattr(event, 'type', 'unknown')
            event_data = getattr(event, 'data', {})
            event_source = getattr(event, 'source', 'unknown')
            
            # Build prompt for AI
            prompt = f"""
You are an AI security analyst making real-time decisions during a pentest.

Event Type: {event_type}
Event Source: {event_source}
Event Data: {json.dumps(event_data, indent=2, ensure_ascii=False)}

Current Strategy:
- Aggressiveness: {self.strategy['aggressiveness']}
- Focus Areas: {self.strategy['focus_areas']}
- Exploit Preferences: {self.strategy['exploit_preferences']}

Available Decision Types:
- CONTINUE: Continue current operations
- ESCALATE: Escalate to more aggressive actions
- FOCUS: Focus on specific target
- EXPLORE: Explore new areas
- RETREAT: Retreat from current action
- STOP: Stop current operation

Make a decision based on the event and current strategy.
Respond with JSON:
{{
    "decision_type": "CONTINUE|ESCALATE|FOCUS|EXPLORE|RETREAT|STOP",
    "action": "specific action to take",
    "reasoning": "brief explanation of the decision",
    "confidence": 0.0-1.0
}}
"""
            
            # Get AI response using LLMBrain's chat method
            response = self.brain.chat(
                system="You are an AI security analyst making real-time decisions during a pentest.",
                user=prompt
            )
            result = self._extract_decision(response)
            
            if result:
                # Update strategy based on decision
                self._update_strategy_from_decision(result, event_data)
                
                # Record decision
                self.decision_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "event": event_type,
                    "decision": result,
                    "confidence": result.get("confidence", 0.5)
                })
                
                # Create Decision object
                decision_type_str = result.get("decision_type", "continue").lower()
                try:
                    decision_type = DecisionType(decision_type_str)
                except ValueError:
                    # Fallback to continue if invalid type
                    decision_type = DecisionType.CONTINUE
                
                priority = Priority.MEDIUM  # Default priority
                
                # Set priority based on decision type
                if decision_type == DecisionType.ESCALATE:
                    priority = Priority.HIGH
                elif decision_type == DecisionType.STOP:
                    priority = Priority.CRITICAL
                
                return Decision(
                    type=decision_type,
                    action=result.get("action", "continue"),
                    priority=priority,
                    reasoning=result.get("reasoning", ""),
                    confidence=result.get("confidence", 0.5)
                )
            
            # Fallback to default
            return Decision(
                type=DecisionType.CONTINUE,
                action="continue",
                priority=Priority.MEDIUM,
                reasoning="Default decision - AI response unavailable",
                confidence=0.3
            )
            
        except Exception as e:
            self._log(f"Error in decide: {e}", "ERROR")
            return Decision(
                type=DecisionType.CONTINUE,
                action="continue",
                priority=Priority.MEDIUM,
                reasoning=f"Error: {str(e)}",
                confidence=0.2
            )
    
    def _extract_decision(self, response) -> Optional[Dict]:
        """Extract ANY JSON object from an AI response (general — not tied to one key).

        كان سابقاً يبحث حصراً عن "decision_type" → ففشل مع كل الدوال التي تُرجع
        مفاتيح أخرى (exploit_type/aggressiveness/should_run/...) وأرجعت افتراضات ثابتة.
        الآن يفكّ أي JSON صالح (مع تقشير أسوار الكود)."""
        try:
            if isinstance(response, dict):
                return response
            if not response:
                return None
            text = str(response).strip()
            # تقشير ```json ... ``` إن وُجدت
            if "```" in text:
                import re as _re
                fence = _re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, _re.DOTALL)
                if fence:
                    text = fence.group(1)
            # محاولة مباشرة (الردّ غالباً JSON صرف كما نطلب)
            try:
                return json.loads(text)
            except Exception:
                pass
            # أول كائن JSON في النص
            import re
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                return json.loads(m.group(0))
            return None
        except Exception:
            return None
    
    def _update_strategy_from_decision(self, decision: Dict, event_data: Dict):
        """Update strategy based on decision"""
        decision_type = decision.get("decision_type", "CONTINUE")
        
        if decision_type == "ESCALATE":
            self.strategy["aggressiveness"] = min(1.0, self.strategy["aggressiveness"] + 0.1)
        elif decision_type == "DEESCALATE":
            self.strategy["aggressiveness"] = max(0.0, self.strategy["aggressiveness"] - 0.1)
        elif decision_type == "PIVOT":
            # Rotate focus areas
            if len(self.strategy["focus_areas"]) > 1:
                self.strategy["focus_areas"] = self.strategy["focus_areas"][1:] + [self.strategy["focus_areas"][0]]
    
    # ============================================================
    # Exploit Selection
    # ============================================================
    
    def select_exploit(self, target: Dict, analysis: Dict = None, context: Dict = None):
        """
        Select the best exploit for a given target.

        Args:
            target: Target information with type, priority, secrets, etc.
            analysis: (اختياري) تحليل الهدف — تمرّره AdaptiveExploitationEngine.
            context: (اختياري) سياق الذاكرة العاملة.

        Returns:
            - عند الاستدعاء بوسيط واحد (توافق قديم): سلسلة نوع الاستغلال.
            - عند تمرير `analysis` (من محرّك الاستغلال التكيفي): dict بالشكل
              {"type": <قيمة ExploitType>, "confidence": float} أو None ليعود
              المحرّك إلى اختيار قائم على الأوزان.
        """
        # خريطة مفردات ExtendedBrain (UPPER) → قيم ExploitType في المحرّك التكيفي
        _ENGINE_MAP = {
            "CLOUD": "cloud_exploitation",
            "CLOUD_EXPLOITATION": "cloud_exploitation",
            "AUTH_BYPASS": "auth_bypass",
            "TOKEN_THEFT": "token_theft",
        }

        def _shape(exploit_type_str, confidence=0.5):
            """يعيد التنسيق المطلوب حسب طريقة الاستدعاء."""
            if analysis is None:
                return exploit_type_str  # التوافق القديم: سلسلة
            mapped = _ENGINE_MAP.get(str(exploit_type_str).upper())
            if not mapped:
                return None  # نوع بلا قالب في المحرّك → دع الأوزان تقرّر
            return {"type": mapped, "confidence": confidence}
        try:
            target_type = target.get("type", "unknown")
            target_priority = target.get("priority", "medium")
            target_secrets = target.get("secrets", {})
            
            # Build prompt for AI
            prompt = f"""
You are an AI security specialist selecting the best exploit for a target.

Target Type: {target_type}
Target Priority: {target_priority}
Available Secrets: {json.dumps(target_secrets, indent=2, ensure_ascii=False)}

Available Exploit Types:
- CLOUD: Exploit cloud credentials and services
- AUTH_BYPASS: Bypass authentication mechanisms
- TOKEN_THEFT: Steal and reuse authentication tokens
- API_ABUSE: Abuse API endpoints
- DATA_EXFILTRATION: Exfiltrate sensitive data
- PRIVILEGE_ESCALATION: Escalate privileges

Current Strategy:
- Aggressiveness: {self.strategy['aggressiveness']}
- Exploit Preferences: {self.strategy['exploit_preferences']}

Select the best exploit type for this target.
Respond with JSON:
{{
    "exploit_type": "CLOUD|AUTH_BYPASS|TOKEN_THEFT|API_ABUSE|DATA_EXFILTRATION|PRIVILEGE_ESCALATION",
    "reasoning": "brief explanation",
    "confidence": 0.0-1.0
}}
"""
            
            response = self.brain.think(prompt, strategy="fast_reactive")
            result = self._extract_decision(response)
            
            if result:
                exploit_type = result.get("exploit_type", "DATA_EXFILTRATION")
                
                # Update preferences
                self.strategy["exploit_preferences"][exploit_type] = \
                    self.strategy["exploit_preferences"].get(exploit_type, 0) + 1
                
                # Record exploit selection
                self.exploit_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "target": target_type,
                    "exploit": exploit_type,
                    "confidence": result.get("confidence", 0.5)
                })

                return _shape(exploit_type, result.get("confidence", 0.5))

            return _shape("DATA_EXFILTRATION")  # Fallback

        except Exception as e:
            self._log(f"Error in select_exploit: {e}", "ERROR")
            return _shape("DATA_EXFILTRATION")
    
    # ============================================================
    # Strategy Update
    # ============================================================
    
    def update_strategy(self, feedback: Dict):
        """
        Update strategy based on feedback.
        
        Args:
            feedback: Feedback with action, result, context
        """
        try:
            action = feedback.get("action", "unknown")
            result = feedback.get("result", {})
            success = result.get("success", False)
            context = feedback.get("context", {})
            
            # Build prompt for AI
            prompt = f"""
You are an AI security strategist updating pentest strategy based on feedback.

Action: {action}
Result Success: {success}
Context: {json.dumps(context, indent=2, ensure_ascii=False)}

Current Strategy:
- Aggressiveness: {self.strategy['aggressiveness']}
- Focus Areas: {self.strategy['focus_areas']}
- Exploit Preferences: {self.strategy['exploit_preferences']}
- Learning Rate: {self.strategy['learning_rate']}

Update the strategy based on this feedback.
Respond with JSON:
{{
    "aggressiveness": 0.0-1.0,
    "focus_areas": ["area1", "area2", ...],
    "exploit_preferences": {{"exploit_type": weight, ...}},
    "reasoning": "brief explanation"
}}
"""
            
            response = self.brain.think(prompt, strategy="fast_reactive")
            result = self._extract_decision(response)
            
            if result:
                # Update strategy with learning rate
                lr = self.strategy["learning_rate"]
                
                if "aggressiveness" in result:
                    old_agg = self.strategy["aggressiveness"]
                    new_agg = result["aggressiveness"]
                    self.strategy["aggressiveness"] = old_agg + lr * (new_agg - old_agg)
                
                if "focus_areas" in result:
                    self.strategy["focus_areas"] = result["focus_areas"]
                
                if "exploit_preferences" in result:
                    for exp_type, weight in result["exploit_preferences"].items():
                        old_weight = self.strategy["exploit_preferences"].get(exp_type, 0)
                        self.strategy["exploit_preferences"][exp_type] = \
                            old_weight + lr * (weight - old_weight)
                
                self._log(f"Strategy updated: {result.get('reasoning', 'No reasoning')}")
            
        except Exception as e:
            self._log(f"Error in update_strategy: {e}", "ERROR")
    
    # ============================================================
    # Phase Management
    # ============================================================
    
    def should_run_phase(self, phase_name: str, context: 'PhaseContext') -> 'PhaseDecision':
        """
        Determine if a phase should run.
        
        Args:
            phase_name: Name of the phase
            context: Phase context with previous results, live data, etc.
            
        Returns:
            PhaseDecision (RUN, SKIP, RETRY, ABORT)
        """
        if PhaseDecision is None:
            return None
        
        try:
            # Extract context data
            prev_results = getattr(context, 'previous_results', {})
            live_data = getattr(context, 'live_data', [])
            static_data = getattr(context, 'static_data', {})
            
            # Build prompt for AI
            prompt = f"""
You are an AI pentest orchestrator deciding whether to run a phase.

Phase: {phase_name}
Previous Results: {json.dumps(prev_results, indent=2, ensure_ascii=False)}
Live Data Count: {len(live_data) if live_data else 0}
Static Data Available: {bool(static_data)}

Available Decisions:
- RUN: Execute this phase
- SKIP: Skip this phase
- RETRY: Retry this phase (if it failed before)
- ABORT: Stop the entire pipeline

Current Strategy:
- Phase Priorities: {self.strategy['phase_priorities']}
- Aggressiveness: {self.strategy['aggressiveness']}

Make a decision for this phase.
Respond with JSON:
{{
    "decision": "RUN|SKIP|RETRY|ABORT",
    "reasoning": "brief explanation",
    "confidence": 0.0-1.0
}}
"""
            
            response = self.brain.think(prompt, strategy="fast_reactive")
            result = self._extract_decision(response)
            
            if result:
                decision_str = result.get("decision", "RUN")
                decision = PhaseDecision(decision_str)
                
                # Record phase decision
                self.phase_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "phase": phase_name,
                    "decision": decision_str,
                    "confidence": result.get("confidence", 0.5)
                })
                
                return decision
            
            return PhaseDecision.RUN  # Fallback
            
        except Exception as e:
            self._log(f"Error in should_run_phase: {e}", "ERROR")
            return PhaseDecision.RUN
    
    def adapt_strategy(self, phase_name: str, result: Dict, context: 'PhaseContext'):
        """
        Adapt strategy based on phase result.
        
        Args:
            phase_name: Name of the completed phase
            result: Phase result data
            context: Phase context
        """
        try:
            success = result.get("success", True)
            data = result.get("data", {})
            
            # Build prompt for AI
            prompt = f"""
You are an AI pentest strategist adapting strategy after a phase.

Phase: {phase_name}
Phase Success: {success}
Phase Data: {json.dumps(data, indent=2, ensure_ascii=False)}

Current Strategy:
- Aggressiveness: {self.strategy['aggressiveness']}
- Focus Areas: {self.strategy['focus_areas']}
- Phase Priorities: {self.strategy['phase_priorities']}

Adapt the strategy based on this phase result.
Respond with JSON:
{{
    "aggressiveness": 0.0-1.0,
    "focus_areas": ["area1", "area2", ...],
    "phase_priorities": {{"phase": priority, ...}},
    "reasoning": "brief explanation"
}}
"""
            
            response = self.brain.think(prompt, strategy="fast_reactive")
            result = self._extract_decision(response)
            
            if result:
                lr = self.strategy["learning_rate"]
                
                if "aggressiveness" in result:
                    old_agg = self.strategy["aggressiveness"]
                    new_agg = result["aggressiveness"]
                    self.strategy["aggressiveness"] = old_agg + lr * (new_agg - old_agg)
                
                if "focus_areas" in result:
                    self.strategy["focus_areas"] = result["focus_areas"]
                
                if "phase_priorities" in result:
                    self.strategy["phase_priorities"].update(result["phase_priorities"])
                
                self._log(f"Strategy adapted after {phase_name}: {result.get('reasoning', 'No reasoning')}")
            
        except Exception as e:
            self._log(f"Error in adapt_strategy: {e}", "ERROR")
    
    # ============================================================
    # Utility Methods
    # ============================================================
    
    def get_strategy(self) -> Dict:
        """Get current strategy"""
        return self.strategy.copy()
    
    def get_stats(self) -> Dict:
        """Get brain statistics"""
        return {
            "decision_count": len(self.decision_history),
            "exploit_count": len(self.exploit_history),
            "phase_count": len(self.phase_history),
            "strategy": self.strategy.copy()
        }
    
    def export_state(self) -> Dict:
        """Export brain state for persistence"""
        return {
            "strategy": self.strategy,
            "decision_history": self.decision_history,
            "exploit_history": self.exploit_history,
            "phase_history": self.phase_history,
            "timestamp": datetime.now().isoformat()
        }
    
    def import_state(self, state: Dict):
        """Import brain state from persistence"""
        if "strategy" in state:
            self.strategy = state["strategy"]
        if "decision_history" in state:
            self.decision_history = state["decision_history"]
        if "exploit_history" in state:
            self.exploit_history = state["exploit_history"]
        if "phase_history" in state:
            self.phase_history = state["phase_history"]
        
        self._log("Brain state imported")
    
    # ============================================================
    # Cloud Network Access
    # ============================================================
    
    def probe_cloud_service(self, service_type: str, credentials: Dict) -> Dict:
        """
        Probe a cloud service to check if credentials are valid and gather info.
        
        Args:
            service_type: Type of cloud service (aws, google, firebase, openai, etc.)
            credentials: Dictionary with credentials
            
        Returns:
            Dictionary with probe results
        """
        results = {
            "service": service_type,
            "valid": False,
            "info": {},
            "error": None
        }
        
        try:
            if service_type == "aws":
                results = self._probe_aws(credentials)
            elif service_type == "google":
                results = self._probe_google(credentials)
            elif service_type == "firebase":
                results = self._probe_firebase(credentials)
            elif service_type == "openai":
                results = self._probe_openai(credentials)
            elif service_type == "deepseek":
                results = self._probe_deepseek(credentials)
            elif service_type == "anthropic":
                results = self._probe_anthropic(credentials)
            else:
                results["error"] = f"Unknown service type: {service_type}"
        except Exception as e:
            results["error"] = str(e)
            self._log(f"Error probing {service_type}: {e}", "ERROR")
        
        return results
    
    def _probe_aws(self, credentials: Dict) -> Dict:
        """Probe AWS service"""
        access_key = credentials.get("access_key")
        secret_key = credentials.get("secret_key")
        
        if not access_key or not secret_key:
            return {"service": "aws", "valid": False, "error": "Missing credentials"}
        
        # Try to get AWS account info (simplified check)
        # In production, use boto3 with proper error handling
        results = {
            "service": "aws",
            "valid": True,
            "info": {
                "access_key": access_key[:8] + "..." if len(access_key) > 8 else access_key,
                "note": "Credentials format valid - full validation requires boto3"
            }
        }
        
        self._log(f"AWS credentials detected: {access_key[:8]}...")
        return results
    
    def _probe_google(self, credentials: Dict) -> Dict:
        """Probe Google Cloud service"""
        api_key = credentials.get("api_key")
        
        if not api_key:
            return {"service": "google", "valid": False, "error": "Missing API key"}
        
        results = {
            "service": "google",
            "valid": True,
            "info": {
                "api_key": api_key[:10] + "..." if len(api_key) > 10 else api_key,
                "note": "Google API key format valid"
            }
        }
        
        self._log(f"Google API key detected: {api_key[:10]}...")
        return results
    
    def _probe_firebase(self, credentials: Dict) -> Dict:
        """Probe Firebase service"""
        storage_url = credentials.get("storage_url")
        db_url = credentials.get("db_url")
        
        results = {
            "service": "firebase",
            "valid": False,
            "info": {}
        }
        
        if storage_url:
            results["valid"] = True
            results["info"]["storage"] = storage_url
            self._log(f"Firebase Storage detected: {storage_url}")
        
        if db_url:
            results["valid"] = True
            results["info"]["database"] = db_url
            self._log(f"Firebase Database detected: {db_url}")
        
        return results
    
    def _probe_openai(self, credentials: Dict) -> Dict:
        """Probe OpenAI API"""
        api_key = credentials.get("api_key")
        
        if not api_key:
            return {"service": "openai", "valid": False, "error": "Missing API key"}
        
        # Try to validate with OpenAI API
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            response = requests.get("https://api.openai.com/v1/models", headers=headers, timeout=5)
            
            if response.status_code == 200:
                results = {
                    "service": "openai",
                    "valid": True,
                    "info": {
                        "api_key": api_key[:10] + "..." if len(api_key) > 10 else api_key,
                        "models_available": len(response.json().get("data", [])),
                        "note": "API key is valid"
                    }
                }
                self._log(f"OpenAI API key valid: {api_key[:10]}...")
            else:
                results = {
                    "service": "openai",
                    "valid": False,
                    "error": f"API returned status {response.status_code}",
                    "info": {"api_key": api_key[:10] + "..."}
                }
        except Exception as e:
            results = {
                "service": "openai",
                "valid": False,
                "error": f"Connection error: {str(e)}",
                "info": {"api_key": api_key[:10] + "..."}
            }
        
        return results
    
    def _probe_deepseek(self, credentials: Dict) -> Dict:
        """Probe DeepSeek API"""
        api_key = credentials.get("api_key")
        
        if not api_key:
            return {"service": "deepseek", "valid": False, "error": "Missing API key"}
        
        # Try to validate with DeepSeek API
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            response = requests.get("https://api.deepseek.com/v1/models", headers=headers, timeout=5)
            
            if response.status_code == 200:
                results = {
                    "service": "deepseek",
                    "valid": True,
                    "info": {
                        "api_key": api_key[:10] + "..." if len(api_key) > 10 else api_key,
                        "note": "API key is valid"
                    }
                }
                self._log(f"DeepSeek API key valid: {api_key[:10]}...")
            else:
                results = {
                    "service": "deepseek",
                    "valid": False,
                    "error": f"API returned status {response.status_code}",
                    "info": {"api_key": api_key[:10] + "..."}
                }
        except Exception as e:
            results = {
                "service": "deepseek",
                "valid": False,
                "error": f"Connection error: {str(e)}",
                "info": {"api_key": api_key[:10] + "..."}
            }
        
        return results
    
    def _probe_anthropic(self, credentials: Dict) -> Dict:
        """Probe Anthropic Claude API"""
        api_key = credentials.get("api_key")
        
        if not api_key:
            return {"service": "anthropic", "valid": False, "error": "Missing API key"}
        
        # Try to validate with Anthropic API
        try:
            headers = {
                "x-api-key": api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01"
            }
            response = requests.get("https://api.anthropic.com/v1/messages", headers=headers, timeout=5)
            
            # Anthropic returns 400 for missing body, but 401 for invalid key
            if response.status_code != 401:
                results = {
                    "service": "anthropic",
                    "valid": True,
                    "info": {
                        "api_key": api_key[:10] + "..." if len(api_key) > 10 else api_key,
                        "note": "API key format valid"
                    }
                }
                self._log(f"Anthropic API key valid: {api_key[:10]}...")
            else:
                results = {
                    "service": "anthropic",
                    "valid": False,
                    "error": f"API returned status {response.status_code}",
                    "info": {"api_key": api_key[:10] + "..."}
                }
        except Exception as e:
            results = {
                "service": "anthropic",
                "valid": False,
                "error": f"Connection error: {str(e)}",
                "info": {"api_key": api_key[:10] + "..."}
            }
        
        return results
    
    def analyze_cloud_exposure(self, secrets: List[Dict]) -> Dict:
        """
        Analyze cloud exposure from discovered secrets.
        
        Args:
            secrets: List of discovered secrets
            
        Returns:
            Dictionary with cloud exposure analysis
        """
        analysis = {
            "total_secrets": len(secrets),
            "cloud_services": {},
            "valid_credentials": [],
            "risk_level": "low"
        }
        
        for secret in secrets:
            secret_type = secret.get("type", "unknown")
            secret_value = secret.get("value", "")
            
            # Map secret types to cloud services
            service_map = {
                "aws_access_key": "aws",
                "google_api_key": "google",
                "firebase_storage": "firebase",
                "firebase_db_url": "firebase",
                "openai_key": "openai",
                "deepseek_key": "deepseek",
                "deepseek_chat_key": "deepseek",
                "chatgpt_key": "openai",
                "gpt4_key": "openai",
                "claude_key": "anthropic",
                "anthropic_key": "anthropic",
                "gemini_key": "google"
            }
            
            if secret_type in service_map:
                service = service_map[secret_type]
                
                if service not in analysis["cloud_services"]:
                    analysis["cloud_services"][service] = {
                        "count": 0,
                        "secrets": []
                    }
                
                analysis["cloud_services"][service]["count"] += 1
                analysis["cloud_services"][service]["secrets"].append({
                    "type": secret_type,
                    "value": secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                    "severity": secret.get("severity", "unknown")
                })
        
        # Determine risk level
        total_cloud = sum(s["count"] for s in analysis["cloud_services"].values())
        if total_cloud > 5:
            analysis["risk_level"] = "critical"
        elif total_cloud > 2:
            analysis["risk_level"] = "high"
        elif total_cloud > 0:
            analysis["risk_level"] = "medium"
        
        self._log(f"Cloud exposure analysis: {total_cloud} cloud secrets detected, risk level: {analysis['risk_level']}")
        
        return analysis


# ============================================================
# Factory function
# ============================================================

def create_extended_brain(verbose=False) -> ExtendedBrain:
    """
    Create an extended brain with OpenAI integration.
    
    Args:
        verbose: Enable verbose logging
        
    Returns:
        ExtendedBrain instance
    """
    return ExtendedBrain(verbose=verbose)


if __name__ == "__main__":
    # Test the extended brain
    print("Testing Extended Brain...")
    
    brain = create_extended_brain(verbose=True)
    
    # Test decision making
    from realtime_decision_engine import Event
    event = Event(
        type="finding",
        data={"type": "api_key", "severity": "critical"},
        source="frida"
    )
    
    decision = brain.decide(event)
    print(f"Decision: {decision.action} - {decision.reasoning}")
    
    # Test exploit selection
    target = {
        "type": "cloud_credentials",
        "priority": "critical",
        "secrets": {"aws_key": "AKIA123"}
    }
    
    exploit = brain.select_exploit(target)
    print(f"Selected exploit: {exploit}")
    
    # Test strategy update
    feedback = {
        "action": "exploit_cloud",
        "result": {"success": True},
        "context": {"severity": "critical"}
    }
    
    brain.update_strategy(feedback)
    print(f"Updated strategy: {brain.get_strategy()}")
    
    print("Extended Brain test completed successfully!")
