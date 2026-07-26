#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — ML Engine (Directive 3)
========================================
Machine Learning integration for:
  1. Secret detection (entropy + regex + patterns)
  2. Vulnerability pattern recognition
  3. Intelligent UI crawling guidance

No external ML dependencies required — uses Shannon entropy, scoring
heuristics, and state-space analysis suitable for the HAYO Android
pentest framework.
"""
import math, re, os, json, hashlib
from collections import defaultdict, Counter
from datetime import datetime
from itertools import chain

# ═════════════════════════════════════════════════════════════════════
# 1. SECRET DETECTION ENGINE
# ═════════════════════════════════════════════════════════════════════

# ── Known secret patterns ──────────────────────────────────────────
SECRET_PATTERNS = [
    # API Keys & Tokens
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,64})', 0.9),
    (r'(?i)(bearer|bearer_token|access_token|auth_token)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,200})', 1.0),
    (r'(?i)sk-[A-Za-z0-9]{32,}', 1.0),  # OpenAI key
    (r'(?i)pk-[A-Za-z0-9]{32,}', 1.0),  # Stripe publishable
    (r'(?i)sk_live_[A-Za-z0-9]{24,}', 1.0),  # Stripe live secret
    (r'(?i)AWS[A-Z0-9]{16,}', 0.95),  # AWS key ID
    (r'(?i)(?:(?:AKIA|ASIA)[A-Z0-9]{16})', 1.0),  # AWS access key
    # Firebase
    (r'(?i)(firebase|firebase_url|firebase_secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', 0.95),
    # JWT
    (r'(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})', 0.95),
    # Private keys
    (r'-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PRIVATE)\s?KEY-----', 1.0),
    # Connection strings
    (r'(?i)(jdbc|mongodb|postgresql|mysql|redis)://[^\s"\']{10,}', 0.95),
    # OAuth
    (r'(?i)(client_secret|client_id|oauth_token|refresh_token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{8,128})', 0.9),
    # Generic high-entropy tokens (covers Firebase, custom JWTs, session tokens)
    (r'["\']([A-Za-z0-9_\-]{40,80})["\']', 0.7),
    # Android-specific: Google Maps API key
    (r'(?i)(google_maps_key|maps_api_key|com\.google\.android\.maps\.v2\.API_KEY)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', 0.9),
    # Facebook App Secret
    (r'(?i)(facebook_app_secret|fb_app_secret)\s*[:=]\s*["\']?([A-Za-z0-9]{32})', 1.0),
]

# ── High-value keywords for context-based detection ────────────────
SECRET_KEYWORDS = {
    "password", "passwd", "pwd", "secret", "token", "auth", "apikey",
    "api_key", "apikey", "apisecret", "api_secret", "client_secret",
    "access_key", "accesskey", "private_key", "privatekey",
    "refresh_token", "refreshtoken", "bearer", "authorization",
    "credential", "cred", "db_password", "dbpassword",
    "s3cret", "encryption_key", "encryptionkey",
    "jwt_secret", "jwttoken", "session_secret",
    "firebase_secret", "firebase_url",
}


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string. High entropy (>4.0) often
    indicates random/encoded content (tokens, keys, hashes)."""
    if not data:
        return 0.0
    data = data.strip()
    if not data:
        return 0.0
    # Only consider printable ASCII and hex/base64 characters
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 4)


def detect_secrets(text: str, context: str = "") -> list:
    """
    Scan a string (or concatenated UI text) for secrets.
    Returns a list of secret dicts with:
      type, value (redacted), entropy, pattern, confidence, context
    """
    findings = []

    # 1. Regex pattern matching
    for pattern, confidence in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            if len(value) < 4:
                continue
            entropy = shannon_entropy(value)
            findings.append({
                "type": "secret_pattern",
                "value": value[:8] + "..." + value[-4:] if len(value) > 16 else value[:4] + "...",
                "entropy": entropy,
                "pattern": pattern,
                "confidence": confidence,
                "context": context,
                "length": len(value),
            })

    # 2. High-entropy string detection (for strings > 20 chars)
    #    Split by common delimiters and test each token
    tokens = re.split(r'[\s,;:=\'\"{}()\[\]<>|\\/]+', text)
    for token in tokens:
        token = token.strip()
        if len(token) < 16 or len(token) > 256:
            continue
        # Skip if purely numeric or short hex
        if token.isdigit() or (len(token) < 24 and all(c in '0123456789abcdefABCDEF' for c in token)):
            continue
        entropy = shannon_entropy(token)
        if entropy > 4.5:
            findings.append({
                "type": "high_entropy",
                "value": token[:8] + "..." + token[-4:] if len(token) > 16 else token[:4] + "...",
                "entropy": entropy,
                "pattern": "shannon_entropy>4.5",
                "confidence": min(0.7, entropy / 8.0),
                "context": context,
                "length": len(token),
            })

    # 3. Keyword-context detection (surround text hints at a secret)
    #    Look for common patterns like `key=value` where key contains secret keywords
    keyword_kv = re.finditer(r'(?i)([a-z_]{3,50})\s*[:=]\s*["\']?([A-Za-z0-9_\-\./=+]{8,120})["\']?', text)
    for match in keyword_kv:
        key_name = match.group(1).lower()
        value = match.group(2)
        if any(kw in key_name for kw in SECRET_KEYWORDS):
            entropy = shannon_entropy(value)
            findings.append({
                "type": "keyword_context",
                "value": value[:8] + "..." + value[-4:] if len(value) > 16 else value[:4] + "...",
                "entropy": entropy,
                "pattern": f"keyword_context:{key_name}",
                "confidence": min(0.85, 0.5 + entropy * 0.08),
                "context": context,
                "length": len(value),
            })

    # Deduplicate by redacted value
    seen = set()
    unique = []
    for f in findings:
        key = f["type"] + "|" + f["value"] + "|" + f["pattern"][:30]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def score_secret_risk(findings: list) -> dict:
    """
    Aggregate secret findings into a risk score (0-100).
    Returns dict with overall_score, count_by_confidence, high_confidence_secrets.
    """
    if not findings:
        return {"overall_score": 0, "count_by_confidence": {}, "high_confidence_secrets": 0}

    # Score based on confidence and count
    total_confidence = sum(f["confidence"] for f in findings)
    high_conf = sum(1 for f in findings if f["confidence"] >= 0.9)
    medium_conf = sum(1 for f in findings if 0.5 <= f["confidence"] < 0.9)

    # Raw score: weighted sum capped at 100
    raw = min(100, total_confidence * 10 + high_conf * 15 + medium_conf * 5)

    return {
        "overall_score": round(raw, 1),
        "count_by_confidence": {
            "high": high_conf,
            "medium": medium_conf,
            "low": len(findings) - high_conf - medium_conf,
        },
        "high_confidence_secrets": high_conf,
        "total_findings": len(findings),
        "highest_entropy": max((f["entropy"] for f in findings), default=0),
    }


# ═════════════════════════════════════════════════════════════════════
# 2. VULNERABILITY PATTERN RECOGNITION
# ═════════════════════════════════════════════════════════════════════

class VulnerabilityScorer:
    """
    ML-lite vulnerability pattern recognition.
    Takes findings from static/dynamic analysis and produces a scored,
    ranked list of likely vulnerability classes.
    """
    # Feature vectors: (indicators -> vuln class, base_weight)
    VULN_PATTERNS = {
        "sql_injection": {
            "keywords": {"select", "insert", "update", "delete", "where", "from", "execsql",
                        "rawquery", "databas", "compileStatement", "cursor"},
            "weight": 0.8,
            "cwe": 89,
            "description": "Possible SQL injection via string concatenation in database queries",
        },
        "xss": {
            "keywords": {"webview", "loadurl", "loaddata", "javascript:", "<script",
                        "setjavascriptenabled", "evaluatejavascript", "addjavascriptinterface"},
            "weight": 0.7,
            "cwe": 79,
            "description": "Cross-site scripting through WebView content loading",
        },
        "hardcoded_secret": {
            "keywords": {"secret", "password", "apikey", "token", "credential", "private_key",
                        "jwt_secret", "encryptionkey", "auth_token"},
            "weight": 0.9,
            "cwe": 798,
            "description": "Hardcoded credentials or cryptographic keys in source",
        },
        "insecure_storage": {
            "keywords": {"sharedpreferences", "getsharedpreferences", "sqlite", "openordb",
                        "fileoutputstream", "context.getfilesdir", "getexternalstoragedir",
                        "modeworld_readable", "modeworld_writeable"},
            "weight": 0.75,
            "cwe": 200,
            "description": "Insecure local data storage (world-readable or unencrypted)",
        },
        "insecure_network": {
            "keywords": {"http://", "cleartext", "allowcleartext", "network_security_config",
                        "trustallcertificates", "setdefaulthostnameverifier",
                        "allowallhostnameverifier", "proxy()"},
            "weight": 0.85,
            "cwe": 319,
            "description": "Cleartext network traffic or insecure TLS configuration",
        },
        "dynamic_code_loading": {
            "keywords": {"dexclassloader", "pathclassloader", "urlclassloader",
                        "loadclass", "forgeclass", "invoke", "reflect", "getmethod",
                        "getdeclaredmethod", "setaccessible"},
            "weight": 0.8,
            "cwe": 470,
            "description": "Dynamic class loading or reflection-based code execution",
        },
        "webview_rce": {
            "keywords": {"addjavascriptinterface", "setjavascriptenabled",
                        "removedangerouspermissions", "webchromeclient", "webviewclient"},
            "weight": 0.9,
            "cwe": 749,
            "description": "WebView with JavaScript interface enabled (potential RCE)",
        },
        "root_detection_bypass": {
            "keywords": {"checkroot", "isrooted", "rootbeer", "su.exists", "findbinary",
                        "build.tags", "test-keys", "superuser"},
            "weight": 0.7,
            "cwe": 916,
            "description": "Root/jailbreak detection logic that may be bypassed",
        },
        "ssl_pinning_bypass": {
            "keywords": {"pin", "pinning", "certificatepinner", "trustmanager",
                        "x509", "checkclienttrusted", "checkservertrusted"},
            "weight": 0.75,
            "cwe": 295,
            "description": "SSL certificate validation or pinning implementation",
        },
        "intent_injection": {
            "keywords": {"getintent", "getstringextra", "getbooleanextra", "parsedata",
                        "intent.getdata", "getserializableextra", "setdata", "setclass"},
            "weight": 0.7,
            "cwe": 927,
            "description": "Intent handling with possible injection from external sources",
        },
    }

    def __init__(self):
        self.counter = defaultdict(float)
        self.evidence = defaultdict(list)

    def ingest_static_finding(self, finding: dict):
        """Score a static analysis finding (from hayo_auto.py or similar)."""
        text = json.dumps(finding).lower()
        title = (finding.get("title") or "").lower()
        detail = (finding.get("detail") or "").lower()
        combined = title + " " + detail + " " + text

        for vuln, config in self.VULN_PATTERNS.items():
            matches = sum(1 for kw in config["keywords"] if kw.lower() in combined)
            if matches > 0:
                score = min(config["weight"] * matches * 0.3, 1.0)
                self.counter[vuln] += score
                self.evidence[vuln].append({
                    "source": "static",
                    "title": finding.get("title", ""),
                    "matches": matches,
                })

    def ingest_dynamic_finding(self, finding: dict):
        """Score a dynamic analysis finding (from Frida/agent.py)."""
        ftype = (finding.get("type") or "").lower()
        title = (finding.get("title") or "").lower()
        evidence_str = json.dumps(finding.get("evidence", [])).lower()
        combined = ftype + " " + title + " " + evidence_str

        for vuln, config in self.VULN_PATTERNS.items():
            matches = sum(1 for kw in config["keywords"] if kw.lower() in combined)
            if matches > 0:
                score = min(config["weight"] * matches * 0.25, 1.0)
                self.counter[vuln] += score
                self.evidence[vuln].append({
                    "source": "dynamic",
                    "type": finding.get("type", ""),
                    "title": finding.get("title", ""),
                })

    def get_ranked_vulnerabilities(self, min_score=0.3) -> list:
        """Return ranked list of likely vulnerabilities (score 0.0-1.0)."""
        results = []
        for vuln, score in sorted(self.counter.items(), key=lambda x: -x[1]):
            if score >= min_score:
                cfg = self.VULN_PATTERNS[vuln]
                results.append({
                    "vulnerability": vuln,
                    "cwe": cfg["cwe"],
                    "confidence": round(min(score, 1.0), 2),
                    "description": cfg["description"],
                    "evidence": self.evidence[vuln][-5:],
                })
        return results

    def get_summary(self) -> dict:
        ranked = self.get_ranked_vulnerabilities()
        return {
            "total_candidates": len(ranked),
            "high_confidence": sum(1 for r in ranked if r["confidence"] >= 0.7),
            "ranked": ranked,
        }


# ═════════════════════════════════════════════════════════════════════
# 3. INTELLIGENT UI CRAWLING GUIDANCE
# ═════════════════════════════════════════════════════════════════════

class CrawlState:
    """Represents a single UI state discovered during crawling."""
    def __init__(self, activity: str, screenshot_hash: str = "",
                 view_hierarchy: str = "", ui_elements: list = None):
        self.activity = activity
        self.screenshot_hash = screenshot_hash
        self.view_hierarchy = view_hierarchy
        self.ui_elements = ui_elements or []
        self.visited_at = datetime.now()
        self.secrets_found = []
        self.score = 0.0

    def compute_state_hash(self) -> str:
        """Deterministic hash for state deduplication."""
        parts = [
            self.activity,
            self.screenshot_hash[:16],
            str(sorted(e.get("text", "") for e in self.ui_elements)[:10]),
            str(sorted(e.get("resource_id", "") for e in self.ui_elements)[:10]),
        ]
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def compute_value_score(self) -> float:
        """
        Estimate the security value of this state.
        Higher score = more interesting for pentesting.
        """
        score = 0.0
        text_all = " ".join(e.get("text", "") for e in self.ui_elements)
        id_all = " ".join(e.get("resource_id", "") for e in self.ui_elements)

        # + for sensitive keywords in text or IDs
        high_value = {"login", "password", "email", "token", "key", "secret",
                      "payment", "credit", "card", "ssn", "admin", "setting",
                      "pin", "otp", "verify", "auth", "subscription",
                      "premium", "unlock", "vip"}
        for kw in high_value:
            if kw in text_all.lower() or kw in id_all.lower():
                score += 2.0

        # + for forms / input fields
        input_count = sum(1 for e in self.ui_elements if e.get("class", "").endswith("EditText"))
        clickable_count = sum(1 for e in self.ui_elements if e.get("clickable"))
        score += input_count * 1.5 + clickable_count * 0.5

        # + for webviews
        if any("webview" in e.get("class", "").lower() for e in self.ui_elements):
            score += 5.0

        # + for recently discovered secrets
        score += len(self.secrets_found) * 3.0

        self.score = score
        return score


class IntelligentCrawler:
    """
    ML-guided UI crawler that prioritizes high-value states,
    avoids infinite loops via state hashing, and automatically
    detects secrets in UI elements.
    """
    def __init__(self, package: str):
        self.package = package
        self.seen_states = {}  # state_hash -> CrawlState
        self.exploration_queue = []  # priority queue
        self.secrets_found = []
        self.activity_coverage = defaultdict(int)
        self.secret_detector = detect_secrets
        self._visit_count = 0

    def is_new_state(self, state: CrawlState) -> bool:
        """Check if this state is new (dedup via hash)."""
        h = state.compute_state_hash()
        return h not in self.seen_states

    def record_state(self, state: CrawlState):
        """Record a visited state and extract any visible secrets."""
        h = state.compute_state_hash()
        if h in self.seen_states:
            return False
        self.seen_states[h] = state
        self.activity_coverage[state.activity] += 1
        self._visit_count += 1

        # Scan UI text for secrets
        for elem in state.ui_elements:
            text = elem.get("text", "")
            if text and len(text) > 8:
                secrets = self.secret_detector(text, context=state.activity)
                for s in secrets:
                    state.secrets_found.append(s)
                    self.secrets_found.append({
                        **s,
                        "activity": state.activity,
                        "element_id": elem.get("resource_id", ""),
                    })

        state.compute_value_score()
        return True

    def get_next_target(self) -> dict:
        """
        Get the next best UI element to interact with.
        Prioritizes: high-value elements > unvisited > unexplored activities.
        """
        if not self.exploration_queue:
            return None
        # Sort by score descending (highest value first)
        self.exploration_queue.sort(key=lambda x: -x.get("_priority", 0))
        return self.exploration_queue.pop(0)

    def build_exploration_queue(self, elements: list, current_activity: str):
        """
        Build/refresh the exploration queue from available UI elements.
        Assigns ML-informed priority scores.
        """
        self.exploration_queue = []
        for elem in elements:
            text = (elem.get("text") or "").lower()
            rid = (elem.get("resource_id") or "").lower()
            clazz = (elem.get("class") or "").lower()
            clickable = elem.get("clickable", False)
            checked = elem.get("checked", False)

            priority = 0.0

            # + for high-value keywords
            for kw in {"login", "sign in", "submit", "next", "continue",
                       "allow", "grant", "accept", "enable", "unlock",
                       "get started", "premium", "upgrade", "subscribe"}:
                if kw in text or kw in rid:
                    priority += 3.0

            # + for EditText (input fields)
            if "edittext" in clazz:
                priority += 2.0
                if "password" in rid or "password" in text:
                    priority += 3.0

            # + for unvisited activities (linked via intents)
            if rid and any(act not in rid.lower() for act in self.activity_coverage):
                priority += 1.0

            # - for already-visited dead ends
            if "dismiss" in text or "cancel" in text or "close" in text:
                priority -= 2.0

            # + for buttons with security relevance
            if "button" in clazz:
                for kw in {"bypass", "debug", "secret", "token", "admin", "hidden"}:
                    if kw in text or kw in rid:
                        priority += 5.0

            elem["_priority"] = max(priority, 0)
            if clickable and not checked:
                self.exploration_queue.append(elem)

    def get_coverage_report(self) -> dict:
        """Return coverage statistics."""
        return {
            "package": self.package,
            "states_visited": len(self.seen_states),
            "activities_covered": dict(self.activity_coverage),
            "secrets_discovered": len(self.secrets_found),
            "secrets": self.secrets_found[:20],
        }


# ═════════════════════════════════════════════════════════════════════
# 4. INTEGRATION API
# ═════════════════════════════════════════════════════════════════════

class MLEngine:
    """
    Top-level ML integration class combining secret detection,
    vulnerability scoring, and intelligent crawling.
    """
    def __init__(self, package: str = ""):
        self.package = package
        self.vuln_scorer = VulnerabilityScorer()
        self.crawler = IntelligentCrawler(package) if package else None
        self.secrets_log = []

    def scan_text(self, text: str, context: str = "unknown") -> list:
        """Scan arbitrary text for secrets. Returns findings."""
        findings = detect_secrets(text, context)
        for f in findings:
            self.secrets_log.append({**f, "scanned_at": datetime.now().isoformat()})
        return findings

    def scan_static_findings(self, findings: list):
        """Batch ingest static analysis findings for vulnerability scoring."""
        for f in findings:
            self.vuln_scorer.ingest_static_finding(f)

    def scan_dynamic_findings(self, findings: list):
        """Batch ingest dynamic analysis findings."""
        for f in findings:
            self.vuln_scorer.ingest_dynamic_finding(f)

    def get_risk_assessment(self) -> dict:
        """Comprehensive risk assessment from all ML subsystems."""
        secret_risk = score_secret_risk(self.secrets_log)
        vuln_summary = self.vuln_scorer.get_summary()
        return {
            "package": self.package,
            "secret_risk": secret_risk,
            "vulnerability_assessment": vuln_summary,
            "overall_risk_score": round(
                secret_risk.get("overall_score", 0) * 0.4 +
                (sum(r["confidence"] for r in vuln_summary.get("ranked", [])) / max(len(vuln_summary.get("ranked", [])), 1)) * 60,
                1
            ),
        }


if __name__ == "__main__":
    print("=== ML Engine Self-Test ===")

    # Test secret detection
    test_texts = [
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.d1fVxY4RlQ",
        "api_key = sk-proj-XXXXXXXXXxyYYYYYYYYYzzZZZZZZZZZabcdefgh12345678",
        "password = super_secret_123!",
        "AWS Access Key: AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0",
        "jdbc:postgresql://db.internal:5432/prod?user=admin&password=secret123",
        "Just a normal chat message with no secrets",
        "com.google.android.maps.v2.API_KEY = AIzaSyD-EXAMPLE_KEY_12345",
    ]
    for text in test_texts:
        secrets = detect_secrets(text, "test")
        if secrets:
            risk = score_secret_risk(secrets)
            print(f"  [{risk['overall_score']:5.1f}] {text[:50]}... -> {len(secrets)} secrets")
            for s in secrets[:2]:
                print(f"         {s['type']:20} entropy={s['entropy']:.2f} conf={s['confidence']:.2f}")

    # Test vulnerability scoring
    scorer = VulnerabilityScorer()
    scorer.ingest_static_finding({"title": "Found RawQuery with string concatenation", "detail": "execSQL"})
    scorer.ingest_static_finding({"title": "WebView with JavaScript enabled", "detail": "setJavaScriptEnabled(true)"})
    scorer.ingest_dynamic_finding({"type": "command_exec", "title": "Dynamic class loading via DexClassLoader",
                                   "evidence": [{"label": "dex", "value": "payload.dex"}]})
    ranked = scorer.get_ranked_vulnerabilities()
    print(f"\n  Vulnerability candidates: {len(ranked)}")
    for r in ranked[:5]:
        print(f"    CWE-{r['cwe']} ({r['confidence']:.2f}): {r['vulnerability']}")

    # Test intelligent crawler
    ml = MLEngine("com.example.app")
    findings = ml.scan_text(test_texts[0], "LoginActivity")
    findings += ml.scan_text(test_texts[1], "ConfigActivity")
    assessment = ml.get_risk_assessment()
    print(f"\n  Overall risk score: {assessment['overall_risk_score']:.1f}/100")
    print(f"  Secret risk: {assessment['secret_risk']['overall_score']:.1f}/100")
    print(f"  Vuln candidates: {assessment['vulnerability_assessment']['total_candidates']}")
    print("ML Engine OK")
