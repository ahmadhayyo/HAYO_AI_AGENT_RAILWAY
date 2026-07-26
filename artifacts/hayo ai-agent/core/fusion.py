#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepSeek Core v5 — core/fusion.py
Static + Dynamic Analysis Fusion Engine.
Reads the static analysis report (hayo-pentest-report.json) and pre-populates
the exploit queue with API keys, endpoints, project IDs, and bucket names BEFORE
the dynamic phase launches the app.

This bridges the gap between static APK analysis and dynamic Frida-based exploitation,
ensuring no finding from static analysis goes unexploited.
"""
import json, os, re, sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# ─── Secret patterns (same as brain.py) ───
_HARVEST_PATTERNS = [
    ("google_api_key",  re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("openai_key",      re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("claude_key",      re.compile(r"sk-ant-[A-Za-z0-9]{32,}")),
    ("huggingface_key", re.compile(r"hf_[A-Za-z0-9]{32,}")),
    ("aws_key",         re.compile(r"(?:AKIA|ASIA|AGPA|AROA|AIDA)[0-9A-Z]{16}")),
    ("stripe_key",      re.compile(r"[sr]k_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("jwt",             re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}")),
    ("bearer",          re.compile(r"[Bb]earer\s+([A-Za-z0-9_\-\.=]{20,})")),
]

# ─── Project ID patterns ───
_PROJECT_PATTERNS = [
    re.compile(r'project[_\-]?\s*id["\']?\s*[:=]\s*["\']?([a-z0-9-]{6,})["\']?\s', re.I),
    re.compile(r'gcm[_\-]default[_\-]sender[_\-]id["\']?\s*[:=]\s*["\']?(\d+)["\']?'),
    re.compile(r'firebase[_\-]?url["\']?\s*[:=]\s*["\']?https://([a-z0-9-]+)\.', re.I),
    re.compile(r'project_number["\']?\s*[:=]\s*["\']?(\d+)["\']?'),
]

# ─── Bucket patterns ───
_BUCKET_PATTERNS = [
    re.compile(r'storage[_\-]?bucket["\']?\s*[:=]\s*["\']?([a-z0-9-]+\.appspot\.com)["\']?', re.I),
    re.compile(r'bucket["\']?\s*[:=]\s*["\']?([a-z0-9-]+)["\']?', re.I),
]


def extract_secrets_from_blob(blob):
    """Extract all secrets from a text blob."""
    secrets = []
    if not blob:
        return secrets
    for kind, rx in _HARVEST_PATTERNS:
        for m in rx.findall(blob):
            val = m if isinstance(m, str) else m[0]
            secrets.append({"kind": kind, "value": val})
    return secrets


def extract_project_ids(blob):
    """Extract Firebase project IDs from text."""
    projects = []
    if not blob:
        return projects
    for rx in _PROJECT_PATTERNS:
        for m in rx.findall(blob):
            if m and len(m) > 5 and m not in projects:
                projects.append(m)
    return projects


def extract_buckets(blob):
    """Extract Storage bucket names from text."""
    buckets = []
    if not blob:
        return buckets
    for rx in _BUCKET_PATTERNS:
        for m in rx.findall(blob):
            if m and m not in buckets:
                buckets.append(m)
    return buckets


def fuse(static_report_path=None):
    """Main fusion function. Returns structured dict with all extracted intel."""
    result = {
        "fusion_timestamp": datetime.now().isoformat(timespec="seconds"),
        "secrets": [],
        "project_ids": [],
        "buckets": [],
        "endpoints": [],
        "findings": [],
        "source": None,
    }

    # Try to find the static report
    candidates = [
        static_report_path,
        os.path.join(ROOT, "hayo-pentest-report.json"),
        os.path.join(ROOT, "loot", "hayo-pentest-report.json"),
        os.path.join(ROOT, "pentest-report.json"),
        os.path.join(ROOT, "artifacts", "pentest-report.json"),
    ]

    for fp in candidates:
        if fp and os.path.exists(fp):
            result["source"] = fp
            break

    if not result["source"]:
        return result

    with open(result["source"], "r", encoding="utf-8") as f:
        data = json.load(f)

    result["findings"] = data.get("findings", [])

    # 1) Extract from findings
    for finding in data.get("findings", []):
        detail = finding.get("detail", "")
        evidence = json.dumps(finding.get("evidence", []), ensure_ascii=False)
        blob = detail + " " + evidence

        secrets = extract_secrets_from_blob(blob)
        for s in secrets:
            s["source"] = f"finding:{finding.get('type','unknown')}"
            if s not in result["secrets"]:
                result["secrets"].append(s)

        projects = extract_project_ids(blob)
        for p in projects:
            if p not in result["project_ids"]:
                result["project_ids"].append(p)

        buckets = extract_buckets(blob)
        for b in buckets:
            if b not in result["buckets"]:
                result["buckets"].append(b)

    # 2) Extract from top-level config keys
    config_keys = [
        ("google_api_key", "google_api_key"),
        ("firebase_api_key", "google_api_key"),
        ("openai_api_key", "openai_key"),
        ("claude_api_key", "claude_key"),
        ("huggingface_api_key", "huggingface_key"),
        ("aws_access_key", "aws_key"),
        ("stripe_key", "stripe_key"),
    ]

    for cfg_key, secret_kind in config_keys:
        val = data.get(cfg_key) or data.get("config", {}).get(cfg_key)
        if val and isinstance(val, str) and len(val) > 10:
            entry = {"kind": secret_kind, "value": val, "source": f"config:{cfg_key}"}
            if entry not in result["secrets"]:
                result["secrets"].append(entry)

    # 3) Extract from full text of report
    full_text = json.dumps(data, ensure_ascii=False)
    for s in extract_secrets_from_blob(full_text):
        if s not in result["secrets"]:
            s["source"] = "full_text"
            result["secrets"].append(s)
    for p in extract_project_ids(full_text):
        if p not in result["project_ids"]:
            result["project_ids"].append(p)
    for b in extract_buckets(full_text):
        if b not in result["buckets"]:
            result["buckets"].append(b)

    # 4) Extract endpoints
    for finding in data.get("findings", []):
        evidence = finding.get("evidence", [])
        for ev in evidence:
            if isinstance(ev, dict):
                val = ev.get("value", str(ev))
                if isinstance(val, str) and ("http" in val.lower() or "api" in val.lower()):
                    if val not in result["endpoints"] and len(val) > 10:
                        result["endpoints"].append(val)

    return result


def main():
    """CLI entry point."""
    ap = argparse.ArgumentParser(description="DeepSeek Core v5 Fusion Engine")
    ap.add_argument("--report", help="Path to static analysis report JSON")
    a = ap.parse_args()
    result = fuse(a.report)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
