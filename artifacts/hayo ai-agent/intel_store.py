#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Intelligence Store / Blackboard (intel_store.py)
===============================================================
The shared "information aggregation container" every phase reads from and writes
to. Static analysis seeds it; the dynamic engine + AI explorer keep enriching it
live; the agent reasons over it to decide the next move and to correlate secrets
against endpoints. Every fact keeps its PROVENANCE (which phase found it) so the
final report is credible and the agent can trust-rank what it sees.

Thread-safe, de-duplicated, and persistable to loot/intel_<pkg>.json.
"""
import json
import os
import threading
import time

# canonical fact kinds (free-form is allowed, but these are the ones the agent
# and report understand best)
KINDS = ("package", "secret", "credential", "endpoint", "url", "cloud_id",
         "klass", "method", "hook", "ui_screen", "cred_test", "finding", "note")


class IntelStore:
    def __init__(self, package="", loot_dir=None):
        self.package = package
        self._lock = threading.RLock()
        self._facts = {}          # kind -> { dedup_key -> fact }
        self.findings = []        # structured findings (typed, with severity)
        self._subs = []           # callbacks(kind, value, fact) fired on NEW facts
        self._loot = loot_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "loot")
        os.makedirs(self._loot, exist_ok=True)
        self.started = time.time()

    # ── feedback loop: subscribe to NEW facts ────────────────────────────────
    def on_new(self, callback):
        """Register callback(kind, value, fact) fired ONCE per newly-seen fact.
        This is what lets an advanced phase react to what an earlier phase found
        (e.g. test a just-captured token against a statically-discovered host)."""
        with self._lock:
            self._subs.append(callback)

    def _emit(self, kind, value, fact):
        for cb in list(self._subs):
            try:
                cb(kind, value, fact)
            except Exception:
                pass

    # ── write ───────────────────────────────────────────────────────────────
    def add(self, kind, value, source="unknown", note="", **meta):
        """Add a fact. Returns True if NEW (not seen before)."""
        value = ("" if value is None else str(value)).strip()
        if not value:
            return False
        key = value[:400]
        with self._lock:
            bucket = self._facts.setdefault(kind, {})
            if key in bucket:
                # enrich provenance without duplicating
                fact = bucket[key]
                if source and source not in fact["sources"]:
                    fact["sources"].append(source)
                if note and note not in fact.get("notes", []):
                    fact.setdefault("notes", []).append(note)
                fact.update(meta)
                return False
            fact = {"value": value, "sources": [source] if source else [],
                    "notes": [note] if note else [], "ts": round(time.time() - self.started, 1),
                    **meta}
            bucket[key] = fact
        self._emit(kind, value, fact)   # outside the lock: subscribers may re-enter add()
        return True

    def add_finding(self, finding):
        """finding = {type,title,severity,detail,evidence,phase,...}"""
        with self._lock:
            key = str(finding.get("type", "")) + "|" + json.dumps(finding.get("evidence", []),
                                                                  ensure_ascii=False, sort_keys=True)[:200]
            if any(f.get("_k") == key for f in self.findings):
                return False
            finding = dict(finding); finding["_k"] = key
            self.findings.append(finding)
            t = finding.get("type", "")
        # mirror useful facts so the agent can correlate (add() emits + is lock-safe)
        for ev in finding.get("evidence", []):
            if isinstance(ev, dict) and ev.get("sensitive"):
                self.add("secret", ev.get("value"), source=finding.get("phase", "dynamic"),
                         note=finding.get("title", t))
        self._emit("finding", key, finding)
        return True

    # ── read ─────────────────────────────────────────────────────────────────
    def query(self, kind):
        with self._lock:
            return [dict(f) for f in self._facts.get(kind, {}).values()]

    def values(self, kind):
        with self._lock:
            return [f["value"] for f in self._facts.get(kind, {}).values()]

    def all(self):
        with self._lock:
            return {k: [dict(v) for v in b.values()] for k, b in self._facts.items()}

    def counts(self):
        with self._lock:
            c = {k: len(b) for k, b in self._facts.items()}
            c["finding"] = len(self.findings)
            return c

    def summary(self, max_per_kind=8):
        """Compact, token-friendly snapshot for the agent's context."""
        with self._lock:
            lines = [f"IntelStore for {self.package or '?'} — " +
                     ", ".join(f"{k}:{len(b)}" for k, b in self._facts.items()) +
                     f", findings:{len(self.findings)}"]
            for k in ("secret", "credential", "endpoint", "url", "cloud_id", "hook", "ui_screen"):
                b = self._facts.get(k)
                if not b:
                    continue
                vals = [v["value"][:90] for v in list(b.values())[:max_per_kind]]
                lines.append(f"  {k}: " + " | ".join(vals))
            sev = {}
            for f in self.findings:
                s = str(f.get("severity", "info")).lower(); sev[s] = sev.get(s, 0) + 1
            if sev:
                lines.append("  findings by severity: " + ", ".join(f"{s}={n}" for s, n in sev.items()))
            return "\n".join(lines)

    # ── agent-facing views + endpoint bookkeeping ────────────────────────────
    def _mask(self, v, keep=6):
        s = str(v)
        return s if len(s) <= keep + 4 else s[:keep] + "…" + s[-4:]

    def untested_endpoints(self, limit=20):
        with self._lock:
            out = []
            for kind in ("endpoint", "url"):
                for f in self._facts.get(kind, {}).values():
                    if not f.get("tested"):
                        out.append(f["value"])
            return out[:limit]

    def mark_tested(self, url, result):
        with self._lock:
            for kind in ("endpoint", "url"):
                f = self._facts.get(kind, {}).get(str(url)[:400])
                if f:
                    f["tested"] = True
                    f["result"] = result
                    return

    def brain_context(self, n=15):
        """Compact JSON-able view handed to the LLM agent each decision."""
        with self._lock:
            def vals(kind):
                return [f["value"] for f in self._facts.get(kind, {}).values()]
            secrets = [{"kind": (f.get("notes") or ["?"])[0], "masked": self._mask(f["value"]),
                        "verified": f.get("verified", False)}
                       for f in list(self._facts.get("secret", {}).values())[:n]]
            creds = [self._mask(v) for v in vals("credential")[:n]]
            hosts = list(dict.fromkeys(vals("url") + vals("endpoint")))
            hosts = [h for h in hosts if "://" in h][:n]
            untested = self.untested_endpoints(n)
            screens = vals("ui_screen")[-n:]
            hooks = vals("hook")[:n]
            # الشاشات الداخلية (post-login) للقفز إليها متجاوزين بوابة الدخول
            post_login = vals("post_login_activity")[:n]
            sev = {}
            for f in self.findings:
                s = str(f.get("severity", "info")).lower(); sev[s] = sev.get(s, 0) + 1
        return {
            "known_secrets": secrets,
            "captured_credentials": creds,
            "backend_urls": hosts,
            "untested_endpoints": untested,
            "installed_hooks": hooks,
            "visited_screens": screens,
            "activities": post_login,   # أهداف القفز (تجاوز الدخول)
            "findings_by_severity": sev,
            "counts": self.counts(),
        }

    # ── persistence ───────────────────────────────────────────────────────────
    def save(self, path=None):
        path = path or os.path.join(self._loot, f"intel_{self.package or 'session'}.json")
        with self._lock:
            data = {"package": self.package, "facts": self.all(), "findings": self.findings}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return path

    def load(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        with self._lock:
            self.package = data.get("package", self.package)
            for kind, facts in (data.get("facts") or {}).items():
                for fct in facts:
                    self.add(kind, fct.get("value"), source="loaded")
            for fnd in data.get("findings") or []:
                self.add_finding(fnd)
        return self


if __name__ == "__main__":
    s = IntelStore("com.demo.app")
    print("new:", s.add("endpoint", "https://api.demo/login", "static"))
    print("dup:", s.add("endpoint", "https://api.demo/login", "dynamic"))
    s.add("secret", "AIzaSyDEMO", "static", note="google key")
    s.add_finding({"type": "secret_captured", "severity": "critical", "title": "key",
                   "evidence": [{"label": "k", "value": "AIzaSyDEMO2", "sensitive": True}], "phase": "dynamic"})
    print(s.summary())
    print("saved:", s.save())
