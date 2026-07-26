#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HAYO Cipher-7 Behavioral Analysis Engine (Directive 2.2)"""
import json, time, threading, re, math
from collections import defaultdict, deque
from datetime import datetime

EVENT_CATEGORIES = {
    "network": {"http_request","native_socket","cleartext_request","dns_query"},
    "crypto": {"static_key_runtime","encryption_op","decryption_op","signing_op"},
    "storage": {"file_read","file_write","file_delete","sql_query","shared_pref_access"},
    "auth": {"token_access","credential_access","biometric_auth","auth_attempt"},
    "ipc": {"intent_launch","content_provider_access","service_bind","broadcast_send"},
    "code_load": {"dynamic_code_load","reflective_call","class_dex_load"},
    "ui": {"activity_launch","crawler_target","ui_interaction"},
    "billing": {"subscription_bypass","billing_api_call","premium_check"},
    "system": {"command_exec","native_lib_load","runtime_exec","system_property_read"},
    "secret": {"secret_captured","deobfuscated_string","high_entropy_string"},
}
CATEGORY_FOR_EVENT = {}
for cat, events in EVENT_CATEGORIES.items():
    for e in events: CATEGORY_FOR_EVENT[e] = cat

class NormalizedEvent:
    """Standardized event for the behavioral pipeline."""
    __slots__ = ("timestamp","event_type","category","source","severity","title","details","app_package","stack_trace","raw")
    def __init__(self, event_type, source="frida", severity="info", title="", details=None, app_package="", stack_trace=""):
        self.timestamp = time.time()
        self.event_type = event_type
        self.category = CATEGORY_FOR_EVENT.get(event_type, "unknown")
        self.source = source; self.severity = severity; self.title = title
        self.details = details or {}; self.app_package = app_package; self.stack_trace = stack_trace; self.raw = None
    def to_dict(self):
        return {"ts":self.timestamp,"ts_human":datetime.fromtimestamp(self.timestamp).isoformat(),
                "type":self.event_type,"category":self.category,"source":self.source,
                "severity":self.severity,"title":self.title,"details":self.details,"app_package":self.app_package}
    @classmethod
    def from_frida_message(cls, msg, app_package=""):
        kind = msg.get("kind") or msg.get("type","")
        if kind == "finding":
            etype = msg.get("type","unknown"); sev = msg.get("severity","medium")
            title = msg.get("title",""); evidence = msg.get("evidence") or msg.get("detail","")
            details = {}
            if isinstance(evidence, list):
                for ev in evidence:
                    if isinstance(ev, dict): details[ev.get("label","value")] = ev.get("value","")
            elif isinstance(evidence, str): details["detail"] = evidence[:300]
            return cls(etype, source="frida", severity=sev, title=title, details=details, app_package=app_package)
        elif kind == "log":
            return cls("log_message", source="frida", severity="info", title=str(msg.get("message","")), app_package=app_package)
        elif kind == "premium":
            return cls("billing_api_call", source="frida", severity="high",
                       title="Premium: "+str(msg.get("detail","")), details={"kind":msg.get("kind","")}, app_package=app_package)
        elif kind == "waf_bypass":
            return cls("waf_operation", source="frida", severity="info",
                       title="WAF: "+str(msg.get("kind","")), app_package=app_package)
        return cls("unknown", source="frida", title=str(msg), app_package=app_package)

class BaselineProfile:
    """Profiles normal app behavior during un-instrumented run."""
    def __init__(self):
        self.event_counts = defaultdict(int)
        self.api_sequences = []
        self.network_destinations = defaultdict(int)
        self.ui_activities = defaultdict(int)
        self.file_access_patterns = defaultdict(int)
        self.event_rate_per_second = []
        self.start_time = None; self.end_time = None
    def record_event(self, event):
        if self.start_time is None: self.start_time = event.timestamp
        self.end_time = event.timestamp
        self.event_counts[event.event_type] += 1
        self.event_rate_per_second.append(event.timestamp)
        if event.category == "network":
            host = event.details.get("ip") or event.details.get("host","unknown")
            self.network_destinations[f"{host}:{event.details.get('port','80')}"] += 1
        if event.category == "ui":
            self.ui_activities[event.details.get("activity",event.title)] += 1
        if event.category == "storage":
            path = event.details.get("path",event.title)
            self.file_access_patterns["/".join(path.split("/")[:3]) if "/" in path else path] += 1
        if event.event_type == "reflective_call":
            self.api_sequences.append(event.details.get("method",event.title))
    def is_baseline_ready(self, min_events=50, min_duration=2.0):
        return len(self.event_rate_per_second) >= min_events and (self.end_time-self.start_time or 0) >= min_duration
    def get_event_rate(self):
        if not self.start_time or not self.end_time: return 0.0
        return len(self.event_rate_per_second) / max(self.end_time-self.start_time, 1.0)
    def get_summary(self):
        return {"duration": round(self.end_time-self.start_time,1) if self.start_time else 0,
                "total_events": sum(self.event_counts.values()),
                "event_types": dict(self.event_counts),
                "event_rate": round(self.get_event_rate(), 2),
                "network_destinations": dict(sorted(self.network_destinations.items(), key=lambda x:-x[1])[:20]),
                "ui_activities": dict(self.ui_activities),
                "api_sequences": self.api_sequences[-50:]}

class AnomalyDetector:
    """Compares live event stream against baseline, flags statistical deviations."""
    def __init__(self, baseline=None, stddev_threshold=3.0):
        self.baseline = baseline or BaselineProfile()
        self.stddev_threshold = stddev_threshold
        self.anomalies = []
        self._event_buffer = deque(maxlen=1000)
        self._rate_window = deque(maxlen=100)
        self._network_seen = set()
        self._lock = threading.Lock()
    def set_baseline(self, baseline): self.baseline = baseline
    def analyze_event(self, event):
        findings = []
        self._event_buffer.append(event)
        self._rate_window.append(event.timestamp)
        with self._lock:
            # Unexpected event type
            if event.event_type not in self.baseline.event_counts and event.event_type != "unknown":
                if self.baseline.start_time is not None:
                    findings.append({"type":"unexpected_event_type","severity":"medium",
                                     "title":f"Unexpected: {event.event_type} in {event.category}","event":event.to_dict()})
            # Unexpected network destination
            if event.category == "network":
                host = event.details.get("ip") or event.details.get("host",""); port = event.details.get("port","")
                dest = f"{host}:{port}"
                if dest != ":" and dest not in self._network_seen:
                    self._network_seen.add(dest)
                    if self.baseline.start_time is not None and dest not in self.baseline.network_destinations:
                        findings.append({"type":"unexpected_network_dest","severity":"high","title":f"New dest: {dest}","event":event.to_dict()})
            # Event rate anomaly
            if len(self._rate_window) >= 10:
                base_rate = self.baseline.get_event_rate()
                if base_rate > 0:
                    wd = max(self._rate_window[-1]-self._rate_window[0], 0.1)
                    cur = len(self._rate_window)/wd
                    if cur > base_rate*5 and base_rate > 0.5:
                        findings.append({"type":"event_rate_anomaly","severity":"medium",
                                         "title":f"Rate spike: {cur:.1f}/{base_rate:.1f}","event":event.to_dict()})
            # Sensitive command execution
            if event.event_type == "command_exec":
                cmd = event.details.get("cmd") or event.details.get("detail","")
                sus = ["su","chmod","mount","remount","chown","dd","ptrace","pm grant","app_process","zygote"]
                if any(k in cmd.lower() for k in sus):
                    findings.append({"type":"sensitive_command","severity":"critical",
                                     "title":f"Sensitive cmd: {cmd[:100]}","event":event.to_dict()})
            # Dynamic code loading
            if event.event_type == "dynamic_code_load":
                findings.append({"type":"dynamic_code_load","severity":"high",
                                 "title":"Dynamic code: "+event.title,"event":event.to_dict()})
            # Reflection burst detection
            if event.event_type == "reflective_call":
                cnt = sum(1 for e in self._event_buffer if e.event_type=="reflective_call" and time.time()-e.timestamp<5)
                if cnt >= 10:
                    findings.append({"type":"reflection_burst","severity":"high",
                                     "title":f"{cnt}+ reflective/5s","event":event.to_dict()})
        if findings: self.anomalies.extend(findings)
        return findings
    def get_summary(self):
        by_type = defaultdict(int)
        for a in self.anomalies: by_type[a["type"]] += 1
        return {"total_anomalies":len(self.anomalies),"by_type":dict(by_type),"recent":self.anomalies[-20:]}

class HeuristicRule:
    """Single user-definable heuristic rule for behavioral matching."""
    def __init__(self, name, conditions, action, description=""):
        self.name = name; self.conditions = conditions; self.action = action
        self.description = description; self.matches = 0
    def evaluate(self, event):
        for field, op, value in self.conditions:
            actual = self._resolve(event, field)
            if not self._cmp(actual, op, value): return False
        self.matches += 1; return True
    def _resolve(self, event, field):
        val = event.to_dict()
        for p in field.split("."):
            if isinstance(val, dict): val = val.get(p, None)
            else: return None
        return val
    def _cmp(self, a, op, e):
        if a is None: return False
        if op == "eq": return a == e
        if op == "neq": return a != e
        if op == "contains": return e in str(a)
        if op == "regex": return bool(re.search(e, str(a)))
        if op == "gt":
            try: return float(a) > float(e)
            except: return False
        if op == "lt":
            try: return float(a) < float(e)
            except: return False
        if op == "in": return a in e
        return False

class RuleEngine:
    """Manages heuristic rules against event stream."""
    def __init__(self): self.rules = []; self._cbs = []
    def add_rule(self, r): self.rules.append(r)
    def add_alert_callback(self, cb): self._cbs.append(cb)
    def evaluate(self, event):
        matched = []
        for r in self.rules:
            if r.evaluate(event):
                matched.append(r)
                for cb in self._cbs:
                    try: cb(r, event)
                    except: pass
        return matched
    def load_default_rules(self):
        defaults = [
            HeuristicRule("sensitive_data_over_http",[("details.url","regex","^http://"),("category","eq","network"),("details.auth","neq","(none)")],"alert","Credentials over HTTP"),
            HeuristicRule("suspicious_file_access",[("category","eq","storage"),("details.path","regex","(/data/data/|/sdcard/Android|shared_prefs)"),("severity","eq","high")],"alert","Sensitive path access"),
            HeuristicRule("root_detection",[("details.cmd","regex","which\\s+su|test\\s+-f\\s+/sbin|id|stat\\s+/system"),("event_type","eq","command_exec")],"alert","Root check"),
            HeuristicRule("debugger_check",[("details.cmd","regex","android\\.os\\.Debug|isDebuggerConnected|WaitForDebugger"),("event_type","eq","reflective_call")],"alert","Debugger check"),
            HeuristicRule("firebase_leak",[("details.url","regex","firebaseio\\.com|firestore\\.google|firebasestorage"),("category","eq","network")],"alert","Firebase access"),
            HeuristicRule("emulator_detection",[("details.cmd","regex","ro\\.kernel\\.qemu|ro\\.product\\.model.*sdk|gsm\\.sim\\.operator\\.numeric"),("event_type","eq","command_exec")],"alert","Emulator check"),
            HeuristicRule("sensitive_reflection",[("event_type","eq","reflective_call"),("details.method","regex","getDeclaredMethod|setAccessible|getDeclaredField")],"alert","Reflection bypass"),
        ]
        for r in defaults: self.add_rule(r)

class BehaviorAnalyzer:
    """Top-level integration: normalization + baseline + anomaly + rules."""
    def __init__(self, app_package=""):
        self.app_package = app_package
        self.baseline = BaselineProfile()
        self.detector = AnomalyDetector(baseline=self.baseline)
        self.rule_engine = RuleEngine()
        self.rule_engine.load_default_rules()
        self._baseline_phase = True
        self._events = deque(maxlen=5000)
        self._lock = threading.Lock()
    @property
    def is_baseline_phase(self): return self._baseline_phase
    def ingest_frida_message(self, msg_dict):
        event = NormalizedEvent.from_frida_message(msg_dict, self.app_package)
        if not event: return []
        with self._lock:
            self._events.append(event)
            if self._baseline_phase:
                self.baseline.record_event(event)
                if self.baseline.is_baseline_ready():
                    self._baseline_phase = False
                    return [{"type":"baseline_complete","title":"Baseline ready","details":self.baseline.get_summary()}]
                return []  # Skip anomaly detection during baseline
            results = []
            for a in self.detector.analyze_event(event):
                results.append({**a, "source":"anomaly_detector"})
            for r in self.rule_engine.evaluate(event):
                results.append({"type":"rule_match","severity":"medium","title":f"Rule: {r.name}",
                                "description":r.description,"event":event.to_dict(),"source":"rule_engine"})
            return results
    def finalize_baseline(self):
        self._baseline_phase = False
        return self.baseline.get_summary()
    def get_session_report(self):
        with self._lock:
            ec = defaultdict(int); sc = defaultdict(int)
            for e in self._events: ec[e.event_type]+=1; sc[e.severity]+=1
            return {"app_package":self.app_package,
                    "duration":time.time()-(self._events[0].timestamp if self._events else time.time()),
                    "total_events":len(self._events),"baseline":self.baseline.get_summary(),
                    "anomalies":self.detector.get_summary(),"event_distribution":dict(ec),
                    "severity_distribution":dict(sc),"rule_matches":sum(r.matches for r in self.rule_engine.rules)}

if __name__ == "__main__":
    import time as _time
    ba = BehaviorAnalyzer("com.example.app")
    print("=== Baseline phase ===")
    for i in range(60):
        r = ba.ingest_frida_message({"kind":"finding","type":"http_request","severity":"info",
            "title":"GET https://api.example.com/data","evidence":[{"label":"url","value":f"https://api.example.com/data/{i}"}]})
        if r:
            for x in r: print(f"  [{x['type']}] {x['title']}")
        _time.sleep(0.05)
    print("=== Anomaly detection ===")
    for m in [
        {"kind":"finding","type":"command_exec","severity":"critical","title":"su -c id","evidence":[{"label":"cmd","value":"su -c id"}]},
        {"kind":"finding","type":"native_socket","severity":"medium","title":"C2 socket","evidence":[{"label":"ip","value":"203.0.113.99"},{"label":"port","value":"4444"}]},
    ]:
        r = ba.ingest_frida_message(m)
        for x in r: print(f"  [{x.get('severity','?')}] {x['title']}")
    report = ba.get_session_report()
    print(f"Events: {report['total_events']}, Anomalies: {report['anomalies']['total_anomalies']}, Rules: {report['rule_matches']}")
    print("Behavioral analysis engine OK")
