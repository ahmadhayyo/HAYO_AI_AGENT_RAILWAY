#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Phase Manager Brain
===================================
Enhanced AI brain for managing sequential phases with intelligent
decision-making based on extracted data and phase results.
"""
import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class PhaseDecision(Enum):
    RUN = "run"
    SKIP = "skip"
    RETRY = "retry"
    ABORT = "abort"


@dataclass
class PhaseContext:
    """Context for phase decision-making"""
    current_phase: str
    previous_results: Dict[str, Any]
    live_data: List[Dict]
    static_data: Dict[str, Any]
    correlations: List[Dict]
    targets: List[Dict]
    findings: List[Dict]
    timestamp: float = field(default_factory=time.time)


class PhaseManagerBrain:
    def __init__(self, package: str):
        """
        Initialize the phase manager brain.
        
        Args:
            package: Target package name
        """
        self.package = package
        self.phase_history: List[Dict] = []
        self.decision_cache: Dict[str, Dict] = {}
        self.phase_prerequisites = self._define_prerequisites()
        self.phase_thresholds = self._define_thresholds()
        self.phase_strategies = self._define_strategies()
    
    def _define_prerequisites(self) -> Dict[str, List[str]]:
        """Define prerequisites for each phase"""
        return {
            "pre_check": [],
            "static_analysis": ["pre_check"],
            "dynamic_setup": ["static_analysis"],
            "intelligence_gathering": ["dynamic_setup"],
            "data_correlation": ["intelligence_gathering"],
            "adaptive_exploitation": ["data_correlation"],
            "post_exploitation": ["adaptive_exploitation"],
            "reporting": ["data_correlation"],
        }
    
    def _define_thresholds(self) -> Dict[str, Dict]:
        """Define value thresholds for optional phases"""
        return {
            "adaptive_exploitation": {
                "min_high_value_targets": 1,
                "min_critical_findings": 0,
                "min_correlations": 2,
            },
            "post_exploitation": {
                "min_successful_exploits": 1,
                "min_critical_data_extracted": 1,
            },
        }
    
    def _define_strategies(self) -> Dict[str, str]:
        """Define strategies for each phase"""
        return {
            "pre_check": "conservative",
            "static_analysis": "thorough",
            "dynamic_setup": "fast",
            "intelligence_gathering": "aggressive",
            "data_correlation": "comprehensive",
            "adaptive_exploitation": "calculated",
            "post_exploitation": "stealthy",
            "reporting": "detailed",
        }
    
    def should_run_phase(self, phase_name: str, context: PhaseContext) -> PhaseDecision:
        """
        Decide whether to run a phase.
        
        Args:
            phase_name: Name of the phase
            context: Current context
        
        Returns:
            PhaseDecision
        """
        # Check cache
        cache_key = f"{phase_name}_{hash(json.dumps(context.previous_results, sort_keys=True))}"
        if cache_key in self.decision_cache:
            return PhaseDecision(self.decision_cache[cache_key]["decision"])
        
        # Check prerequisites
        if not self._check_prerequisites(phase_name, context):
            decision = PhaseDecision.SKIP
            self.decision_cache[cache_key] = {"decision": decision.value, "reason": "Prerequisites not met"}
            return decision
        
        # Estimate value
        expected_value = self._estimate_value(phase_name, context)
        threshold = self.phase_thresholds.get(phase_name, {})
        
        if expected_value < self._get_threshold_value(phase_name, threshold):
            decision = PhaseDecision.SKIP
            self.decision_cache[cache_key] = {"decision": decision.value, "reason": "Expected value below threshold"}
            return decision
        
        # Check for abort conditions
        if self._should_abort(phase_name, context):
            decision = PhaseDecision.ABORT
            self.decision_cache[cache_key] = {"decision": decision.value, "reason": "Abort condition met"}
            return decision
        
        decision = PhaseDecision.RUN
        self.decision_cache[cache_key] = {"decision": decision.value, "reason": "All checks passed"}
        return decision
    
    def _check_prerequisites(self, phase_name: str, context: PhaseContext) -> bool:
        """Check if phase prerequisites are met"""
        prerequisites = self.phase_prerequisites.get(phase_name, [])
        
        for prereq in prerequisites:
            if prereq not in context.previous_results:
                return False
            
            result = context.previous_results[prereq]
            if result.get("status") == "failed":
                return False
        
        return True
    
    def _estimate_value(self, phase_name: str, context: PhaseContext) -> float:
        """Estimate the value of running a phase"""
        value = 0.0
        
        # Base value for required phases
        if phase_name in ["pre_check", "static_analysis", "dynamic_setup", "intelligence_gathering", 
                          "data_correlation", "reporting"]:
            value += 1.0
        
        # Value based on available data
        if phase_name == "adaptive_exploitation":
            # Value increases with high-value targets
            high_value_targets = [t for t in context.targets if t.get("priority") in ("critical", "high")]
            value += len(high_value_targets) * 0.5
            
            # Value increases with critical findings
            critical_findings = [f for f in context.findings if f.get("severity") == "critical"]
            value += len(critical_findings) * 0.3
            
            # Value increases with correlations
            value += len(context.correlations) * 0.1
        
        elif phase_name == "post_exploitation":
            # Value increases with successful exploits
            successful_exploits = [e for e in context.previous_results.get("adaptive_exploitation", {}).get("exploitation_results", []) if e.get("success")]
            value += len(successful_exploits) * 0.5
        
        return value
    
    def _get_threshold_value(self, phase_name: str, threshold: Dict) -> float:
        """Get the threshold value for a phase"""
        if not threshold:
            return 0.5
        
        min_targets = threshold.get("min_high_value_targets", 0)
        min_findings = threshold.get("min_critical_findings", 0)
        min_correlations = threshold.get("min_correlations", 0)
        
        return (min_targets * 0.5) + (min_findings * 0.3) + (min_correlations * 0.1)
    
    def _should_abort(self, phase_name: str, context: PhaseContext) -> bool:
        """Check if pipeline should abort"""
        # Abort if critical errors in previous phases
        for phase_name_prev, result in context.previous_results.items():
            if result.get("status") == "failed" and result.get("critical", False):
                return True
        
        # Abort if no data to work with
        if phase_name == "data_correlation" and not context.live_data:
            return True
        
        if phase_name == "adaptive_exploitation" and not context.targets:
            return True
        
        return False
    
    def decide_next_action(self, context: PhaseContext) -> Dict:
        """
        Decide the next action based on current context.
        
        Args:
            context: Current context
        
        Returns:
            Decision dictionary
        """
        live_data = context.live_data
        static_data = context.static_data
        
        # Analyze live data
        analysis = self._analyze_live_data(live_data)
        
        # Make decision
        if analysis.get("critical_secrets_found"):
            return {
                "action": "escalate_to_exploitation",
                "reason": "Critical secrets found",
                "priority": "critical",
                "targets": analysis.get("critical_secrets"),
            }
        elif analysis.get("high_value_targets"):
            return {
                "action": "focus_on_targets",
                "reason": "High-value targets identified",
                "priority": "high",
                "targets": analysis.get("high_value_targets"),
            }
        elif analysis.get("new_endpoints"):
            return {
                "action": "explore_endpoints",
                "reason": "New endpoints discovered",
                "priority": "medium",
                "endpoints": analysis.get("new_endpoints"),
            }
        elif analysis.get("correlation_opportunities"):
            return {
                "action": "correlate_data",
                "reason": "Data correlation opportunities",
                "priority": "high",
                "opportunities": analysis.get("correlation_opportunities"),
            }
        else:
            return {
                "action": "continue_exploration",
                "reason": "Continue with current strategy",
                "priority": "medium",
            }
    
    def _analyze_live_data(self, live_data: List[Dict]) -> Dict:
        """Analyze live data for decision-making"""
        analysis = {
            "critical_secrets_found": [],
            "high_value_targets": [],
            "new_endpoints": [],
            "correlation_opportunities": [],
        }
        
        for data in live_data:
            # Check for critical secrets
            if data.get("priority") == "critical":
                if "key" in str(data.get("data", {})).lower() or "secret" in str(data.get("data", {})).lower():
                    analysis["critical_secrets_found"].append(data)
            
            # Check for high-value targets
            if data.get("priority") == "high":
                analysis["high_value_targets"].append(data)
            
            # Check for new endpoints
            if data.get("type") == "network":
                url = data.get("data", {}).get("url")
                if url:
                    analysis["new_endpoints"].append(url)
        
        # Check for correlation opportunities
        if len(live_data) > 10:
            analysis["correlation_opportunities"] = True
        
        return analysis
    
    def adapt_strategy(self, phase_name: str, phase_result: Dict, context: PhaseContext):
        """
        Adapt strategy based on phase result.
        
        Args:
            phase_name: Name of the phase
            phase_result: Result of the phase
            context: Current context
        """
        if phase_result.get("success"):
            self._update_strategy_for_success(phase_name, phase_result, context)
        else:
            self._update_strategy_for_failure(phase_name, phase_result, context)
        
        # Record in history
        self.phase_history.append({
            "phase": phase_name,
            "result": phase_result,
            "context_snapshot": {
                "live_data_count": len(context.live_data),
                "targets_count": len(context.targets),
                "findings_count": len(context.findings),
            },
            "timestamp": time.time(),
        })
    
    def _update_strategy_for_success(self, phase_name: str, phase_result: Dict, context: PhaseContext):
        """Update strategy after successful phase"""
        if phase_name == "intelligence_gathering":
            # If we found critical data, be more aggressive in exploitation
            if phase_result.get("critical_data_count", 0) > 0:
                self.phase_strategies["adaptive_exploitation"] = "aggressive"
        
        elif phase_name == "adaptive_exploitation":
            # If exploitation was successful, be more stealthy in post-exploitation
            if phase_result.get("successful_exploits", 0) > 0:
                self.phase_strategies["post_exploitation"] = "stealthy"
    
    def _update_strategy_for_failure(self, phase_name: str, phase_result: Dict, context: PhaseContext):
        """Update strategy after failed phase"""
        if phase_name == "intelligence_gathering":
            # If we didn't gather enough data, be more thorough
            if len(context.live_data) < 5:
                self.phase_strategies["intelligence_gathering"] = "thorough"
        
        elif phase_name == "adaptive_exploitation":
            # If exploitation failed, try different approach
            self.phase_strategies["adaptive_exploitation"] = "conservative"
    
    def get_strategy(self, phase_name: str) -> str:
        """Get the current strategy for a phase"""
        return self.phase_strategies.get(phase_name, "default")
    
    def get_phase_history(self) -> List[Dict]:
        """Get phase execution history"""
        return self.phase_history
    
    def clear_cache(self):
        """Clear decision cache"""
        self.decision_cache = {}


if __name__ == "__main__":
    # تشغيل منفصل حقيقي: يبني سياق المراحل من جلسة ديناميكية حقيقية ويطبع قرارات
    # المراحل الفعلية لهذا الهدف — لا سياق ديمو.
    from standalone_utils import parse_target_args, require_session, session_targets

    args = parse_target_args("Phase Manager Brain — قرارات المراحل من جلسة حقيقية")
    _path, session = require_session(args.package, args.session)

    package = session.get("package") or args.package or "unknown"
    brain = PhaseManagerBrain(package)

    findings = session.get("findings", [])
    targets = session_targets(session)
    live_data = [
        {"type": f.get("type", "?"), "priority": f.get("severity", "medium"),
         "data": f.get("evidence", {})}
        for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")
    ]
    context = PhaseContext(
        current_phase="data_correlation",
        previous_results={
            "static_analysis": {"status": "completed"},
            "dynamic_setup": {"status": "completed"},
            "intelligence_gathering": {"status": "completed", "findings": len(findings)},
        },
        live_data=live_data,
        static_data=session.get("cloud_analysis", {}) or {},
        correlations=[],
        targets=targets,
        findings=findings,
    )

    print(f"\n[*] قرارات المراحل للهدف «{package}» "
          f"(نتائج={len(findings)}, أهداف={len(targets)}, حرجة/عالية={len(live_data)}):")
    for phase in ("intelligence_gathering", "data_correlation",
                  "adaptive_exploitation", "cloud_exploitation", "reporting"):
        try:
            decision = brain.should_run_phase(phase, context)
            print(f"    - {phase:24s} → {getattr(decision, 'value', decision)}")
        except Exception as e:
            print(f"    - {phase:24s} → (تعذّر القرار: {e})")

    action = brain.decide_next_action(context)
    print(f"\n[*] الإجراء التالي المقترح: {action.get('action')}")
    print(f"    السبب: {action.get('reason')}")
    print(f"\n[*] استراتيجية الاستغلال التكيفي:\n    {brain.get_strategy('adaptive_exploitation')}")
