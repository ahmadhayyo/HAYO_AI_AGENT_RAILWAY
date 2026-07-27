#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Real-time Decision Engine
=======================================
Makes immediate decisions based on live data with dynamic priority
setting and adaptive exploitation guidance.
"""
import json
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod


class DecisionType(Enum):
    CONTINUE = "continue"
    ESCALATE = "escalate"
    FOCUS = "focus"
    EXPLORE = "explore"
    RETREAT = "retreat"
    STOP = "stop"


class Priority(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class Decision:
    type: DecisionType
    action: str
    priority: Priority
    reasoning: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class Event:
    type: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    source: str = "unknown"


class DecisionRule(ABC):
    """Base class for decision rules"""
    
    @abstractmethod
    def matches(self, event: Event, analysis: Dict) -> bool:
        """Check if rule matches the event"""
        pass
    
    @abstractmethod
    def execute(self, event: Event, analysis: Dict, context: Dict) -> Optional[Decision]:
        """Execute the rule and return a decision"""
        pass


class CriticalSecretRule(DecisionRule):
    """Rule: Critical secret found -> escalate"""
    
    def matches(self, event: Event, analysis: Dict) -> bool:
        if event.type == "finding":
            data = event.data
            severity = data.get("severity", "").lower()
            finding_type = data.get("type", "").lower()
            return (
                severity in ("critical", "high") and
                any(k in finding_type for k in ["key", "secret", "token", "password", "credential"])
            )
        return False
    
    def execute(self, event: Event, analysis: Dict, context: Dict) -> Optional[Decision]:
        return Decision(
            type=DecisionType.ESCALATE,
            action="exploit_critical_secret",
            priority=Priority.CRITICAL,
            reasoning=f"Critical secret found: {event.data.get('type')}",
            confidence=0.95,
            metadata={"event_data": event.data},
        )


class HighValueTargetRule(DecisionRule):
    """Rule: High-value target discovered -> focus"""
    
    def matches(self, event: Event, analysis: Dict) -> bool:
        if event.type == "target":
            return event.data.get("priority") in ("critical", "high")
        return False
    
    def execute(self, event: Event, analysis: Dict, context: Dict) -> Optional[Decision]:
        return Decision(
            type=DecisionType.FOCUS,
            action="focus_on_target",
            priority=Priority.HIGH,
            reasoning=f"High-value target: {event.data.get('description')}",
            confidence=0.85,
            metadata={"target": event.data},
        )


class NewEndpointRule(DecisionRule):
    """Rule: New endpoint discovered -> explore"""
    
    def matches(self, event: Event, analysis: Dict) -> bool:
        if event.type == "endpoint":
            return True
        return False
    
    def execute(self, event: Event, analysis: Dict, context: Dict) -> Optional[Decision]:
        return Decision(
            type=DecisionType.EXPLORE,
            action="explore_endpoint",
            priority=Priority.MEDIUM,
            reasoning=f"New endpoint discovered: {event.data.get('url', 'unknown')}",
            confidence=0.7,
            metadata={"endpoint": event.data},
        )


class StagnationRule(DecisionRule):
    """Rule: No progress -> try different approach"""
    
    def matches(self, event: Event, analysis: Dict) -> bool:
        if event.type == "progress":
            return analysis.get("stagnation_count", 0) > 5
        return False
    
    def execute(self, event: Event, analysis: Dict, context: Dict) -> Optional[Decision]:
        return Decision(
            type=DecisionType.EXPLORE,
            action="change_approach",
            priority=Priority.HIGH,
            reasoning="No progress detected, changing approach",
            confidence=0.8,
            metadata={"stagnation_count": analysis.get("stagnation_count")},
        )


class FailureRule(DecisionRule):
    """Rule: Repeated failures -> retreat or retry"""
    
    def matches(self, event: Event, analysis: Dict) -> bool:
        if event.type == "failure":
            return analysis.get("failure_count", 0) > 3
        return False
    
    def execute(self, event: Event, analysis: Dict, context: Dict) -> Optional[Decision]:
        return Decision(
            type=DecisionType.RETREAT,
            action="retry_with_different_strategy",
            priority=Priority.HIGH,
            reasoning="Repeated failures, retreating to retry",
            confidence=0.75,
            metadata={"failure_count": analysis.get("failure_count")},
        )


class SuccessRule(DecisionRule):
    """Rule: Success -> continue or escalate"""
    
    def matches(self, event: Event, analysis: Dict) -> bool:
        if event.type == "success":
            return True
        return False
    
    def execute(self, event: Event, analysis: Dict, context: Dict) -> Optional[Decision]:
        if event.data.get("critical", False):
            return Decision(
                type=DecisionType.ESCALATE,
                action="exploit_success",
                priority=Priority.CRITICAL,
                reasoning="Critical success achieved, escalating",
                confidence=0.9,
                metadata={"success_data": event.data},
            )
        else:
            return Decision(
                type=DecisionType.CONTINUE,
                action="continue_exploration",
                priority=Priority.MEDIUM,
                reasoning="Success achieved, continuing",
                confidence=0.8,
                metadata={"success_data": event.data},
            )


class RealtimeDecisionEngine:
    def __init__(self, brain, working_memory):
        """
        Initialize the real-time decision engine.
        
        Args:
            brain: AI brain instance
            working_memory: Working memory instance
        """
        self.brain = brain
        self.memory = working_memory
        # تحديد معدّل استشارة الـ LLM: القواعد تعمل لكل حدث (سريعة)، لكن العقل
        # يُستشار مرّة كل ~15s فقط كي لا نُغرق النموذج بنداء لكل نتيجة (كان هذا
        # سبب تعطيل المحرك سابقاً «integration issues»).
        self._last_brain_ts = 0.0
        self._brain_min_interval = 15.0
        self.rules = self._load_rules()
        self.decision_history: List[Dict] = []
        self.event_history: List[Event] = []
        self.stagnation_count = 0
        self.failure_count = 0
        self.success_count = 0
        self._last_event_time = time.time()
    
    def _load_rules(self) -> List[DecisionRule]:
        """Load decision rules"""
        return [
            CriticalSecretRule(),
            HighValueTargetRule(),
            NewEndpointRule(),
            StagnationRule(),
            FailureRule(),
            SuccessRule(),
        ]
    
    def decide(self, event: Event) -> Decision:
        """
        Make a decision based on an event.
        
        Args:
            event: Event to decide on
        
        Returns:
            Decision object
        """
        # Analyze the event
        analysis = self._analyze_event(event)
        
        # Apply rules
        rule_decision = self._apply_rules(event, analysis)
        
        # Consult AI brain
        brain_decision = self._consult_brain(event, analysis)
        
        # Merge decisions
        final_decision = self._merge_decisions(rule_decision, brain_decision)
        
        # Record decision
        self._record_decision(event, analysis, final_decision)
        
        # Update counters
        self._update_counters(event, final_decision)
        
        return final_decision
    
    def _analyze_event(self, event: Event) -> Dict:
        """Analyze an event"""
        analysis = {
            "event_type": event.type,
            "event_data": event.data,
            "timestamp": event.timestamp,
            "source": event.source,
            "stagnation_count": self.stagnation_count,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "time_since_last_event": time.time() - self._last_event_time,
        }
        
        # Check for stagnation
        if event.type == "progress" and not event.data.get("progress"):
            self.stagnation_count += 1
        else:
            self.stagnation_count = 0
        
        return analysis
    
    def _apply_rules(self, event: Event, analysis: Dict) -> Optional[Decision]:
        """Apply decision rules"""
        for rule in self.rules:
            try:
                if rule.matches(event, analysis):
                    decision = rule.execute(event, analysis, self.memory.get_all())
                    if decision:
                        return decision
            except Exception as e:
                print(f"[!] Rule execution failed: {e}")
        return None
    
    def _consult_brain(self, event: Event, analysis: Dict) -> Optional[Decision]:
        """Consult AI brain for a decision (real — was previously dead code).

        كان سابقاً يمرّر `event.type` (نصاً) بدل كائن Event، ويستدعي `.get()` على
        كائن Decision الذي تُرجعه ExtendedBrain.decide → استثناء دائم → None (استشارة
        ذكاء وهمية؛ القواعد وحدها كانت تعمل). الآن نمرّر الحدث الحقيقي ونعيد كائن
        Decision مباشرةً، مع حارس إن كان العقل لا يدعم decide()."""
        try:
            if self.brain is None or not hasattr(self.brain, "decide"):
                return None
            # تحديد المعدّل: استشر العقل بفواصل زمنية فقط (القواعد تغطّي الباقي)
            now = time.time()
            if now - self._last_brain_ts < self._brain_min_interval:
                return None
            self._last_brain_ts = now
            context = {
                "event": {"type": event.type, "data": event.data},
                "analysis": analysis,
                "memory_summary": self.memory.get_stats() if hasattr(self.memory, "get_stats") else {},
                "recent_decisions": self.decision_history[-5:] if self.decision_history else [],
            }
            # ExtendedBrain.decide(event, analysis, context) → يُرجع كائن Decision
            brain_response = self.brain.decide(event, analysis, context)
            if brain_response is None:
                return None
            if isinstance(brain_response, Decision):
                return brain_response
            if isinstance(brain_response, dict):
                return Decision(
                    type=DecisionType(brain_response.get("type", "continue")),
                    action=brain_response.get("action", "continue"),
                    priority=Priority(brain_response.get("priority", "medium")),
                    reasoning=brain_response.get("reasoning", "AI decision"),
                    confidence=brain_response.get("confidence", 0.7),
                    metadata={"brain_response": brain_response},
                )
        except Exception as e:
            print(f"[!] Brain consultation failed: {e}")
        return None
    
    def _merge_decisions(self, rule_decision: Optional[Decision], 
                        brain_decision: Optional[Decision]) -> Decision:
        """Merge rule and brain decisions"""
        if rule_decision and brain_decision:
            # Both decisions present - choose based on priority and confidence
            if rule_decision.priority.value > brain_decision.priority.value:
                return rule_decision
            elif brain_decision.priority.value > rule_decision.priority.value:
                return brain_decision
            else:
                # Same priority - choose higher confidence
                if rule_decision.confidence > brain_decision.confidence:
                    return rule_decision
                else:
                    return brain_decision
        elif rule_decision:
            return rule_decision
        elif brain_decision:
            return brain_decision
        else:
            # No decisions - return default
            return self._default_decision()
    
    def _default_decision(self) -> Decision:
        """Return default decision"""
        return Decision(
            type=DecisionType.CONTINUE,
            action="continue_exploration",
            priority=Priority.MEDIUM,
            reasoning="No specific decision, continuing exploration",
            confidence=0.5,
        )
    
    def _record_decision(self, event: Event, analysis: Dict, decision: Decision):
        """Record decision in history"""
        record = {
            "event": {
                "type": event.type,
                "data": event.data,
                "timestamp": event.timestamp,
            },
            "analysis": analysis,
            "decision": {
                "type": decision.type.value,
                "action": decision.action,
                "priority": decision.priority.value,
                "reasoning": decision.reasoning,
                "confidence": decision.confidence,
                "metadata": decision.metadata,
            },
            "timestamp": time.time(),
        }
        
        self.decision_history.append(record)
        self.event_history.append(event)
        self._last_event_time = time.time()
        
        # Keep history manageable
        if len(self.decision_history) > 1000:
            self.decision_history = self.decision_history[-500:]
        if len(self.event_history) > 1000:
            self.event_history = self.event_history[-500:]
    
    def _update_counters(self, event: Event, decision: Decision):
        """Update success/failure counters"""
        if event.type == "success":
            self.success_count += 1
        elif event.type == "failure":
            self.failure_count += 1
    
    def get_decision_stats(self) -> Dict:
        """Get decision statistics"""
        if not self.decision_history:
            return {"total_decisions": 0}
        
        decision_types = {}
        for record in self.decision_history:
            dtype = record["decision"]["type"]
            decision_types[dtype] = decision_types.get(dtype, 0) + 1
        
        avg_confidence = sum(
            r["decision"]["confidence"] for r in self.decision_history
        ) / len(self.decision_history)
        
        return {
            "total_decisions": len(self.decision_history),
            "decision_types": decision_types,
            "average_confidence": avg_confidence,
            "stagnation_count": self.stagnation_count,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
        }
    
    def add_custom_rule(self, rule: DecisionRule):
        """Add a custom decision rule"""
        self.rules.append(rule)
    
    def clear_history(self):
        """Clear decision and event history"""
        self.decision_history = []
        self.event_history = []
        self.stagnation_count = 0
        self.failure_count = 0
        self.success_count = 0


if __name__ == "__main__":
    # تشغيل منفصل حقيقي: يعيد تشغيل نتائج جلسة حقيقية كأحداث عبر المحرّك بعقل
    # مدبّر حقيقي، ويطبع القرارات الفعلية — لا DummyBrain ولا بيانات ديمو.
    from working_memory import WorkingMemory
    from standalone_utils import parse_target_args, require_session, build_brain

    args = parse_target_args("Real-time Decision Engine — قرارات حية على نتائج جلسة حقيقية")
    _path, session = require_session(args.package, args.session)

    brain = build_brain(verbose=False)
    if brain is None:
        raise SystemExit(3)

    memory = WorkingMemory()
    engine = RealtimeDecisionEngine(brain, memory)

    findings = [f for f in session.get("findings", [])
                if str(f.get("severity", "")).lower() in ("critical", "high", "medium")]
    print(f"\n[*] إعادة تشغيل {len(findings)} نتيجة (≥MEDIUM) كأحداث حقيقية:")
    for f in findings[:25]:
        event = Event(type="finding", data=f, source="session")
        try:
            decision = engine.decide(event)
            print(f"    - [{f.get('severity','?')}] {str(f.get('type','?'))[:28]:28s} "
                  f"→ {decision.type.value}: {decision.action} (ثقة {decision.confidence:.2f})")
        except Exception as e:
            print(f"    - [{f.get('severity','?')}] {str(f.get('type','?'))[:28]:28s} → (تعذّر: {e})")

    stats = engine.get_decision_stats()
    print(f"\n[*] إحصاءات القرارات:\n{json.dumps(stats, ensure_ascii=False, indent=2)}")
