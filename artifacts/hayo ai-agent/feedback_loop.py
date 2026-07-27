#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Feedback Loop System
=====================================
Creates a feedback loop for continuous improvement based on
action results, learning from successes and failures.
"""
import json
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class FeedbackType(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    ERROR = "error"


@dataclass
class Feedback:
    action: str
    result: Dict[str, Any]
    type: FeedbackType
    timestamp: float
    metrics: Dict[str, Any]
    context: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Trend:
    metric: str
    direction: str  # "increasing", "decreasing", "stable"
    change_rate: float
    confidence: float


@dataclass
class Improvement:
    area: str
    current_value: float
    target_value: float
    priority: str
    recommendations: List[str]


class FeedbackLoop:
    def __init__(self, brain, working_memory):
        """
        Initialize the feedback loop system.
        
        Args:
            brain: AI brain instance
            working_memory: Working memory instance
        """
        self.brain = brain
        self.memory = working_memory
        self.metrics = {
            "success_rate": 0.0,
            "exploit_success": 0,
            "exploit_failure": 0,
            "data_extracted": 0,
            "time_spent": 0.0,
            "decisions_made": 0,
            "phases_completed": 0,
            "phases_failed": 0,
        }
        self.feedback_history: List[Feedback] = []
        self.metric_history: Dict[str, List[float]] = defaultdict(list)
        self.trends: Dict[str, Trend] = {}
        self.improvements: List[Improvement] = []
        self._last_analysis_time = time.time()
        self._analysis_interval = 60  # seconds
    
    def collect_feedback(self, action: str, result: Dict, context: Dict = None) -> Feedback:
        """
        Collect feedback from an action.
        
        Args:
            action: Action that was performed
            result: Result of the action
            context: Context in which action was performed
        
        Returns:
            Feedback object
        """
        if context is None:
            context = {}
        
        # Determine feedback type
        feedback_type = self._determine_feedback_type(result)
        
        # Calculate metrics
        metrics = self._calculate_metrics(action, result)
        
        # Create feedback
        feedback = Feedback(
            action=action,
            result=result,
            type=feedback_type,
            timestamp=time.time(),
            metrics=metrics,
            context=context,
        )
        
        # Store feedback
        self.feedback_history.append(feedback)
        
        # Update metrics
        self._update_metrics(feedback)
        
        # Update metric history
        for metric_name, metric_value in metrics.items():
            self.metric_history[metric_name].append(metric_value)
        
        return feedback
    
    def _determine_feedback_type(self, result: Dict) -> FeedbackType:
        """Determine the type of feedback based on result"""
        if result.get("success"):
            if result.get("partial_success"):
                return FeedbackType.PARTIAL
            return FeedbackType.SUCCESS
        elif result.get("error"):
            return FeedbackType.ERROR
        else:
            return FeedbackType.FAILURE
    
    def _calculate_metrics(self, action: str, result: Dict) -> Dict:
        """Calculate metrics for feedback"""
        metrics = {}
        
        # Success rate
        if result.get("success"):
            metrics["success"] = 1
        else:
            metrics["success"] = 0
        
        # Data extracted
        if "data" in result:
            data_size = len(json.dumps(result.get("data", {})))
            metrics["data_extracted"] = data_size
        
        # Time spent
        if "duration" in result:
            metrics["time_spent"] = result["duration"]
        
        # Exploit-specific metrics
        if "exploit" in action:
            if result.get("success"):
                metrics["exploit_success"] = 1
            else:
                metrics["exploit_failure"] = 1
        
        # Phase-specific metrics
        if "phase" in action:
            if result.get("success"):
                metrics["phase_completed"] = 1
            else:
                metrics["phase_failed"] = 1
        
        return metrics
    
    def _update_metrics(self, feedback: Feedback):
        """Update overall metrics based on feedback"""
        metrics = feedback.metrics
        
        # Update counters
        if metrics.get("success"):
            self.metrics["success_rate"] = (
                (self.metrics["success_rate"] * len(self.feedback_history) + 1) /
                (len(self.feedback_history) + 1)
            )
        
        if metrics.get("exploit_success"):
            self.metrics["exploit_success"] += 1
        
        if metrics.get("exploit_failure"):
            self.metrics["exploit_failure"] += 1
        
        if metrics.get("data_extracted"):
            self.metrics["data_extracted"] += metrics["data_extracted"]
        
        if metrics.get("time_spent"):
            self.metrics["time_spent"] += metrics["time_spent"]
        
        if metrics.get("phase_completed"):
            self.metrics["phases_completed"] += 1
        
        if metrics.get("phase_failed"):
            self.metrics["phases_failed"] += 1
        
        self.metrics["decisions_made"] += 1
    
    def analyze_feedback(self) -> Dict:
        """
        Analyze collected feedback.
        
        Returns:
            Analysis dictionary with trends, improvements, and recommendations
        """
        now = time.time()
        if now - self._last_analysis_time < self._analysis_interval:
            return self._get_cached_analysis()
        
        self._last_analysis_time = now
        
        # Analyze trends
        trends = self._analyze_trends()
        self.trends = trends
        
        # Identify improvements
        improvements = self._identify_improvements(trends)
        self.improvements = improvements
        
        # Generate recommendations
        recommendations = self._generate_recommendations(improvements)
        
        return {
            "trends": trends,
            "improvements": improvements,
            "recommendations": recommendations,
            "current_metrics": self.metrics,
            "feedback_count": len(self.feedback_history),
        }
    
    def _get_cached_analysis(self) -> Dict:
        """Get cached analysis"""
        return {
            "trends": self.trends,
            "improvements": self.improvements,
            "recommendations": self._generate_recommendations(self.improvements),
            "current_metrics": self.metrics,
            "feedback_count": len(self.feedback_history),
        }
    
    def _analyze_trends(self) -> Dict[str, Trend]:
        """Analyze trends in metrics"""
        trends = {}
        
        for metric_name, history in self.metric_history.items():
            if len(history) < 3:
                continue
            
            # Calculate trend direction
            recent = history[-5:] if len(history) >= 5 else history
            older = history[:-5] if len(history) >= 10 else history[:len(history)//2]
            
            if not older:
                continue
            
            recent_avg = sum(recent) / len(recent)
            older_avg = sum(older) / len(older)
            
            change_rate = (recent_avg - older_avg) / older_avg if older_avg != 0 else 0
            
            if change_rate > 0.1:
                direction = "increasing"
            elif change_rate < -0.1:
                direction = "decreasing"
            else:
                direction = "stable"
            
            # Calculate confidence based on variance
            variance = sum((x - recent_avg) ** 2 for x in recent) / len(recent)
            confidence = max(0, 1 - variance / (recent_avg ** 2 + 1))
            
            trends[metric_name] = Trend(
                metric=metric_name,
                direction=direction,
                change_rate=change_rate,
                confidence=confidence,
            )
        
        return trends
    
    def _identify_improvements(self, trends: Dict[str, Trend]) -> List[Improvement]:
        """Identify areas for improvement"""
        improvements = []
        
        # Check success rate trend
        if "success" in trends:
            success_trend = trends["success"]
            if success_trend.direction == "decreasing":
                improvements.append(Improvement(
                    area="success_rate",
                    current_value=self.metrics["success_rate"],
                    target_value=0.8,
                    priority="high",
                    recommendations=[
                        "Review failed actions for common patterns",
                        "Adjust decision thresholds",
                        "Improve exploit selection",
                    ],
                ))
        
        # Check exploit success rate
        total_exploits = self.metrics["exploit_success"] + self.metrics["exploit_failure"]
        if total_exploits > 0:
            exploit_rate = self.metrics["exploit_success"] / total_exploits
            if exploit_rate < 0.5:
                improvements.append(Improvement(
                    area="exploit_success_rate",
                    current_value=exploit_rate,
                    target_value=0.7,
                    priority="high",
                    recommendations=[
                        "Update exploit weights",
                        "Improve target analysis",
                        "Add new exploit templates",
                    ],
                ))
        
        # Check data extraction efficiency
        if "data_extracted" in self.metric_history:
            data_history = self.metric_history["data_extracted"]
            if len(data_history) > 5:
                recent_avg = sum(data_history[-5:]) / 5
                if recent_avg < 100:  # Less than 100 bytes per action
                    improvements.append(Improvement(
                        area="data_extraction",
                        current_value=recent_avg,
                        target_value=500,
                        priority="medium",
                        recommendations=[
                            "Improve data extraction hooks",
                            "Add more Frida hooks",
                            "Optimize data processing",
                        ],
                    ))
        
        # Check phase completion rate
        total_phases = self.metrics["phases_completed"] + self.metrics["phases_failed"]
        if total_phases > 0:
            phase_rate = self.metrics["phases_completed"] / total_phases
            if phase_rate < 0.8:
                improvements.append(Improvement(
                    area="phase_completion",
                    current_value=phase_rate,
                    target_value=0.95,
                    priority="high",
                    recommendations=[
                        "Improve phase prerequisites",
                        "Add better error handling",
                        "Increase retry counts",
                    ],
                ))
        
        return improvements
    
    def _generate_recommendations(self, improvements: List[Improvement]) -> List[str]:
        """Generate recommendations based on improvements"""
        recommendations = []
        
        for improvement in improvements:
            recommendations.extend(improvement.recommendations)
        
        # Add general recommendations
        if len(self.feedback_history) > 50:
            recommendations.append("Consider pruning old feedback history")
        
        if self.metrics["time_spent"] > 3600:  # More than 1 hour
            recommendations.append("Optimize action execution time")
        
        return recommendations
    
    def apply_feedback(self):
        """Apply feedback to improve the system"""
        analysis = self.analyze_feedback()
        
        # Update brain strategy
        try:
            self.brain.update_strategy(analysis)
        except Exception as e:
            print(f"[!] Failed to update brain strategy: {e}")
        
        # Update decision rules
        self._update_decision_rules(analysis)
        
        # Update exploit priorities
        self._update_exploit_priorities(analysis)
        
        # Update phase thresholds
        self._update_phase_thresholds(analysis)
    
    def _update_decision_rules(self, analysis: Dict):
        """Update decision rules based on feedback"""
        # This would update the realtime_decision_engine rules
        # For now, just log the action
        print("[*] Updating decision rules based on feedback")
    
    def _update_exploit_priorities(self, analysis: Dict):
        """Update exploit priorities based on feedback"""
        # This would update the adaptive_exploitation_engine weights
        # For now, just log the action
        print("[*] Updating exploit priorities based on feedback")
    
    def _update_phase_thresholds(self, analysis: Dict):
        """Update phase thresholds based on feedback"""
        # This would update the pipeline_orchestrator thresholds
        # For now, just log the action
        print("[*] Updating phase thresholds based on feedback")
    
    def get_recent_feedback(self, limit: int = 10) -> List[Feedback]:
        """Get recent feedback entries"""
        return self.feedback_history[-limit:]
    
    def get_feedback_by_type(self, feedback_type: FeedbackType) -> List[Feedback]:
        """Get feedback by type"""
        return [f for f in self.feedback_history if f.type == feedback_type]
    
    def get_metrics(self) -> Dict:
        """Get current metrics"""
        return self.metrics.copy()
    
    def get_metric_history(self, metric_name: str) -> List[float]:
        """Get history for a specific metric"""
        return self.metric_history.get(metric_name, [])
    
    def clear_history(self, retain_last: int = 0):
        """
        Clear feedback history.
        
        Args:
            retain_last: Number of recent entries to retain
        """
        if retain_last > 0:
            self.feedback_history = self.feedback_history[-retain_last:]
        else:
            self.feedback_history = []
        
        # Reset metrics
        self.metrics = {
            "success_rate": 0.0,
            "exploit_success": 0,
            "exploit_failure": 0,
            "data_extracted": 0,
            "time_spent": 0.0,
            "decisions_made": 0,
            "phases_completed": 0,
            "phases_failed": 0,
        }
        
        # Reset metric history
        self.metric_history = defaultdict(list)
    
    def export(self) -> Dict:
        """Export feedback loop state"""
        return {
            "metrics": self.metrics,
            "feedback_history": [
                {
                    "action": f.action,
                    "result": f.result,
                    "type": f.type.value,
                    "timestamp": f.timestamp,
                    "metrics": f.metrics,
                    "context": f.context,
                }
                for f in self.feedback_history
            ],
            "metric_history": dict(self.metric_history),
            "trends": {
                k: {
                    "metric": v.metric,
                    "direction": v.direction,
                    "change_rate": v.change_rate,
                    "confidence": v.confidence,
                }
                for k, v in self.trends.items()
            },
            "improvements": [
                {
                    "area": i.area,
                    "current_value": i.current_value,
                    "target_value": i.target_value,
                    "priority": i.priority,
                    "recommendations": i.recommendations,
                }
                for i in self.improvements
            ],
        }


if __name__ == "__main__":
    # تشغيل منفصل حقيقي: يجمع تغذية راجعة من نتائج جلسة حقيقية (محاولات الفتح،
    # التحليل السحابي، النتائج المُصنّفة) ويطبع تحليلاً/مقاييس فعلية — لا ديمو.
    from working_memory import WorkingMemory
    from standalone_utils import parse_target_args, require_session, build_brain

    args = parse_target_args("Feedback Loop — تحليل تغذية راجعة من جلسة حقيقية")
    _path, session = require_session(args.package, args.session)

    brain = build_brain(verbose=False)
    if brain is None:
        raise SystemExit(3)

    memory = WorkingMemory()
    feedback_loop = FeedbackLoop(brain, memory)

    collected = 0
    pu = session.get("premium_unlock")
    if isinstance(pu, dict) and pu:
        feedback_loop.collect_feedback(
            action="premium_unlock",
            result={"success": bool(pu.get("success") or pu.get("unlocked")),
                    "data": pu, "duration": float(session.get("duration_s", 0) or 0)})
        collected += 1
    ca = session.get("cloud_analysis")
    if isinstance(ca, dict) and ca:
        feedback_loop.collect_feedback(
            action="cloud_analysis",
            result={"success": bool(ca.get("accessible") or ca.get("verified")),
                    "data": ca, "duration": 0.0})
        collected += 1
    for t in session.get("triaged", []):
        sev = str(t.get("severity", "info")).lower()
        if sev in ("critical", "high"):
            feedback_loop.collect_feedback(
                action=f"detect_{str(t.get('type','finding')).split('.')[0]}",
                result={"success": True, "data": {"severity": sev}, "duration": 0.0})
            collected += 1

    if collected == 0:
        print("\n[!] لا توجد إجراءات/نتائج قابلة للتحليل في هذه الجلسة.")
        raise SystemExit(2)

    print(f"\n[+] جُمعت {collected} تغذية راجعة حقيقية من الجلسة.")
    analysis = feedback_loop.analyze_feedback()
    print(f"\n[*] التحليل:\n{json.dumps(analysis, ensure_ascii=False, indent=2)}")
    feedback_loop.apply_feedback()
    metrics = feedback_loop.get_metrics()
    print(f"\n[*] المقاييس:\n{json.dumps(metrics, ensure_ascii=False, indent=2)}")
