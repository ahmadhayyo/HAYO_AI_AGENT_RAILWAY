#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Pipeline Orchestrator
====================================
Manages the sequential execution of pentest phases with proper data flow,
checkpoints, and intelligent phase management.
"""
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Any
from datetime import datetime


class PhaseStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PhaseResult:
    name: str
    status: PhaseStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def failed(self) -> bool:
        return self.status == PhaseStatus.FAILED
    
    @property
    def success(self) -> bool:
        return self.status == PhaseStatus.COMPLETED


@dataclass
class Phase:
    name: str
    execute: Callable
    required: bool = True
    dependencies: List[str] = field(default_factory=list)
    timeout: int = 300  # seconds
    retry_count: int = 0
    max_retries: int = 2


class PipelineOrchestrator:
    def __init__(self, package: str, device: str, brain, adb: str = "adb"):
        self.package = package
        self.device = device
        self.adb = adb
        self.brain = brain
        self.phases: List[Phase] = []
        self.context: Dict[str, Any] = {}
        self.checkpoints: Dict[str, PhaseResult] = {}
        self.phase_history: List[PhaseResult] = []
        self._stop = False
        
        self._initialize_phases()
    
    def _initialize_phases(self):
        """Define all pipeline phases with dependencies"""
        self.phases = [
            Phase(
                name="pre_check",
                execute=self._pre_check,
                required=True,
                dependencies=[],
                timeout=30,
            ),
            Phase(
                name="static_analysis",
                execute=self._static_analysis,
                required=True,
                dependencies=["pre_check"],
                timeout=120,
            ),
            Phase(
                name="dynamic_setup",
                execute=self._dynamic_setup,
                required=True,
                dependencies=["static_analysis"],
                timeout=60,
            ),
            Phase(
                name="intelligence_gathering",
                execute=self._intelligence_gathering,
                required=True,
                dependencies=["dynamic_setup"],
                timeout=300,
            ),
            Phase(
                name="data_correlation",
                execute=self._data_correlation,
                required=True,
                dependencies=["intelligence_gathering"],
                timeout=60,
            ),
            Phase(
                name="adaptive_exploitation",
                execute=self._adaptive_exploitation,
                required=False,
                dependencies=["data_correlation"],
                timeout=180,
            ),
            Phase(
                name="post_exploitation",
                execute=self._post_exploitation,
                required=False,
                dependencies=["adaptive_exploitation"],
                timeout=120,
            ),
            Phase(
                name="reporting",
                execute=self._reporting,
                required=True,
                dependencies=["data_correlation"],
                timeout=30,
            ),
        ]
    
    def stop(self):
        """Stop the pipeline gracefully"""
        self._stop = True
    
    def run(self) -> Dict[str, PhaseResult]:
        """Execute all phases in order with dependency checking"""
        print(f"\n{'='*60}")
        print(f"Pipeline Orchestrator - Starting")
        print(f"Package: {self.package}")
        print(f"Device: {self.device}")
        print(f"Total Phases: {len(self.phases)}")
        print(f"{'='*60}\n")
        
        for phase in self.phases:
            if self._stop:
                print("[!] Pipeline stopped by user")
                break
            
            # Check if phase should run
            if not self._should_run_phase(phase):
                result = PhaseResult(
                    name=phase.name,
                    status=PhaseStatus.SKIPPED,
                    data={"reason": "Phase not required or dependencies not met"}
                )
                self.checkpoints[phase.name] = result
                self.phase_history.append(result)
                print(f"[{phase.name}] SKIPPED")
                continue
            
            # Check dependencies
            if not self._check_dependencies(phase):
                result = PhaseResult(
                    name=phase.name,
                    status=PhaseStatus.FAILED,
                    error="Dependencies not met"
                )
                self.checkpoints[phase.name] = result
                self.phase_history.append(result)
                print(f"[{phase.name}] FAILED - Dependencies not met")
                if phase.required:
                    print(f"[!] Required phase {phase.name} failed - stopping pipeline")
                    break
                continue
            
            # Execute phase
            result = self._execute_phase(phase)
            self.checkpoints[phase.name] = result
            self.phase_history.append(result)
            
            # Update context with phase data
            if result.success:
                self.context.update(result.data)
            
            # Handle failure
            if result.failed and phase.required:
                print(f"[!] Required phase {phase.name} failed - stopping pipeline")
                self._handle_failure(phase, result)
                break
            elif result.failed:
                print(f"[!] Optional phase {phase.name} failed - continuing")
        
        return self.checkpoints
    
    def _should_run_phase(self, phase: Phase) -> bool:
        """Determine if a phase should run"""
        # Required phases always run if dependencies met
        if phase.required:
            return True
        
        # Optional phases: ask brain
        try:
            decision = self.brain.decide(phase.name, self.context)
            return decision.get("run", False)
        except Exception as e:
            print(f"[!] Brain decision failed for {phase.name}: {e}")
            return False
    
    def _check_dependencies(self, phase: Phase) -> bool:
        """Check if all dependencies are satisfied"""
        for dep in phase.dependencies:
            if dep not in self.checkpoints:
                return False
            if self.checkpoints[dep].failed:
                return False
        return True
    
    def _execute_phase(self, phase: Phase) -> PhaseResult:
        """Execute a single phase with retry logic"""
        print(f"\n[{phase.name}] STARTING")
        print(f"Required: {phase.required}")
        print(f"Dependencies: {phase.dependencies}")
        
        start_time = time.time()
        last_error = None
        
        for attempt in range(phase.max_retries + 1):
            if self._stop:
                break
            
            try:
                phase.retry_count = attempt
                result_data = phase.execute(self.context)
                
                duration = time.time() - start_time
                result = PhaseResult(
                    name=phase.name,
                    status=PhaseStatus.COMPLETED,
                    data=result_data,
                    duration=duration
                )
                
                print(f"[{phase.name}] COMPLETED in {duration:.2f}s")
                return result
                
            except Exception as e:
                last_error = str(e)
                print(f"[{phase.name}] Attempt {attempt + 1} failed: {e}")
                
                if attempt < phase.max_retries:
                    print(f"[{phase.name}] Retrying...")
                    time.sleep(2)
        
        # All retries failed
        duration = time.time() - start_time
        result = PhaseResult(
            name=phase.name,
            status=PhaseStatus.FAILED,
            error=last_error,
            duration=duration
        )
        
        print(f"[{phase.name}] FAILED after {phase.max_retries + 1} attempts")
        return result
    
    def _handle_failure(self, phase: Phase, result: PhaseResult):
        """Handle phase failure"""
        print(f"\n[!] Handling failure for {phase.name}")
        print(f"Error: {result.error}")
        
        # Try to recover or provide fallback
        try:
            recovery_data = self._attempt_recovery(phase, result)
            if recovery_data:
                self.context.update(recovery_data)
                print(f"[!] Recovery successful for {phase.name}")
        except Exception as e:
            print(f"[!] Recovery failed: {e}")
    
    def _attempt_recovery(self, phase: Phase, result: PhaseResult) -> Optional[Dict]:
        """Attempt to recover from a failed phase"""
        # Default recovery: do nothing
        # Subclasses can override for specific recovery logic
        return None
    
    # ── Phase Implementations ─────────────────────────────────────────────
    
    def _pre_check(self, context: Dict) -> Dict:
        """Phase 0: Pre-requisites Check"""
        print("  Checking device connectivity...")
        # Check device connectivity
        import subprocess
        try:
            result = subprocess.run(
                [self.adb, "-s", self.device, "shell", "echo", "ok"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise Exception("Device not reachable")
        except Exception as e:
            raise Exception(f"Device check failed: {e}")
        
        print("  Checking frida-server...")
        # Check frida-server (best effort)
        try:
            result = subprocess.run(
                [self.adb, "-s", self.device, "shell", "su", "-c", "ps | grep frida"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "frida" not in result.stdout:
                print("  [!] frida-server not running - will try to start later")
        except Exception:
            print("  [!] Could not check frida-server status")
        
        print("  Checking target app...")
        try:
            result = subprocess.run(
                [self.adb, "-s", self.device, "shell", "pm", "path", self.package],
                capture_output=True,
                text=True,
                timeout=10
            )
            if not result.stdout or "package:" not in result.stdout:
                raise Exception(f"App {self.package} not installed")
        except Exception as e:
            raise Exception(f"App check failed: {e}")
        
        return {
            "device_connected": True,
            "frida_server_checked": True,
            "app_installed": True,
        }
    
    def _static_analysis(self, context: Dict) -> Dict:
        """Phase 1: Static Analysis (Deep)"""
        print("  Running static analysis...")
        try:
            from static_engine import StaticEngine
            from intel_store import IntelStore
            
            store = IntelStore(self.package)
            engine = StaticEngine(self.package, store=store, device=self.device)
            report = engine.run_full_static()
            
            return {
                "static_report": report,
                "secrets": report.get("secrets", {}),
                "endpoints": report.get("endpoints", []),
                "activities": report.get("manifest", {}).get("activities", []),
                "login_gates": report.get("login_gates", []),
                "post_login_candidates": report.get("post_login_candidates", []),
            }
        except Exception as e:
            raise Exception(f"Static analysis failed: {e}")
    
    def _dynamic_setup(self, context: Dict) -> Dict:
        """Phase 2: Dynamic Instrumentation Setup"""
        print("  Setting up dynamic instrumentation...")
        # This will be handled by dynamic_engine.py
        # Just return context for now
        return {
            "dynamic_setup_complete": True,
            "instrumentation_loaded": True,
        }
    
    def _intelligence_gathering(self, context: Dict) -> Dict:
        """Phase 3: Intelligence Gathering (Live)"""
        print("  Gathering intelligence...")
        # This will be handled by dynamic_engine.py
        # Just return context for now
        return {
            "intelligence_gathered": True,
            "live_data": {},
        }
    
    def _data_correlation(self, context: Dict) -> Dict:
        """Phase 4: Data Correlation & Analysis"""
        print("  Correlating data...")
        
        static_data = context.get("static_report", {})
        live_data = context.get("live_data", {})
        
        correlations = []
        
        # Correlate secrets
        static_secrets = static_data.get("secrets", {})
        live_secrets = live_data.get("secrets", [])
        
        for secret_type, static_values in static_secrets.items():
            for static_val in static_values:
                for live_secret in live_secrets:
                    if static_val in str(live_secret):
                        correlations.append({
                            "type": "secret_match",
                            "static": secret_type,
                            "static_value": static_val,
                            "live_value": live_secret,
                            "confidence": "high",
                        })
        
        return {
            "correlations": correlations,
            "high_value_targets": self._identify_high_value_targets(context),
        }
    
    def _identify_high_value_targets(self, context: Dict) -> List[Dict]:
        """Identify high-value targets for exploitation"""
        targets = []
        
        static_data = context.get("static_report", {})
        
        # Check for critical secrets
        secrets = static_data.get("secrets", {})
        if secrets.get("aws_key") or secrets.get("stripe_sk"):
            targets.append({
                "type": "cloud_credentials",
                "priority": "critical",
                "description": "Cloud credentials found",
            })
        
        # Check for exported components
        exported = static_data.get("manifest", {}).get("exported", [])
        if exported:
            targets.append({
                "type": "exported_components",
                "priority": "high",
                "description": f"{len(exported)} exported components",
                "components": exported,
            })
        
        # Check for debuggable
        if static_data.get("app_info", {}).get("debuggable"):
            targets.append({
                "type": "debuggable_app",
                "priority": "high",
                "description": "App is debuggable",
            })
        
        return targets
    
    def _adaptive_exploitation(self, context: Dict) -> Dict:
        """Phase 5: Adaptive Exploitation"""
        print("  Running adaptive exploitation...")
        # This will be handled by adaptive_exploitation_engine.py
        return {
            "exploitation_results": [],
            "exploits_executed": 0,
        }
    
    def _post_exploitation(self, context: Dict) -> Dict:
        """Phase 6: Post-Exploitation"""
        print("  Running post-exploitation...")
        return {
            "post_exploitation_complete": True,
        }
    
    def _reporting(self, context: Dict) -> Dict:
        """Phase 7: Reporting"""
        print("  Generating report...")
        
        report = {
            "package": self.package,
            "device": self.device,
            "timestamp": datetime.now().isoformat(),
            "pipeline_summary": {
                "total_phases": len(self.phases),
                "completed": len([r for r in self.phase_history if r.success]),
                "failed": len([r for r in self.phase_history if r.failed]),
                "skipped": len([r for r in self.phase_history if r.status == PhaseStatus.SKIPPED]),
            },
            "context": context,
            "phase_history": [
                {
                    "name": r.name,
                    "status": r.status.value,
                    "duration": r.duration,
                    "error": r.error,
                }
                for r in self.phase_history
            ],
        }
        
        return {
            "report": report,
            "report_generated": True,
        }
    
    def get_summary(self) -> Dict:
        """Get pipeline execution summary"""
        return {
            "total_phases": len(self.phases),
            "completed": len([r for r in self.phase_history if r.success]),
            "failed": len([r for r in self.phase_history if r.failed]),
            "skipped": len([r for r in self.phase_history if r.status == PhaseStatus.SKIPPED]),
            "total_duration": sum(r.duration for r in self.phase_history),
            "checkpoints": {k: v.status.value for k, v in self.checkpoints.items()},
        }


if __name__ == "__main__":
    # تشغيل منفصل حقيقي: يشغّل المنسّق على الهدف الفعلي المحدّد بعقل مدبّر حقيقي
    # (لا DummyBrain ولا com.example.app). يتطلّب اسم حزمة حقيقياً.
    from standalone_utils import parse_target_args, build_brain

    args = parse_target_args("Pipeline Orchestrator — تشغيل حقيقي على الهدف")
    if not args.package:
        print("[!] هذا الزر يشغّل المسار فعلياً على الهدف — يجب تحديد اسم الحزمة.")
        print("    اختر التطبيق من تبويب «الهدف والجهاز» ثم أعد المحاولة.")
        raise SystemExit(2)

    brain = build_brain(verbose=True)
    if brain is None:
        print("[!] لا يمكن تشغيل المنسّق دون عقل مدبّر حقيقي.")
        raise SystemExit(3)

    print(f"[*] تشغيل المنسّق على «{args.package}» | الجهاز {args.device}")
    orchestrator = PipelineOrchestrator(
        package=args.package,
        device=args.device,
        brain=brain,
        adb=args.adb,
    )

    results = orchestrator.run()
    summary = orchestrator.get_summary()

    print(f"\n{'='*60}")
    print("ملخّص المسار (Pipeline Summary)")
    print(f"{'='*60}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
