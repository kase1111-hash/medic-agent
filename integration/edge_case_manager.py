"""
Medic Agent Edge Case Manager

Handles unusual scenarios that don't fit standard decision patterns,
including cascading failures, rapid repeated kills, and anomalous patterns.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

from core.models import KillReport, KillReason, Severity
from core.logger import get_logger

logger = get_logger("integration.edge_case")


class EdgeCaseType(Enum):
    """Types of edge cases that can be detected."""
    RAPID_REPEATED_KILLS = "rapid_repeated_kills"
    CASCADING_FAILURE = "cascading_failure"
    CONTRADICTORY_SIGNALS = "contradictory_signals"
    NOVEL_PATTERN = "novel_pattern"
    SYSTEM_WIDE_ANOMALY = "system_wide_anomaly"
    RESOURCE_CONTENTION = "resource_contention"
    CIRCULAR_DEPENDENCY = "circular_dependency"
    FLAPPING_MODULE = "flapping_module"


class EdgeCaseSeverity(Enum):
    """Severity of detected edge cases."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EdgeCaseAction(Enum):
    """Recommended actions for edge cases."""
    PROCEED_WITH_CAUTION = "proceed_with_caution"
    REQUIRE_HUMAN_REVIEW = "require_human_review"
    PAUSE_AUTO_RESURRECTION = "pause_auto_resurrection"
    ESCALATE_IMMEDIATELY = "escalate_immediately"
    COORDINATE_WITH_SMITH = "coordinate_with_smith"
    DEFER_DECISION = "defer_decision"


@dataclass
class EdgeCase:
    """Detected edge case."""
    edge_case_id: str
    edge_case_type: EdgeCaseType
    severity: EdgeCaseSeverity
    detected_at: datetime
    description: str
    affected_modules: List[str]
    affected_kill_ids: List[str]
    recommended_action: EdgeCaseAction
    evidence: Dict[str, Any]
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolution: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "edge_case_id": self.edge_case_id,
            "edge_case_type": self.edge_case_type.value,
            "severity": self.severity.value,
            "detected_at": self.detected_at.isoformat(),
            "description": self.description,
            "affected_modules": self.affected_modules,
            "affected_kill_ids": self.affected_kill_ids,
            "recommended_action": self.recommended_action.value,
            "evidence": self.evidence,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution": self.resolution,
        }


@dataclass
class EdgeCaseConfig:
    """Configuration for edge case detection."""
    # Rapid kills detection
    rapid_kill_threshold: int = 3
    rapid_kill_window_seconds: int = 60

    # Cascading failure detection
    cascade_threshold: int = 5
    cascade_window_seconds: int = 120

    # Flapping detection
    flap_threshold: int = 4
    flap_window_minutes: int = 30

    # System-wide anomaly
    system_anomaly_module_threshold: int = 10
    system_anomaly_window_seconds: int = 300

    # Auto-pause thresholds
    auto_pause_on_critical: bool = True
    auto_escalate_on_system_anomaly: bool = True


class EdgeCaseManager:
    """
    Manages detection and handling of edge cases.

    Monitors kill patterns and system state to identify
    unusual scenarios requiring special handling.
    """

    def __init__(
        self,
        config: Optional[EdgeCaseConfig] = None,
        on_edge_case_detected: Optional[Callable] = None,
        on_action_required: Optional[Callable] = None,
    ):
        self.config = config or EdgeCaseConfig()
        self.on_edge_case_detected = on_edge_case_detected
        self.on_action_required = on_action_required

        # Kill history for pattern detection
        self._kill_history: List[KillReport] = []
        self._module_kill_times: Dict[str, List[datetime]] = {}

        # Active edge cases
        self._active_edge_cases: Dict[str, EdgeCase] = {}
        self._edge_case_history: List[EdgeCase] = []

        # State
        self._auto_resurrection_paused = False
        self._pause_reason: Optional[str] = None

        logger.info("EdgeCaseManager initialized")

    async def process_kill_report(self, kill_report: KillReport) -> Optional[EdgeCase]:
        """
        Process a kill report for edge case detection.

        Args:
            kill_report: The kill report to analyze

        Returns:
            Detected EdgeCase if any
        """
        self._record_kill(kill_report)

        # Run all detectors
        edge_cases = []

        if ec := self._detect_rapid_repeated_kills(kill_report):
            edge_cases.append(ec)

        if ec := self._detect_cascading_failure(kill_report):
            edge_cases.append(ec)

        if ec := self._detect_flapping_module(kill_report):
            edge_cases.append(ec)

        if ec := self._detect_system_wide_anomaly(kill_report):
            edge_cases.append(ec)

        if ec := self._detect_circular_dependency(kill_report):
            edge_cases.append(ec)

        # Return highest severity edge case
        if edge_cases:
            edge_cases.sort(
                key=lambda e: list(EdgeCaseSeverity).index(e.severity),
                reverse=True,
            )
            primary_edge_case = edge_cases[0]

            # Handle the edge case
            await self._handle_edge_case(primary_edge_case)

            return primary_edge_case

        return None

    def _record_kill(self, kill_report: KillReport) -> None:
        """Record a kill in history."""
        self._kill_history.append(kill_report)

        # Trim history
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        self._kill_history = [
            k for k in self._kill_history
            if k.timestamp > cutoff
        ]

        # Update module kill times
        module = kill_report.target_module
        if module not in self._module_kill_times:
            self._module_kill_times[module] = []
        self._module_kill_times[module].append(kill_report.timestamp)

        # Trim module history
        for mod in list(self._module_kill_times.keys()):
            self._module_kill_times[mod] = [
                t for t in self._module_kill_times[mod]
                if t > cutoff
            ]
            if not self._module_kill_times[mod]:
                del self._module_kill_times[mod]

    def _detect_rapid_repeated_kills(
        self,
        kill_report: KillReport,
    ) -> Optional[EdgeCase]:
        """Detect rapid repeated kills of the same module."""
        module = kill_report.target_module
        window = timedelta(seconds=self.config.rapid_kill_window_seconds)
        cutoff = datetime.now(timezone.utc) - window

        recent_kills = [
            t for t in self._module_kill_times.get(module, [])
            if t > cutoff
        ]

        if len(recent_kills) >= self.config.rapid_kill_threshold:
            return EdgeCase(
                edge_case_id=str(uuid.uuid4()),
                edge_case_type=EdgeCaseType.RAPID_REPEATED_KILLS,
                severity=EdgeCaseSeverity.HIGH,
                detected_at=datetime.now(timezone.utc),
                description=f"Module '{module}' killed {len(recent_kills)} times in {self.config.rapid_kill_window_seconds}s",
                affected_modules=[module],
                affected_kill_ids=[kill_report.kill_id],
                recommended_action=EdgeCaseAction.PAUSE_AUTO_RESURRECTION,
                evidence={
                    "kill_count": len(recent_kills),
                    "window_seconds": self.config.rapid_kill_window_seconds,
                    "kill_times": [t.isoformat() for t in recent_kills],
                },
            )

        return None

    def _detect_cascading_failure(
        self,
        kill_report: KillReport,
    ) -> Optional[EdgeCase]:
        """Detect cascading failures across dependencies."""
        window = timedelta(seconds=self.config.cascade_window_seconds)
        cutoff = datetime.now(timezone.utc) - window

        recent_kills = [
            k for k in self._kill_history
            if k.timestamp > cutoff
        ]

        if len(recent_kills) >= self.config.cascade_threshold:
            # Check if there's dependency relationship
            affected_modules = list(set(k.target_module for k in recent_kills))

            # Check for dependency cascade reason
            cascade_kills = [
                k for k in recent_kills
                if k.kill_reason == KillReason.DEPENDENCY_CASCADE
            ]

            if len(cascade_kills) >= 2 or len(affected_modules) >= 3:
                return EdgeCase(
                    edge_case_id=str(uuid.uuid4()),
                    edge_case_type=EdgeCaseType.CASCADING_FAILURE,
                    severity=EdgeCaseSeverity.CRITICAL,
                    detected_at=datetime.now(timezone.utc),
                    description=f"Cascading failure detected: {len(affected_modules)} modules affected",
                    affected_modules=affected_modules,
                    affected_kill_ids=[k.kill_id for k in recent_kills],
                    recommended_action=EdgeCaseAction.ESCALATE_IMMEDIATELY,
                    evidence={
                        "total_kills": len(recent_kills),
                        "cascade_kills": len(cascade_kills),
                        "affected_module_count": len(affected_modules),
                        "window_seconds": self.config.cascade_window_seconds,
                    },
                )

        return None

    def _detect_flapping_module(
        self,
        kill_report: KillReport,
    ) -> Optional[EdgeCase]:
        """Detect modules that are flapping (repeatedly killed and resurrected)."""
        module = kill_report.target_module
        window = timedelta(minutes=self.config.flap_window_minutes)
        cutoff = datetime.now(timezone.utc) - window

        kill_times = [
            t for t in self._module_kill_times.get(module, [])
            if t > cutoff
        ]

        if len(kill_times) >= self.config.flap_threshold:
            # Check if kills are spread out (flapping) vs clustered
            if len(kill_times) >= 2:
                intervals = [
                    (kill_times[i+1] - kill_times[i]).total_seconds()
                    for i in range(len(kill_times) - 1)
                ]
                avg_interval = sum(intervals) / len(intervals)

                # If average interval is > 2 minutes, it's likely flapping
                if avg_interval > 120:
                    return EdgeCase(
                        edge_case_id=str(uuid.uuid4()),
                        edge_case_type=EdgeCaseType.FLAPPING_MODULE,
                        severity=EdgeCaseSeverity.MEDIUM,
                        detected_at=datetime.now(timezone.utc),
                        description=f"Module '{module}' is flapping: {len(kill_times)} kills in {self.config.flap_window_minutes}min",
                        affected_modules=[module],
                        affected_kill_ids=[kill_report.kill_id],
                        recommended_action=EdgeCaseAction.REQUIRE_HUMAN_REVIEW,
                        evidence={
                            "kill_count": len(kill_times),
                            "avg_interval_seconds": avg_interval,
                            "window_minutes": self.config.flap_window_minutes,
                        },
                    )

        return None

    def _detect_system_wide_anomaly(
        self,
        kill_report: KillReport,
    ) -> Optional[EdgeCase]:
        """Detect system-wide anomalies (many modules killed simultaneously)."""
        window = timedelta(seconds=self.config.system_anomaly_window_seconds)
        cutoff = datetime.now(timezone.utc) - window

        recent_kills = [
            k for k in self._kill_history
            if k.timestamp > cutoff
        ]

        unique_modules = set(k.target_module for k in recent_kills)

        if len(unique_modules) >= self.config.system_anomaly_module_threshold:
            return EdgeCase(
                edge_case_id=str(uuid.uuid4()),
                edge_case_type=EdgeCaseType.SYSTEM_WIDE_ANOMALY,
                severity=EdgeCaseSeverity.CRITICAL,
                detected_at=datetime.now(timezone.utc),
                description=f"System-wide anomaly: {len(unique_modules)} different modules killed recently",
                affected_modules=list(unique_modules),
                affected_kill_ids=[k.kill_id for k in recent_kills],
                recommended_action=EdgeCaseAction.ESCALATE_IMMEDIATELY,
                evidence={
                    "unique_module_count": len(unique_modules),
                    "total_kills": len(recent_kills),
                    "window_seconds": self.config.system_anomaly_window_seconds,
                },
            )

        return None

    def _detect_circular_dependency(
        self,
        kill_report: KillReport,
    ) -> Optional[EdgeCase]:
        """Detect potential circular dependency issues."""
        if kill_report.kill_reason != KillReason.DEPENDENCY_CASCADE:
            return None

        # Check if this module's dependencies have also been killed recently
        window = timedelta(seconds=120)
        cutoff = datetime.now(timezone.utc) - window

        recent_kills = [
            k for k in self._kill_history
            if k.timestamp > cutoff and k.kill_id != kill_report.kill_id
        ]

        # Check for circular pattern
        recent_modules = set(k.target_module for k in recent_kills)
        dep_overlap = set(kill_report.dependencies) & recent_modules

        if len(dep_overlap) >= 2:
            return EdgeCase(
                edge_case_id=str(uuid.uuid4()),
                edge_case_type=EdgeCaseType.CIRCULAR_DEPENDENCY,
                severity=EdgeCaseSeverity.HIGH,
                detected_at=datetime.now(timezone.utc),
                description=f"Potential circular dependency: {kill_report.target_module} and {dep_overlap}",
                affected_modules=[kill_report.target_module] + list(dep_overlap),
                affected_kill_ids=[kill_report.kill_id] + [
                    k.kill_id for k in recent_kills
                    if k.target_module in dep_overlap
                ],
                recommended_action=EdgeCaseAction.COORDINATE_WITH_SMITH,
                evidence={
                    "primary_module": kill_report.target_module,
                    "overlapping_dependencies": list(dep_overlap),
                    "declared_dependencies": kill_report.dependencies,
                },
            )

        return None

    async def _handle_edge_case(self, edge_case: EdgeCase) -> None:
        """Handle a detected edge case."""
        self._active_edge_cases[edge_case.edge_case_id] = edge_case

        logger.warning(
            "Edge case detected",
            edge_case_id=edge_case.edge_case_id,
            type=edge_case.edge_case_type.value,
            severity=edge_case.severity.value,
            action=edge_case.recommended_action.value,
        )

        # Trigger callbacks
        if self.on_edge_case_detected:
            try:
                result = self.on_edge_case_detected(edge_case)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Edge case callback error: {e}")

        # Auto-handle based on configuration
        if edge_case.severity == EdgeCaseSeverity.CRITICAL:
            if self.config.auto_pause_on_critical:
                self.pause_auto_resurrection(
                    f"Critical edge case: {edge_case.edge_case_type.value}"
                )

            if self.config.auto_escalate_on_system_anomaly:
                if edge_case.edge_case_type == EdgeCaseType.SYSTEM_WIDE_ANOMALY:
                    await self._escalate(edge_case)

        # Trigger action callback
        if self.on_action_required:
            try:
                result = self.on_action_required(edge_case)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Action callback error: {e}")

    async def _escalate(self, edge_case: EdgeCase) -> None:
        """Escalate an edge case."""
        logger.critical(
            "ESCALATION: Edge case requires immediate attention",
            edge_case_id=edge_case.edge_case_id,
            type=edge_case.edge_case_type.value,
            affected_modules=edge_case.affected_modules,
        )

    def pause_auto_resurrection(self, reason: str) -> None:
        """Pause auto-resurrection."""
        self._auto_resurrection_paused = True
        self._pause_reason = reason
        logger.warning(f"Auto-resurrection PAUSED: {reason}")

    def resume_auto_resurrection(self) -> None:
        """Resume auto-resurrection."""
        self._auto_resurrection_paused = False
        self._pause_reason = None
        logger.info("Auto-resurrection RESUMED")

    def is_auto_resurrection_paused(self) -> bool:
        """Check if auto-resurrection is paused."""
        return self._auto_resurrection_paused

    def get_pause_reason(self) -> Optional[str]:
        """Get the reason for pause."""
        return self._pause_reason

    def resolve_edge_case(
        self,
        edge_case_id: str,
        resolution: str,
    ) -> bool:
        """Mark an edge case as resolved."""
        if edge_case_id not in self._active_edge_cases:
            return False

        edge_case = self._active_edge_cases[edge_case_id]
        edge_case.resolved = True
        edge_case.resolved_at = datetime.now(timezone.utc)
        edge_case.resolution = resolution

        self._edge_case_history.append(edge_case)
        del self._active_edge_cases[edge_case_id]

        logger.info(
            "Edge case resolved",
            edge_case_id=edge_case_id,
            resolution=resolution,
        )

        return True

    def get_active_edge_cases(self) -> List[EdgeCase]:
        """Get all active edge cases."""
        return list(self._active_edge_cases.values())

    def get_edge_case_history(self, limit: int = 50) -> List[EdgeCase]:
        """Get edge case history."""
        return list(reversed(self._edge_case_history[-limit:]))

    def should_allow_auto_resurrection(self, module: str) -> tuple[bool, Optional[str]]:
        """
        Check if auto-resurrection should be allowed for a module.

        Returns:
            Tuple of (allowed, reason_if_not)
        """
        if self._auto_resurrection_paused:
            return False, self._pause_reason

        # Check for active edge cases affecting this module
        for ec in self._active_edge_cases.values():
            if module in ec.affected_modules:
                if ec.recommended_action in (
                    EdgeCaseAction.PAUSE_AUTO_RESURRECTION,
                    EdgeCaseAction.ESCALATE_IMMEDIATELY,
                    EdgeCaseAction.REQUIRE_HUMAN_REVIEW,
                ):
                    return False, f"Active edge case: {ec.edge_case_type.value}"

        return True, None

    def get_statistics(self) -> Dict[str, Any]:
        """Get edge case statistics."""
        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(days=1)

        recent = [
            ec for ec in self._edge_case_history
            if ec.detected_at > day_ago
        ]

        by_type = {}
        for ec in recent:
            key = ec.edge_case_type.value
            by_type[key] = by_type.get(key, 0) + 1

        return {
            "active_edge_cases": len(self._active_edge_cases),
            "resolved_last_24h": len(recent),
            "by_type": by_type,
            "auto_resurrection_paused": self._auto_resurrection_paused,
            "pause_reason": self._pause_reason,
        }


def create_edge_case_manager(
    config: Dict[str, Any],
    on_edge_case_detected: Optional[Callable] = None,
    on_action_required: Optional[Callable] = None,
) -> EdgeCaseManager:
    """Factory function to create edge case manager."""
    edge_config = config.get("edge_cases", {})

    return EdgeCaseManager(
        config=EdgeCaseConfig(
            rapid_kill_threshold=edge_config.get("rapid_kill_threshold", 3),
            rapid_kill_window_seconds=edge_config.get("rapid_kill_window_seconds", 60),
            cascade_threshold=edge_config.get("cascade_threshold", 5),
            cascade_window_seconds=edge_config.get("cascade_window_seconds", 120),
            flap_threshold=edge_config.get("flap_threshold", 4),
            flap_window_minutes=edge_config.get("flap_window_minutes", 30),
            system_anomaly_module_threshold=edge_config.get("system_anomaly_threshold", 10),
            auto_pause_on_critical=edge_config.get("auto_pause_on_critical", True),
            auto_escalate_on_system_anomaly=edge_config.get("auto_escalate", True),
        ),
        on_edge_case_detected=on_edge_case_detected,
        on_action_required=on_action_required,
    )
