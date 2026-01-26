"""
Medic Agent Pattern Analyzer

Analyzes historical outcomes to identify patterns in false positives,
high-risk modules, time-based trends, and decision accuracy.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import statistics

from learning.outcome_store import (
    OutcomeStore,
    ResurrectionOutcome,
    OutcomeType,
)
from core.logger import get_logger

logger = get_logger("learning.pattern_analyzer")


class PatternType(Enum):
    """Types of patterns that can be detected."""
    FALSE_POSITIVE_SPIKE = "false_positive_spike"
    MODULE_INSTABILITY = "module_instability"
    TIME_CORRELATION = "time_correlation"
    RISK_SCORE_DRIFT = "risk_score_drift"
    AUTO_APPROVE_DEGRADATION = "auto_approve_degradation"
    RECOVERY_TIME_INCREASE = "recovery_time_increase"
    CASCADING_FAILURES = "cascading_failures"


class PatternSeverity(Enum):
    """Severity of detected patterns."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class DetectedPattern:
    """A detected pattern in the outcome data."""
    pattern_id: str
    pattern_type: PatternType
    severity: PatternSeverity
    detected_at: datetime
    description: str
    confidence: float
    affected_modules: List[str]
    evidence: Dict[str, Any]
    recommended_actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type.value,
            "severity": self.severity.value,
            "detected_at": self.detected_at.isoformat(),
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "affected_modules": self.affected_modules,
            "evidence": self.evidence,
            "recommended_actions": self.recommended_actions,
        }


@dataclass
class ModuleProfile:
    """Behavioral profile for a module based on historical outcomes."""
    module: str
    total_resurrections: int
    success_rate: float
    avg_risk_score: float
    avg_recovery_time: float
    false_positive_rate: float
    auto_approve_eligible: bool
    risk_trend: str  # increasing, decreasing, stable
    last_failure: Optional[datetime]
    last_updated: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "module": self.module,
            "total_resurrections": self.total_resurrections,
            "success_rate": round(self.success_rate, 3),
            "avg_risk_score": round(self.avg_risk_score, 3),
            "avg_recovery_time": round(self.avg_recovery_time, 1),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "auto_approve_eligible": self.auto_approve_eligible,
            "risk_trend": self.risk_trend,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
            "last_updated": self.last_updated.isoformat(),
        }


@dataclass
class AnalysisConfig:
    """Configuration for pattern analysis."""
    min_samples_for_analysis: int = 10
    false_positive_threshold: float = 0.3  # 30% FP rate triggers warning
    success_rate_threshold: float = 0.7  # Below 70% success triggers warning
    auto_approve_accuracy_threshold: float = 0.9  # Below 90% triggers review
    time_window_days: int = 30
    trend_comparison_days: int = 7


class PatternAnalyzer:
    """
    Analyzes outcome data to detect patterns and trends.

    Detects:
    - False positive spikes
    - Module instability patterns
    - Time-correlated issues
    - Risk score calibration drift
    - Auto-approval accuracy degradation
    """

    def __init__(
        self,
        outcome_store: OutcomeStore,
        config: Optional[AnalysisConfig] = None,
    ):
        self.outcome_store = outcome_store
        self.config = config or AnalysisConfig()
        self._module_profiles: Dict[str, ModuleProfile] = {}
        self._detected_patterns: List[DetectedPattern] = []

        logger.info("PatternAnalyzer initialized")

    def analyze(self, since: Optional[datetime] = None) -> List[DetectedPattern]:
        """
        Run full pattern analysis.

        Args:
            since: Start date for analysis window

        Returns:
            List of detected patterns
        """
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=self.config.time_window_days)

        logger.info(f"Running pattern analysis since {since.isoformat()}")

        self._detected_patterns = []

        # Get outcomes for analysis
        outcomes = self.outcome_store.get_recent_outcomes(limit=1000, since=since)

        if len(outcomes) < self.config.min_samples_for_analysis:
            logger.info(f"Insufficient samples for analysis: {len(outcomes)}")
            return []

        # Run individual analyses
        self._analyze_false_positives(outcomes)
        self._analyze_module_stability(outcomes)
        self._analyze_time_patterns(outcomes)
        self._analyze_risk_score_drift(outcomes)
        self._analyze_auto_approve_accuracy(outcomes)
        self._analyze_recovery_times(outcomes)

        logger.info(f"Pattern analysis complete: {len(self._detected_patterns)} patterns detected")

        return self._detected_patterns

    def _analyze_false_positives(self, outcomes: List[ResurrectionOutcome]) -> None:
        """Analyze false positive patterns."""
        import uuid

        fp_outcomes = [o for o in outcomes if o.outcome_type == OutcomeType.FALSE_POSITIVE]
        fp_rate = len(fp_outcomes) / len(outcomes) if outcomes else 0

        if fp_rate > self.config.false_positive_threshold:
            # Group by module
            module_fp_counts = defaultdict(int)
            for o in fp_outcomes:
                module_fp_counts[o.target_module] += 1

            top_modules = sorted(
                module_fp_counts.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:5]

            pattern = DetectedPattern(
                pattern_id=str(uuid.uuid4()),
                pattern_type=PatternType.FALSE_POSITIVE_SPIKE,
                severity=PatternSeverity.WARNING if fp_rate < 0.5 else PatternSeverity.CRITICAL,
                detected_at=datetime.now(timezone.utc),
                description=f"High false positive rate detected: {fp_rate:.1%}",
                confidence=min(0.95, 0.5 + len(fp_outcomes) / 100),
                affected_modules=[m for m, _ in top_modules],
                evidence={
                    "false_positive_rate": fp_rate,
                    "fp_count": len(fp_outcomes),
                    "total_outcomes": len(outcomes),
                    "top_modules": dict(top_modules),
                },
                recommended_actions=[
                    "Review Smith detection thresholds",
                    "Analyze common characteristics of false positives",
                    "Consider adjusting risk scoring weights",
                ],
            )
            self._detected_patterns.append(pattern)

    def _analyze_module_stability(self, outcomes: List[ResurrectionOutcome]) -> None:
        """Analyze module stability patterns."""
        import uuid

        # Group by module
        module_outcomes: Dict[str, List[ResurrectionOutcome]] = defaultdict(list)
        for o in outcomes:
            module_outcomes[o.target_module].append(o)

        unstable_modules = []

        for module, module_outs in module_outcomes.items():
            if len(module_outs) < 3:
                continue

            failures = [
                o for o in module_outs
                if o.outcome_type in (OutcomeType.FAILURE, OutcomeType.ROLLBACK)
            ]
            failure_rate = len(failures) / len(module_outs)

            if failure_rate > (1 - self.config.success_rate_threshold):
                unstable_modules.append({
                    "module": module,
                    "failure_rate": failure_rate,
                    "total_resurrections": len(module_outs),
                    "failures": len(failures),
                })

        if unstable_modules:
            pattern = DetectedPattern(
                pattern_id=str(uuid.uuid4()),
                pattern_type=PatternType.MODULE_INSTABILITY,
                severity=PatternSeverity.WARNING,
                detected_at=datetime.now(timezone.utc),
                description=f"{len(unstable_modules)} modules showing instability",
                confidence=0.8,
                affected_modules=[m["module"] for m in unstable_modules],
                evidence={
                    "unstable_modules": unstable_modules,
                },
                recommended_actions=[
                    "Review module health checks",
                    "Consider excluding from auto-resurrection",
                    "Investigate root cause of repeated failures",
                ],
            )
            self._detected_patterns.append(pattern)

    def _analyze_time_patterns(self, outcomes: List[ResurrectionOutcome]) -> None:
        """Analyze time-correlated patterns."""
        import uuid

        # Group by hour
        hour_outcomes: Dict[int, List[ResurrectionOutcome]] = defaultdict(list)
        for o in outcomes:
            hour_outcomes[o.timestamp.hour].append(o)

        # Calculate failure rate by hour
        hour_failure_rates = {}
        for hour, hour_outs in hour_outcomes.items():
            if len(hour_outs) >= 3:
                failures = [o for o in hour_outs if o.outcome_type in (OutcomeType.FAILURE, OutcomeType.ROLLBACK)]
                hour_failure_rates[hour] = len(failures) / len(hour_outs)

        if not hour_failure_rates:
            return

        avg_rate = statistics.mean(hour_failure_rates.values())
        high_risk_hours = [
            h for h, rate in hour_failure_rates.items()
            if rate > avg_rate * 1.5 and rate > 0.3
        ]

        if high_risk_hours:
            pattern = DetectedPattern(
                pattern_id=str(uuid.uuid4()),
                pattern_type=PatternType.TIME_CORRELATION,
                severity=PatternSeverity.INFO,
                detected_at=datetime.now(timezone.utc),
                description=f"Higher failure rates detected during hours: {high_risk_hours}",
                confidence=0.7,
                affected_modules=[],
                evidence={
                    "high_risk_hours": high_risk_hours,
                    "hour_failure_rates": hour_failure_rates,
                    "average_failure_rate": avg_rate,
                },
                recommended_actions=[
                    "Consider time-based risk adjustments",
                    "Review deployments during high-risk hours",
                    "Investigate time-specific triggers",
                ],
            )
            self._detected_patterns.append(pattern)

    def _analyze_risk_score_drift(self, outcomes: List[ResurrectionOutcome]) -> None:
        """Analyze if risk scores are drifting from actual outcomes."""
        import uuid

        if len(outcomes) < 20:
            return

        # Split into two periods
        outcomes_sorted = sorted(outcomes, key=lambda o: o.timestamp)
        midpoint = len(outcomes_sorted) // 2

        first_half = outcomes_sorted[:midpoint]
        second_half = outcomes_sorted[midpoint:]

        def calc_calibration(outs: List[ResurrectionOutcome]) -> float:
            """Calculate how well risk scores predict outcomes."""
            if not outs:
                return 0.0

            successes = [o for o in outs if o.outcome_type == OutcomeType.SUCCESS]
            failures = [o for o in outs if o.outcome_type in (OutcomeType.FAILURE, OutcomeType.ROLLBACK)]

            if not successes or not failures:
                return 0.0

            # Success should have lower risk scores than failures
            avg_success_risk = statistics.mean(o.original_risk_score for o in successes)
            avg_failure_risk = statistics.mean(o.original_risk_score for o in failures)

            # Higher gap = better calibration
            return avg_failure_risk - avg_success_risk

        first_calibration = calc_calibration(first_half)
        second_calibration = calc_calibration(second_half)

        # Check for degradation
        if first_calibration > 0.1 and second_calibration < first_calibration * 0.5:
            pattern = DetectedPattern(
                pattern_id=str(uuid.uuid4()),
                pattern_type=PatternType.RISK_SCORE_DRIFT,
                severity=PatternSeverity.WARNING,
                detected_at=datetime.now(timezone.utc),
                description="Risk score calibration has degraded over time",
                confidence=0.75,
                affected_modules=[],
                evidence={
                    "first_period_calibration": first_calibration,
                    "second_period_calibration": second_calibration,
                    "calibration_change": second_calibration - first_calibration,
                },
                recommended_actions=[
                    "Review risk scoring weights",
                    "Retrain risk model with recent data",
                    "Consider adaptive threshold adjustment",
                ],
            )
            self._detected_patterns.append(pattern)

    def _analyze_auto_approve_accuracy(self, outcomes: List[ResurrectionOutcome]) -> None:
        """Analyze auto-approval accuracy trends."""
        import uuid

        auto_approved = [o for o in outcomes if o.was_auto_approved]

        if len(auto_approved) < 10:
            return

        auto_success = [o for o in auto_approved if o.outcome_type == OutcomeType.SUCCESS]
        accuracy = len(auto_success) / len(auto_approved)

        if accuracy < self.config.auto_approve_accuracy_threshold:
            # Find problematic modules
            module_failures = defaultdict(int)
            for o in auto_approved:
                if o.outcome_type != OutcomeType.SUCCESS:
                    module_failures[o.target_module] += 1

            top_failing = sorted(
                module_failures.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:5]

            pattern = DetectedPattern(
                pattern_id=str(uuid.uuid4()),
                pattern_type=PatternType.AUTO_APPROVE_DEGRADATION,
                severity=PatternSeverity.CRITICAL if accuracy < 0.7 else PatternSeverity.WARNING,
                detected_at=datetime.now(timezone.utc),
                description=f"Auto-approval accuracy has dropped to {accuracy:.1%}",
                confidence=0.9,
                affected_modules=[m for m, _ in top_failing],
                evidence={
                    "auto_approve_accuracy": accuracy,
                    "auto_approved_count": len(auto_approved),
                    "auto_success_count": len(auto_success),
                    "top_failing_modules": dict(top_failing),
                },
                recommended_actions=[
                    "Tighten auto-approval thresholds",
                    "Review modules with high auto-approve failure rates",
                    "Consider moving to manual mode temporarily",
                ],
            )
            self._detected_patterns.append(pattern)

    def _analyze_recovery_times(self, outcomes: List[ResurrectionOutcome]) -> None:
        """Analyze recovery time trends."""
        import uuid

        successful = [
            o for o in outcomes
            if o.outcome_type == OutcomeType.SUCCESS and o.time_to_healthy is not None
        ]

        if len(successful) < 10:
            return

        # Split into periods and compare
        successful_sorted = sorted(successful, key=lambda o: o.timestamp)
        midpoint = len(successful_sorted) // 2

        first_half = successful_sorted[:midpoint]
        second_half = successful_sorted[midpoint:]

        avg_first = statistics.mean(o.time_to_healthy for o in first_half)
        avg_second = statistics.mean(o.time_to_healthy for o in second_half)

        # Check for significant increase (>50%)
        if avg_second > avg_first * 1.5 and avg_second > 60:  # More than 1 minute
            pattern = DetectedPattern(
                pattern_id=str(uuid.uuid4()),
                pattern_type=PatternType.RECOVERY_TIME_INCREASE,
                severity=PatternSeverity.INFO,
                detected_at=datetime.now(timezone.utc),
                description=f"Module recovery times have increased from {avg_first:.0f}s to {avg_second:.0f}s",
                confidence=0.7,
                affected_modules=[],
                evidence={
                    "first_period_avg": avg_first,
                    "second_period_avg": avg_second,
                    "increase_percent": (avg_second - avg_first) / avg_first * 100,
                },
                recommended_actions=[
                    "Review module startup procedures",
                    "Check for resource constraints",
                    "Investigate dependency loading times",
                ],
            )
            self._detected_patterns.append(pattern)

    def build_module_profile(self, module: str) -> ModuleProfile:
        """Build a behavioral profile for a module."""
        outcomes = self.outcome_store.get_outcomes_by_module(module, limit=100)

        if not outcomes:
            return ModuleProfile(
                module=module,
                total_resurrections=0,
                success_rate=0.0,
                avg_risk_score=0.0,
                avg_recovery_time=0.0,
                false_positive_rate=0.0,
                auto_approve_eligible=False,
                risk_trend="unknown",
                last_failure=None,
                last_updated=datetime.now(timezone.utc),
            )

        successes = [o for o in outcomes if o.outcome_type == OutcomeType.SUCCESS]
        failures = [o for o in outcomes if o.outcome_type in (OutcomeType.FAILURE, OutcomeType.ROLLBACK)]
        false_positives = [o for o in outcomes if o.outcome_type == OutcomeType.FALSE_POSITIVE]

        success_rate = len(successes) / len(outcomes)
        fp_rate = len(false_positives) / len(outcomes)

        # Calculate risk trend
        if len(outcomes) >= 10:
            recent = outcomes[:len(outcomes)//2]
            older = outcomes[len(outcomes)//2:]
            recent_avg = statistics.mean(o.original_risk_score for o in recent)
            older_avg = statistics.mean(o.original_risk_score for o in older)
            if recent_avg > older_avg * 1.2:
                trend = "increasing"
            elif recent_avg < older_avg * 0.8:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"

        # Determine auto-approve eligibility
        auto_approve_eligible = (
            len(outcomes) >= 5
            and success_rate >= 0.9
            and fp_rate >= 0.2  # High FP rate = Smith being too aggressive
        )

        profile = ModuleProfile(
            module=module,
            total_resurrections=len(outcomes),
            success_rate=success_rate,
            avg_risk_score=statistics.mean(o.original_risk_score for o in outcomes),
            avg_recovery_time=(
                statistics.mean(o.time_to_healthy or 0 for o in successes)
                if successes else 0.0
            ),
            false_positive_rate=fp_rate,
            auto_approve_eligible=auto_approve_eligible,
            risk_trend=trend,
            last_failure=failures[0].timestamp if failures else None,
            last_updated=datetime.now(timezone.utc),
        )

        self._module_profiles[module] = profile
        return profile

    def get_all_module_profiles(self) -> List[ModuleProfile]:
        """Get profiles for all known modules."""
        outcomes = self.outcome_store.get_recent_outcomes(limit=1000)

        modules = set(o.target_module for o in outcomes)
        profiles = [self.build_module_profile(m) for m in modules]

        return sorted(profiles, key=lambda p: p.total_resurrections, reverse=True)

    def get_recommendations(self) -> Dict[str, Any]:
        """Get actionable recommendations based on analysis."""
        patterns = self.analyze()

        recommendations = {
            "patterns_detected": len(patterns),
            "critical_patterns": [p.to_dict() for p in patterns if p.severity == PatternSeverity.CRITICAL],
            "warnings": [p.to_dict() for p in patterns if p.severity == PatternSeverity.WARNING],
            "info": [p.to_dict() for p in patterns if p.severity == PatternSeverity.INFO],
            "suggested_actions": [],
        }

        # Aggregate actions
        all_actions = set()
        for pattern in patterns:
            all_actions.update(pattern.recommended_actions)

        recommendations["suggested_actions"] = list(all_actions)

        return recommendations


def create_pattern_analyzer(
    outcome_store: OutcomeStore,
    config: Optional[Dict[str, Any]] = None,
) -> PatternAnalyzer:
    """Factory function to create pattern analyzer."""
    analysis_config = None

    if config:
        analysis_config = AnalysisConfig(
            min_samples_for_analysis=config.get("min_samples", 10),
            false_positive_threshold=config.get("false_positive_threshold", 0.3),
            success_rate_threshold=config.get("success_rate_threshold", 0.7),
            auto_approve_accuracy_threshold=config.get("auto_approve_accuracy_threshold", 0.9),
            time_window_days=config.get("time_window_days", 30),
        )

    return PatternAnalyzer(outcome_store, analysis_config)
