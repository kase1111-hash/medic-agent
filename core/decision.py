"""
Medic Agent Decision Engine

Core decision logic for evaluating whether to resurrect killed modules.
Supports observer mode (log-only) and live mode (actionable decisions).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.models import (
    KillReport,
    SIEMResult,
    ResurrectionDecision,
    DecisionOutcome,
    RiskLevel,
    KillReason,
    Severity,
)
from core.logger import get_logger, LogContext

logger = get_logger("core.decision")


@dataclass
class DecisionConfig:
    """Configuration for the decision engine."""
    confidence_threshold: float = 0.7
    auto_approve_min_confidence: float = 0.85

    auto_approve_max_risk: RiskLevel = RiskLevel.LOW
    deny_min_risk: RiskLevel = RiskLevel.HIGH

    smith_confidence_weight: float = 0.30
    siem_risk_weight: float = 0.25
    fp_history_weight: float = 0.20
    module_criticality_weight: float = 0.15
    severity_weight: float = 0.10

    auto_approve_enabled: bool = False

    critical_modules: List[str] = None
    always_deny_modules: List[str] = None

    def __post_init__(self):
        if self.critical_modules is None:
            self.critical_modules = []
        if self.always_deny_modules is None:
            self.always_deny_modules = []


class DecisionEngine(ABC):
    """Abstract interface for resurrection decision logic."""

    @abstractmethod
    def should_resurrect(
        self,
        kill_report: KillReport,
        siem_result: Optional[SIEMResult] = None,
    ) -> ResurrectionDecision:
        """Evaluate whether to resurrect a killed module."""
        pass

    @abstractmethod
    def get_decision_factors(self) -> List[str]:
        """Return list of factors considered in decisions."""
        pass

    @abstractmethod
    def explain_decision(self, decision: ResurrectionDecision) -> str:
        """Generate human-readable explanation of decision."""
        pass


class _BaseDecisionEngine(DecisionEngine):
    """Shared decision logic for observer and live modes."""

    def __init__(
        self,
        config: Optional[DecisionConfig] = None,
        outcome_store: Optional[Any] = None,
    ):
        self.config = config or DecisionConfig()
        self.outcome_store = outcome_store
        self._decision_count = 0
        self._outcome_counts: Dict[DecisionOutcome, int] = {
            outcome: 0 for outcome in DecisionOutcome
        }

    def should_resurrect(
        self,
        kill_report: KillReport,
        siem_result: Optional[SIEMResult] = None,
    ) -> ResurrectionDecision:
        """Evaluate resurrection decision."""
        siem = siem_result or SIEMResult()

        with LogContext(kill_id=kill_report.kill_id):
            logger.info(
                "Evaluating resurrection decision",
                target_module=kill_report.target_module,
                kill_reason=kill_report.kill_reason.value,
            )

            # Check for immediate deny
            if self._should_deny(kill_report):
                return self._create_deny_decision(kill_report)

            # Assess risk
            risk_level, risk_score, factors = self._assess_risk(kill_report, siem)

            # Build reasoning
            reasoning = self._build_reasoning(kill_report, siem, risk_level, factors)

            # Calculate confidence
            confidence = self._calculate_confidence(kill_report, siem, factors)

            # Determine outcome
            outcome = self._determine_outcome(risk_level, risk_score, confidence, kill_report)

            decision = ResurrectionDecision.create(
                kill_id=kill_report.kill_id,
                outcome=outcome,
                risk_score=risk_score,
                confidence=confidence,
                reasoning=reasoning,
                recommended_action=self._get_recommended_action(outcome, risk_level),
            )

            self._decision_count += 1
            self._outcome_counts[outcome] += 1

            logger.info(
                "Decision made",
                decision_id=decision.decision_id,
                outcome=outcome.value,
                risk_level=risk_level.value,
                risk_score=round(risk_score, 3),
                confidence=round(confidence, 3),
            )

            return decision

    def _should_deny(self, kill_report: KillReport) -> bool:
        """Check for conditions that warrant immediate denial."""
        if kill_report.target_module in self.config.always_deny_modules:
            return True

        if (
            kill_report.kill_reason == KillReason.THREAT_DETECTED
            and kill_report.confidence_score > 0.95
        ):
            return True

        return False

    def _create_deny_decision(self, kill_report: KillReport) -> ResurrectionDecision:
        """Create a denial decision with appropriate reasoning."""
        reasoning = ["Immediate denial triggered"]

        if kill_report.target_module in self.config.always_deny_modules:
            reasoning.append(f"Module '{kill_report.target_module}' is on deny list")

        if kill_report.kill_reason == KillReason.THREAT_DETECTED:
            reasoning.append(
                f"Kill reason is confirmed threat with {kill_report.confidence_score:.0%} confidence"
            )

        return ResurrectionDecision.create(
            kill_id=kill_report.kill_id,
            outcome=DecisionOutcome.DENY,
            risk_score=0.95,
            confidence=0.95,
            reasoning=reasoning,
            recommended_action="Do not resurrect - threat confirmed",
        )

    def _assess_risk(
        self,
        kill_report: KillReport,
        siem: SIEMResult,
    ) -> Tuple[RiskLevel, float, Dict[str, float]]:
        """Calculate overall risk score and level."""
        factors = {}

        factors["smith_confidence"] = kill_report.confidence_score * self.config.smith_confidence_weight
        factors["siem_risk"] = siem.risk_score * self.config.siem_risk_weight

        # Combine SIEM FP count with outcome store history
        fp_count = siem.false_positive_history
        module_history = self._get_module_history(kill_report.target_module)
        fp_count = max(fp_count, module_history.get("false_positive_count", 0))
        factors["false_positive_history"] = self._calculate_fp_factor(fp_count)

        factors["module_criticality"] = self._calculate_criticality_factor(kill_report.target_module)
        factors["severity"] = self._calculate_severity_factor(kill_report.severity)

        risk_score = min(1.0, max(0.0, sum(factors.values())))
        risk_level = RiskLevel.from_score(risk_score)

        return risk_level, risk_score, factors

    def _calculate_fp_factor(self, fp_count: int) -> float:
        """More false positives = lower risk."""
        if fp_count == 0:
            return self.config.fp_history_weight
        elif fp_count <= 2:
            return self.config.fp_history_weight * 0.7
        elif fp_count <= 5:
            return self.config.fp_history_weight * 0.4
        else:
            return self.config.fp_history_weight * 0.1

    def _calculate_criticality_factor(self, module: str) -> float:
        """Calculate module criticality factor."""
        if module in self.config.critical_modules:
            return self.config.module_criticality_weight
        return self.config.module_criticality_weight * 0.3

    def _calculate_severity_factor(self, severity: Severity) -> float:
        """Calculate severity contribution to risk."""
        severity_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }
        base_score = severity_scores.get(severity, 0.5)
        return base_score * self.config.severity_weight

    def _build_reasoning(
        self,
        kill_report: KillReport,
        siem: SIEMResult,
        risk_level: RiskLevel,
        factors: Dict[str, float],
    ) -> List[str]:
        """Build human-readable reasoning for the decision."""
        reasoning = [
            f"Module '{kill_report.target_module}' killed by Smith "
            f"({kill_report.kill_reason.value}) with {kill_report.confidence_score:.0%} confidence",
            f"SIEM risk assessment: {siem.risk_score:.0%} ({siem.recommendation})",
        ]

        if siem.false_positive_history > 0:
            reasoning.append(
                f"Module has {siem.false_positive_history} prior false positives"
            )

        reasoning.append(f"Overall risk assessment: {risk_level.value}")
        return reasoning

    def _calculate_confidence(
        self,
        kill_report: KillReport,
        siem: SIEMResult,
        factors: Dict[str, float],
    ) -> float:
        """Calculate confidence in our decision."""
        confidence = 0.5

        if siem.recommendation != "unknown":
            confidence += 0.1

        total_risk = sum(factors.values())
        if total_risk < 0.3 or total_risk > 0.7:
            confidence += 0.15
        else:
            confidence -= 0.1

        if siem.false_positive_history > 2:
            confidence += 0.1

        # Historical data from outcome store boosts confidence
        history = self._get_module_history(kill_report.target_module)
        if history.get("incident_count", 0) > 0:
            confidence += 0.1
            # High success rate for this module = even more confident
            if history.get("success_rate", 0.0) > 0.8:
                confidence += 0.05

        return min(1.0, max(0.0, confidence))

    @abstractmethod
    def _determine_outcome(
        self,
        risk_level: RiskLevel,
        risk_score: float,
        confidence: float,
        kill_report: KillReport,
    ) -> DecisionOutcome:
        """Determine the decision outcome. Differs between observer/live mode."""
        pass

    def _get_recommended_action(
        self, outcome: DecisionOutcome, risk_level: RiskLevel
    ) -> str:
        """Get recommended action based on outcome."""
        if outcome == DecisionOutcome.DENY:
            return "Do not resurrect - risk too high"
        elif outcome == DecisionOutcome.APPROVE_AUTO:
            return "Auto-resurrect - low risk with high confidence"
        elif outcome == DecisionOutcome.PENDING_REVIEW:
            if risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW):
                return "Manual review recommended - likely safe to resurrect"
            else:
                return "Manual review required - moderate risk assessment"
        elif outcome == DecisionOutcome.DEFER:
            return "Gather additional information before deciding"
        else:
            return "Approve resurrection after human verification"

    def get_decision_factors(self) -> List[str]:
        """Return list of factors considered in decisions."""
        return [
            "smith_confidence - Smith's kill confidence score",
            "siem_risk - SIEM aggregated risk score",
            "false_positive_history - Prior false positive count for module",
            "module_criticality - Whether module is marked critical",
            "severity - Kill event severity level",
        ]

    def explain_decision(self, decision: ResurrectionDecision) -> str:
        """Generate human-readable explanation of decision."""
        lines = [
            f"Decision: {decision.outcome.value.upper()}",
            f"Risk Level: {decision.risk_level.value} (score: {decision.risk_score:.2f})",
            f"Confidence: {decision.confidence:.0%}",
            "",
            "Reasoning:",
        ]
        for i, reason in enumerate(decision.reasoning, 1):
            lines.append(f"  {i}. {reason}")

        lines.extend(["", f"Recommended Action: {decision.recommended_action}"])
        return "\n".join(lines)

    def _get_module_history(self, module: str) -> Dict[str, Any]:
        """Get historical data for a module from the outcome store."""
        if not self.outcome_store:
            return {}

        try:
            outcomes = self.outcome_store.get_outcomes_by_module(module, limit=100)
            if not outcomes:
                return {}

            success_count = sum(1 for o in outcomes if o.outcome_type.value == "success")
            failure_count = sum(1 for o in outcomes if o.outcome_type.value == "failure")
            total = len(outcomes)

            return {
                "incident_count": total,
                "success_count": success_count,
                "failure_count": failure_count,
                "success_rate": success_count / total if total > 0 else 0.0,
                "false_positive_count": failure_count,
            }
        except Exception as e:
            logger.warning("Failed to get module history: %s", e)
            return {}

    def calibrate(self) -> None:
        """
        Adjust decision thresholds based on historical outcome data.

        If we have enough data (50+ outcomes) and auto-approved
        resurrections have a >95% success rate, lower the confidence
        threshold to auto-approve more aggressively.

        Called on startup and can be called periodically.
        """
        if not self.outcome_store:
            logger.info("Calibration skipped: no outcome store")
            return

        try:
            stats = self.outcome_store.get_statistics()
        except Exception as e:
            logger.warning("Calibration failed: %s", e)
            return

        total = stats.total_outcomes
        if total < 50:
            logger.info(
                "Calibration skipped: insufficient data",
                total_outcomes=total,
                required=50,
            )
            return

        # Calculate auto-approve accuracy from outcomes
        auto_approved = [
            o for o in self.outcome_store.get_recent_outcomes(limit=500)
            if o.was_auto_approved
        ]
        if len(auto_approved) < 10:
            logger.info(
                "Calibration skipped: too few auto-approved outcomes",
                auto_approved_count=len(auto_approved),
            )
            return

        successes = sum(1 for o in auto_approved if o.outcome_type.value == "success")
        accuracy = successes / len(auto_approved)

        old_threshold = self.config.auto_approve_min_confidence

        if accuracy > 0.95:
            # High success rate — relax confidence threshold slightly
            self.config.auto_approve_min_confidence = max(
                self.config.auto_approve_min_confidence - 0.05, 0.6
            )
            logger.info(
                "Calibration: lowered auto-approve threshold (high accuracy)",
                accuracy=round(accuracy, 3),
                old_threshold=round(old_threshold, 3),
                new_threshold=round(self.config.auto_approve_min_confidence, 3),
                auto_approved_count=len(auto_approved),
                success_count=successes,
            )
        elif accuracy < 0.8:
            # Low success rate — tighten threshold
            self.config.auto_approve_min_confidence = min(
                self.config.auto_approve_min_confidence + 0.05, 0.95
            )
            logger.info(
                "Calibration: raised auto-approve threshold (low accuracy)",
                accuracy=round(accuracy, 3),
                old_threshold=round(old_threshold, 3),
                new_threshold=round(self.config.auto_approve_min_confidence, 3),
            )
        else:
            logger.info(
                "Calibration: thresholds unchanged (acceptable accuracy)",
                accuracy=round(accuracy, 3),
                threshold=round(old_threshold, 3),
            )

    def get_statistics(self) -> Dict[str, Any]:
        """Get decision statistics."""
        return {
            "total_decisions": self._decision_count,
            "outcome_counts": {
                outcome.value: count
                for outcome, count in self._outcome_counts.items()
            },
        }


class ObserverDecisionEngine(_BaseDecisionEngine):
    """
    Observer mode: classifies decisions for logging but never triggers actions.
    All decisions are tagged with what *would* happen.
    """

    def _determine_outcome(
        self,
        risk_level: RiskLevel,
        risk_score: float,
        confidence: float,
        kill_report: KillReport,
    ) -> DecisionOutcome:
        """Classify for logging — no actual resurrection happens."""
        if risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW):
            if confidence >= self.config.auto_approve_min_confidence:
                return DecisionOutcome.APPROVE_AUTO
            else:
                return DecisionOutcome.PENDING_REVIEW
        elif risk_level == RiskLevel.MEDIUM:
            return DecisionOutcome.PENDING_REVIEW
        else:
            return DecisionOutcome.DENY


class LiveDecisionEngine(_BaseDecisionEngine):
    """
    Live mode: returns actionable decisions. When auto_approve is enabled,
    low-risk reports get APPROVE_AUTO and the caller executes resurrection.
    """

    def _determine_outcome(
        self,
        risk_level: RiskLevel,
        risk_score: float,
        confidence: float,
        kill_report: KillReport,
    ) -> DecisionOutcome:
        """Return actionable outcome."""
        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return DecisionOutcome.DENY

        if risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW):
            if self.config.auto_approve_enabled:
                if confidence >= self.config.auto_approve_min_confidence:
                    return DecisionOutcome.APPROVE_AUTO
            return DecisionOutcome.PENDING_REVIEW

        return DecisionOutcome.PENDING_REVIEW


def create_decision_engine(
    config: Dict[str, Any],
    outcome_store: Optional[Any] = None,
) -> DecisionEngine:
    """Factory function to create the appropriate decision engine."""
    decision_config = config.get("decision", {})
    mode = config.get("mode", "observer")

    engine_config = DecisionConfig(
        confidence_threshold=decision_config.get("confidence_threshold", 0.7),
        auto_approve_min_confidence=decision_config.get(
            "auto_approve", {}
        ).get("min_confidence", 0.85),
        auto_approve_enabled=decision_config.get(
            "auto_approve", {}
        ).get("enabled", False),
        critical_modules=config.get("critical_modules", []),
    )

    risk_config = config.get("risk", {}).get("weights", {})
    if risk_config:
        engine_config.smith_confidence_weight = risk_config.get("smith_confidence", 0.30)
        engine_config.siem_risk_weight = risk_config.get("siem_risk_score", 0.25)
        engine_config.fp_history_weight = risk_config.get("false_positive_history", 0.20)
        engine_config.module_criticality_weight = risk_config.get("module_criticality", 0.15)
        engine_config.severity_weight = risk_config.get("severity", 0.10)

    if mode == "observer":
        return ObserverDecisionEngine(engine_config, outcome_store=outcome_store)
    else:
        return LiveDecisionEngine(engine_config, outcome_store=outcome_store)
