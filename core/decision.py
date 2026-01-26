"""
Medic Agent Decision Engine

Implements the core decision logic for evaluating whether to resurrect
killed modules based on kill reports and SIEM context.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import uuid

from core.models import (
    KillReport,
    SIEMContextResponse,
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

    # Confidence thresholds
    confidence_threshold: float = 0.7
    auto_approve_min_confidence: float = 0.85

    # Risk thresholds
    auto_approve_max_risk: RiskLevel = RiskLevel.LOW
    deny_min_risk: RiskLevel = RiskLevel.HIGH

    # Risk score weights
    smith_confidence_weight: float = 0.30
    siem_risk_weight: float = 0.25
    fp_history_weight: float = 0.20
    module_criticality_weight: float = 0.15
    severity_weight: float = 0.10

    # Feature flags
    auto_approve_enabled: bool = False
    observer_mode: bool = True

    # Module-specific overrides
    critical_modules: List[str] = None
    always_deny_modules: List[str] = None

    def __post_init__(self):
        if self.critical_modules is None:
            self.critical_modules = []
        if self.always_deny_modules is None:
            self.always_deny_modules = []


class DecisionEngine(ABC):
    """
    Abstract interface for resurrection decision logic.

    Implementations evaluate kill reports and SIEM context to determine
    the appropriate resurrection action.
    """

    @abstractmethod
    def should_resurrect(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> ResurrectionDecision:
        """
        Evaluate whether to resurrect a killed module.

        Args:
            kill_report: The kill event from Smith
            siem_context: Enriched context from SIEM

        Returns:
            ResurrectionDecision with outcome and reasoning
        """
        pass

    @abstractmethod
    def get_decision_factors(self) -> List[str]:
        """Return list of factors considered in decisions."""
        pass

    @abstractmethod
    def explain_decision(self, decision: ResurrectionDecision) -> str:
        """Generate human-readable explanation of decision."""
        pass


class RiskAssessor:
    """
    Calculates risk scores based on multiple weighted factors.

    The risk score is a normalized value between 0.0 (minimal risk)
    and 1.0 (critical risk).
    """

    def __init__(self, config: DecisionConfig):
        self.config = config

    def assess_risk(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> Tuple[RiskLevel, float, Dict[str, float]]:
        """
        Calculate overall risk score and level.

        Returns:
            Tuple of (RiskLevel, risk_score, factor_breakdown)
        """
        factors = self.get_risk_factors(kill_report, siem_context)
        total_score = sum(factors.values())

        # Normalize to 0.0-1.0 range
        risk_score = min(1.0, max(0.0, total_score))
        risk_level = RiskLevel.from_score(risk_score)

        return risk_level, risk_score, factors

    def get_risk_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> Dict[str, float]:
        """
        Calculate individual risk factor contributions.

        Each factor is weighted according to config and contributes
        to the overall risk score.
        """
        factors = {}

        # Factor 1: Smith's confidence (inverted - high confidence = high risk)
        smith_factor = kill_report.confidence_score * self.config.smith_confidence_weight
        factors["smith_confidence"] = smith_factor

        # Factor 2: SIEM risk score
        siem_factor = siem_context.risk_score * self.config.siem_risk_weight
        factors["siem_risk"] = siem_factor

        # Factor 3: False positive history (inverted - more FPs = lower risk)
        fp_factor = self._calculate_fp_factor(siem_context.false_positive_history)
        factors["false_positive_history"] = fp_factor

        # Factor 4: Module criticality
        criticality_factor = self._calculate_criticality_factor(kill_report.target_module)
        factors["module_criticality"] = criticality_factor

        # Factor 5: Severity
        severity_factor = self._calculate_severity_factor(kill_report.severity)
        factors["severity"] = severity_factor

        return factors

    def _calculate_fp_factor(self, fp_count: int) -> float:
        """
        Calculate false positive factor.

        More false positives in history = lower risk score
        (suggests the module is frequently flagged incorrectly)
        """
        # Diminishing returns - each FP reduces risk less
        if fp_count == 0:
            return self.config.fp_history_weight  # Full weight
        elif fp_count <= 2:
            return self.config.fp_history_weight * 0.7
        elif fp_count <= 5:
            return self.config.fp_history_weight * 0.4
        else:
            return self.config.fp_history_weight * 0.1

    def _calculate_criticality_factor(self, module: str) -> float:
        """Calculate module criticality factor."""
        if module in self.config.critical_modules:
            return self.config.module_criticality_weight  # Full weight
        return self.config.module_criticality_weight * 0.3  # Reduced for non-critical

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


class ObserverDecisionEngine(DecisionEngine):
    """
    Phase 1 Observer Mode decision engine.

    Makes decisions but does not trigger any actions.
    All decisions are logged for analysis.
    """

    def __init__(self, config: Optional[DecisionConfig] = None):
        self.config = config or DecisionConfig()
        self.risk_assessor = RiskAssessor(self.config)

        # Decision statistics
        self._decision_count = 0
        self._outcome_counts: Dict[DecisionOutcome, int] = {
            outcome: 0 for outcome in DecisionOutcome
        }

    def should_resurrect(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> ResurrectionDecision:
        """
        Evaluate resurrection decision in observer mode.

        In observer mode, all decisions are logged but no actual
        resurrection is performed.
        """
        with LogContext(kill_id=kill_report.kill_id):
            logger.info(
                "Evaluating resurrection decision",
                target_module=kill_report.target_module,
                kill_reason=kill_report.kill_reason.value,
            )

            # Check for immediate deny conditions
            if self._should_deny(kill_report, siem_context):
                return self._create_deny_decision(kill_report, siem_context)

            # Assess risk
            risk_level, risk_score, factors = self.risk_assessor.assess_risk(
                kill_report, siem_context
            )

            # Build reasoning chain
            reasoning = self._build_reasoning(
                kill_report, siem_context, risk_level, factors
            )

            # Calculate confidence in our decision
            confidence = self._calculate_confidence(
                kill_report, siem_context, factors
            )

            # Determine outcome
            outcome = self._determine_outcome(
                risk_level, risk_score, confidence, kill_report
            )

            # Create decision
            decision = ResurrectionDecision.create(
                kill_id=kill_report.kill_id,
                outcome=outcome,
                risk_score=risk_score,
                confidence=confidence,
                reasoning=reasoning,
                recommended_action=self._get_recommended_action(outcome, risk_level),
            )

            # Update statistics
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

    def _should_deny(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> bool:
        """Check for conditions that warrant immediate denial."""
        # Check always-deny list
        if kill_report.target_module in self.config.always_deny_modules:
            return True

        # Check for critical threat indicators
        for indicator in siem_context.threat_indicators:
            if indicator.threat_score > 0.9:
                return True

        # Check for confirmed threat kill reasons
        if (
            kill_report.kill_reason == KillReason.THREAT_DETECTED
            and kill_report.confidence_score > 0.95
        ):
            return True

        return False

    def _create_deny_decision(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> ResurrectionDecision:
        """Create a denial decision with appropriate reasoning."""
        reasoning = ["Immediate denial triggered"]

        if kill_report.target_module in self.config.always_deny_modules:
            reasoning.append(f"Module '{kill_report.target_module}' is on deny list")

        if kill_report.kill_reason == KillReason.THREAT_DETECTED:
            reasoning.append(
                f"Kill reason is confirmed threat with {kill_report.confidence_score:.0%} confidence"
            )

        for indicator in siem_context.threat_indicators:
            if indicator.threat_score > 0.9:
                reasoning.append(
                    f"High-severity threat indicator: {indicator.indicator_type}"
                )

        return ResurrectionDecision.create(
            kill_id=kill_report.kill_id,
            outcome=DecisionOutcome.DENY,
            risk_score=0.95,
            confidence=0.95,
            reasoning=reasoning,
            recommended_action="Do not resurrect - threat confirmed",
        )

    def _build_reasoning(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
        risk_level: RiskLevel,
        factors: Dict[str, float],
    ) -> List[str]:
        """Build human-readable reasoning for the decision."""
        reasoning = []

        # Summarize the kill
        reasoning.append(
            f"Module '{kill_report.target_module}' killed by Smith "
            f"({kill_report.kill_reason.value}) with {kill_report.confidence_score:.0%} confidence"
        )

        # SIEM assessment
        reasoning.append(
            f"SIEM risk assessment: {siem_context.risk_score:.0%} "
            f"({siem_context.recommendation})"
        )

        # False positive history
        if siem_context.false_positive_history > 0:
            reasoning.append(
                f"Module has {siem_context.false_positive_history} prior false positives"
            )

        # Threat indicators
        if siem_context.threat_indicators:
            max_threat = max(ti.threat_score for ti in siem_context.threat_indicators)
            reasoning.append(
                f"Found {len(siem_context.threat_indicators)} threat indicators "
                f"(max score: {max_threat:.0%})"
            )
        else:
            reasoning.append("No active threat indicators found")

        # Overall assessment
        reasoning.append(f"Overall risk assessment: {risk_level.value}")

        return reasoning

    def _calculate_confidence(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
        factors: Dict[str, float],
    ) -> float:
        """
        Calculate confidence in our decision.

        Higher confidence when:
        - SIEM data is fresh and complete
        - Risk factors are clearly on one side
        - Historical data supports the decision
        """
        confidence = 0.5  # Base confidence

        # More historical data = more confidence
        if siem_context.historical_behavior:
            confidence += 0.1

        # Clear risk signal = more confidence
        total_risk = sum(factors.values())
        if total_risk < 0.3 or total_risk > 0.7:
            confidence += 0.15  # Clear signal
        else:
            confidence -= 0.1  # Ambiguous signal

        # False positive history provides signal
        if siem_context.false_positive_history > 2:
            confidence += 0.1  # Good historical signal

        # SIEM recommendation consistency
        if (
            "low_risk" in siem_context.recommendation
            and total_risk < 0.4
        ) or (
            "high_risk" in siem_context.recommendation
            and total_risk > 0.6
        ):
            confidence += 0.1

        return min(1.0, max(0.0, confidence))

    def _determine_outcome(
        self,
        risk_level: RiskLevel,
        risk_score: float,
        confidence: float,
        kill_report: KillReport,
    ) -> DecisionOutcome:
        """Determine the decision outcome based on risk assessment."""
        # In observer mode, we don't actually approve anything
        if self.config.observer_mode:
            # Still classify for logging purposes
            if risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW):
                if confidence >= self.config.auto_approve_min_confidence:
                    # Would auto-approve if enabled
                    return DecisionOutcome.APPROVE_AUTO
                else:
                    return DecisionOutcome.PENDING_REVIEW
            elif risk_level == RiskLevel.MEDIUM:
                return DecisionOutcome.PENDING_REVIEW
            else:
                return DecisionOutcome.DENY

        # Non-observer mode logic (for future phases)
        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return DecisionOutcome.DENY

        if risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW):
            if self.config.auto_approve_enabled:
                if confidence >= self.config.auto_approve_min_confidence:
                    return DecisionOutcome.APPROVE_AUTO
            return DecisionOutcome.PENDING_REVIEW

        return DecisionOutcome.PENDING_REVIEW

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

        lines.extend([
            "",
            f"Recommended Action: {decision.recommended_action}",
        ])

        if decision.constraints:
            lines.append("Constraints:")
            for constraint in decision.constraints:
                lines.append(f"  - {constraint}")

        return "\n".join(lines)

    def get_statistics(self) -> Dict[str, Any]:
        """Get decision statistics."""
        return {
            "total_decisions": self._decision_count,
            "outcome_counts": {
                outcome.value: count
                for outcome, count in self._outcome_counts.items()
            },
        }


def create_decision_engine(config: Dict[str, Any]) -> DecisionEngine:
    """
    Factory function to create the appropriate decision engine.

    Args:
        config: Configuration dictionary

    Returns:
        Configured DecisionEngine instance
    """
    decision_config = config.get("decision", {})
    mode = config.get("mode", {}).get("current", "observer")

    engine_config = DecisionConfig(
        confidence_threshold=decision_config.get("confidence_threshold", 0.7),
        auto_approve_min_confidence=decision_config.get(
            "auto_approve", {}
        ).get("min_confidence", 0.85),
        auto_approve_enabled=decision_config.get(
            "auto_approve", {}
        ).get("enabled", False),
        observer_mode=(mode == "observer"),
        critical_modules=config.get("constitution", {}).get(
            "constraints", {}
        ).get("always_require_approval", []),
    )

    # Risk weights from config
    risk_config = config.get("risk", {}).get("weights", {})
    if risk_config:
        engine_config.smith_confidence_weight = risk_config.get(
            "smith_confidence", 0.30
        )
        engine_config.siem_risk_weight = risk_config.get("siem_risk_score", 0.25)
        engine_config.fp_history_weight = risk_config.get(
            "false_positive_history", 0.20
        )
        engine_config.module_criticality_weight = risk_config.get(
            "module_criticality", 0.15
        )
        engine_config.severity_weight = risk_config.get("severity", 0.10)

    return ObserverDecisionEngine(engine_config)
