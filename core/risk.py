"""
Medic Agent Risk Assessment Engine

Multi-factor risk scoring with configurable weights for resurrection decisions.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from core.models import (
    KillReport,
    SIEMResult,
    RiskLevel,
    KillReason,
    Severity,
)
from core.logger import get_logger

logger = get_logger("core.risk")


@dataclass
class RiskFactor:
    """Individual risk factor with metadata."""
    name: str
    raw_value: float
    weight: float
    weighted_score: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "raw_value": round(self.raw_value, 3),
            "weight": round(self.weight, 3),
            "weighted_score": round(self.weighted_score, 3),
            "description": self.description,
        }


@dataclass
class RiskAssessment:
    """Complete risk assessment result."""
    assessment_id: str
    kill_id: str
    timestamp: datetime
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    factors: List[RiskFactor]
    recommendations: List[str]
    auto_approve_eligible: bool
    requires_escalation: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "kill_id": self.kill_id,
            "timestamp": self.timestamp.isoformat(),
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 3),
            "confidence": round(self.confidence, 3),
            "factors": [f.to_dict() for f in self.factors],
            "recommendations": self.recommendations,
            "auto_approve_eligible": self.auto_approve_eligible,
            "requires_escalation": self.requires_escalation,
        }


@dataclass
class RiskThresholds:
    """Configurable risk thresholds."""
    auto_approve_max_score: float = 0.3
    auto_approve_min_confidence: float = 0.85
    escalation_min_score: float = 0.7
    deny_min_score: float = 0.85


@dataclass
class RiskWeights:
    """Configurable weights for risk factors."""
    smith_confidence: float = 0.30
    siem_risk_score: float = 0.25
    false_positive_history: float = 0.20
    kill_reason: float = 0.10
    severity: float = 0.10
    module_criticality: float = 0.05


class RiskAssessor(ABC):
    """Abstract interface for risk assessment."""

    @abstractmethod
    def assess(
        self,
        kill_report: KillReport,
        siem_result: Optional[SIEMResult] = None,
    ) -> RiskAssessment:
        """Perform comprehensive risk assessment."""
        pass

    @abstractmethod
    def get_thresholds(self) -> RiskThresholds:
        """Get current thresholds."""
        pass

    @abstractmethod
    def update_thresholds(self, thresholds: RiskThresholds) -> None:
        """Update risk thresholds."""
        pass


class AdvancedRiskAssessor(RiskAssessor):
    """
    Risk assessment with multi-factor analysis.

    Evaluates kill report data and optional SIEM enrichment to produce
    a weighted risk score with confidence estimation.
    """

    def __init__(
        self,
        weights: Optional[RiskWeights] = None,
        thresholds: Optional[RiskThresholds] = None,
        critical_modules: Optional[List[str]] = None,
        outcome_store: Optional[Any] = None,
    ):
        self.weights = weights or RiskWeights()
        self.thresholds = thresholds or RiskThresholds()
        self.critical_modules = set(critical_modules or [])
        self.outcome_store = outcome_store

    def assess(
        self,
        kill_report: KillReport,
        siem_result: Optional[SIEMResult] = None,
    ) -> RiskAssessment:
        """Perform comprehensive risk assessment."""
        siem = siem_result or SIEMResult()
        factors: List[RiskFactor] = []

        # Smith confidence
        factors.append(RiskFactor(
            name="smith_confidence",
            raw_value=kill_report.confidence_score,
            weight=self.weights.smith_confidence,
            weighted_score=kill_report.confidence_score * self.weights.smith_confidence,
            description=f"Smith kill confidence: {kill_report.confidence_score:.0%}",
        ))

        # SIEM risk score
        factors.append(RiskFactor(
            name="siem_risk_score",
            raw_value=siem.risk_score,
            weight=self.weights.siem_risk_score,
            weighted_score=siem.risk_score * self.weights.siem_risk_score,
            description=f"SIEM risk score: {siem.risk_score:.0%}",
        ))

        # False positive history (inverted: more FPs = lower risk)
        fp_count = siem.false_positive_history
        module_history = self._get_module_history(kill_report.target_module)
        fp_count = max(fp_count, module_history.get("false_positive_count", 0))

        if fp_count == 0:
            fp_score = 0.8
        elif fp_count <= 2:
            fp_score = 0.5
        elif fp_count <= 5:
            fp_score = 0.3
        else:
            fp_score = 0.1

        factors.append(RiskFactor(
            name="false_positive_history",
            raw_value=fp_score,
            weight=self.weights.false_positive_history,
            weighted_score=fp_score * self.weights.false_positive_history,
            description=f"False positive history: {fp_count} prior FPs",
        ))

        # Kill reason
        reason_scores = {
            KillReason.THREAT_DETECTED: 0.9,
            KillReason.ANOMALY_BEHAVIOR: 0.6,
            KillReason.POLICY_VIOLATION: 0.5,
            KillReason.RESOURCE_EXHAUSTION: 0.2,
            KillReason.DEPENDENCY_CASCADE: 0.3,
            KillReason.MANUAL_OVERRIDE: 0.4,
        }
        reason_score = reason_scores.get(kill_report.kill_reason, 0.5)
        factors.append(RiskFactor(
            name="kill_reason",
            raw_value=reason_score,
            weight=self.weights.kill_reason,
            weighted_score=reason_score * self.weights.kill_reason,
            description=f"Kill reason: {kill_report.kill_reason.value}",
        ))

        # Severity
        severity_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }
        severity_score = severity_scores.get(kill_report.severity, 0.5)
        factors.append(RiskFactor(
            name="severity",
            raw_value=severity_score,
            weight=self.weights.severity,
            weighted_score=severity_score * self.weights.severity,
            description=f"Severity: {kill_report.severity.value}",
        ))

        # Module criticality
        is_critical = kill_report.target_module in self.critical_modules
        criticality_score = 0.9 if is_critical else 0.3
        factors.append(RiskFactor(
            name="module_criticality",
            raw_value=criticality_score,
            weight=self.weights.module_criticality,
            weighted_score=criticality_score * self.weights.module_criticality,
            description=f"Critical module: {'Yes' if is_critical else 'No'}",
        ))

        # Calculate overall risk score
        total_weight = sum(f.weight for f in factors)
        if total_weight > 0:
            risk_score = sum(f.weighted_score for f in factors) / total_weight
        else:
            risk_score = 0.5

        risk_score = max(0.0, min(1.0, risk_score))
        risk_level = RiskLevel.from_score(risk_score)

        # Confidence based on data availability
        confidence = self._calculate_confidence(siem, module_history)

        auto_approve_eligible = (
            risk_score <= self.thresholds.auto_approve_max_score
            and confidence >= self.thresholds.auto_approve_min_confidence
        )
        requires_escalation = risk_score >= self.thresholds.escalation_min_score

        recommendations = self._generate_recommendations(risk_level, kill_report)

        assessment = RiskAssessment(
            assessment_id=str(uuid.uuid4()),
            kill_id=kill_report.kill_id,
            timestamp=datetime.now(timezone.utc),
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            factors=factors,
            recommendations=recommendations,
            auto_approve_eligible=auto_approve_eligible,
            requires_escalation=requires_escalation,
        )

        logger.info(
            "Risk assessment completed",
            kill_id=kill_report.kill_id,
            risk_level=risk_level.value,
            risk_score=round(risk_score, 3),
            auto_approve=auto_approve_eligible,
        )

        return assessment

    def _get_module_history(self, module: str) -> Dict[str, Any]:
        """Get historical data for a module from the outcome store."""
        if not self.outcome_store:
            return {}

        try:
            stats = self.outcome_store.get_module_statistics(module)
            return {
                "incident_count_30d": stats.get("total_resurrections", 0),
                "success_rate": stats.get("success_rate", 0.0),
                "false_positive_count": stats.get("failure_count", 0),
            }
        except Exception as e:
            logger.warning("Failed to get module history: %s", e)
            return {}

    def _calculate_confidence(
        self,
        siem: SIEMResult,
        module_history: Dict[str, Any],
    ) -> float:
        """Calculate confidence in the risk assessment."""
        confidence = 0.5  # Base confidence

        # SIEM data available
        if siem.recommendation != "unknown":
            confidence += 0.15

        # False positive history provides signal
        if siem.false_positive_history > 0:
            confidence += 0.1

        # Historical data from outcome store
        if module_history.get("incident_count_30d", 0) > 0:
            confidence += 0.15

        return min(1.0, max(0.0, confidence))

    def _generate_recommendations(
        self,
        risk_level: RiskLevel,
        kill_report: KillReport,
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        if risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW):
            recommendations.append("Low risk - safe to auto-approve")
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.append("Medium risk - manual review recommended")
        elif risk_level == RiskLevel.HIGH:
            recommendations.append("High risk - escalate to senior operator")
        else:
            recommendations.append("Critical risk - do not resurrect without investigation")

        if kill_report.kill_reason == KillReason.THREAT_DETECTED:
            recommendations.append("Verify threat has been contained")

        return recommendations

    def get_thresholds(self) -> RiskThresholds:
        """Get current thresholds."""
        return self.thresholds

    def update_thresholds(self, thresholds: RiskThresholds) -> None:
        """Update risk thresholds."""
        self.thresholds = thresholds
        logger.info("Risk thresholds updated")


def create_risk_assessor(
    config: Dict[str, Any],
    outcome_store: Optional[Any] = None,
) -> RiskAssessor:
    """Factory function to create a risk assessor."""
    risk_config = config.get("risk", {})

    weight_config = risk_config.get("weights", {})
    weights = RiskWeights(
        smith_confidence=weight_config.get("smith_confidence", 0.30),
        siem_risk_score=weight_config.get("siem_risk_score", 0.25),
        false_positive_history=weight_config.get("false_positive_history", 0.20),
        kill_reason=weight_config.get("kill_reason", 0.10),
        severity=weight_config.get("severity", 0.10),
        module_criticality=weight_config.get("module_criticality", 0.05),
    )

    threshold_config = risk_config.get("thresholds", {})
    thresholds = RiskThresholds(
        auto_approve_max_score=threshold_config.get("auto_approve_max_score", 0.3),
        auto_approve_min_confidence=threshold_config.get("auto_approve_min_confidence", 0.85),
        escalation_min_score=threshold_config.get("escalation_min_score", 0.7),
        deny_min_score=threshold_config.get("deny_min_score", 0.85),
    )

    critical_modules = config.get("critical_modules", [])

    return AdvancedRiskAssessor(
        weights=weights,
        thresholds=thresholds,
        critical_modules=critical_modules,
        outcome_store=outcome_store,
    )
