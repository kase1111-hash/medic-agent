"""
Medic Agent Risk Assessment Engine

Advanced risk scoring with configurable weights, adaptive thresholds,
and multi-factor analysis for resurrection decisions.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import math

from core.models import (
    KillReport,
    SIEMContextResponse,
    RiskLevel,
    KillReason,
    Severity,
)
from core.logger import get_logger

logger = get_logger("core.risk")


class RiskCategory(Enum):
    """Categories of risk factors."""
    THREAT = "threat"           # Active threat indicators
    BEHAVIORAL = "behavioral"   # Anomalous behavior patterns
    HISTORICAL = "historical"   # Past incident history
    CONTEXTUAL = "contextual"   # Time, dependencies, criticality
    CONFIDENCE = "confidence"   # Confidence in assessments


@dataclass
class RiskFactor:
    """Individual risk factor with metadata."""
    name: str
    category: RiskCategory
    raw_value: float
    weight: float
    weighted_score: float
    description: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "category": self.category.value,
            "raw_value": round(self.raw_value, 3),
            "weight": round(self.weight, 3),
            "weighted_score": round(self.weighted_score, 3),
            "description": self.description,
            "evidence": self.evidence,
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

    def get_factors_by_category(self, category: RiskCategory) -> List[RiskFactor]:
        """Get factors for a specific category."""
        return [f for f in self.factors if f.category == category]

    def get_top_factors(self, n: int = 3) -> List[RiskFactor]:
        """Get the top N contributing factors."""
        sorted_factors = sorted(
            self.factors,
            key=lambda f: f.weighted_score,
            reverse=True,
        )
        return sorted_factors[:n]


@dataclass
class RiskThresholds:
    """Configurable risk thresholds."""
    auto_approve_max_score: float = 0.3
    auto_approve_min_confidence: float = 0.85
    escalation_min_score: float = 0.7
    deny_min_score: float = 0.85

    # Level boundaries
    minimal_max: float = 0.2
    low_max: float = 0.4
    medium_max: float = 0.6
    high_max: float = 0.8


@dataclass
class RiskWeights:
    """Configurable weights for risk factors."""
    # Threat factors
    smith_confidence: float = 0.20
    siem_risk_score: float = 0.15
    threat_indicators: float = 0.15

    # Behavioral factors
    kill_reason: float = 0.10
    severity: float = 0.10

    # Historical factors
    false_positive_history: float = 0.10
    module_incident_history: float = 0.05

    # Contextual factors
    dependency_impact: float = 0.05
    module_criticality: float = 0.05
    time_of_day: float = 0.05


class RiskAssessor(ABC):
    """Abstract interface for risk assessment."""

    @abstractmethod
    def assess(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
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
    Advanced risk assessment with multi-factor analysis.

    Evaluates multiple risk categories and produces a weighted
    risk score with confidence estimation.
    """

    def __init__(
        self,
        weights: Optional[RiskWeights] = None,
        thresholds: Optional[RiskThresholds] = None,
        critical_modules: Optional[List[str]] = None,
        history_provider: Optional[Any] = None,
    ):
        self.weights = weights or RiskWeights()
        self.thresholds = thresholds or RiskThresholds()
        self.critical_modules = set(critical_modules or [])
        self.history_provider = history_provider

        # Cache for module history
        self._history_cache: Dict[str, Dict[str, Any]] = {}

    def assess(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> RiskAssessment:
        """Perform comprehensive risk assessment."""
        import uuid

        factors: List[RiskFactor] = []

        # Assess threat factors
        factors.extend(self._assess_threat_factors(kill_report, siem_context))

        # Assess behavioral factors
        factors.extend(self._assess_behavioral_factors(kill_report, siem_context))

        # Assess historical factors
        factors.extend(self._assess_historical_factors(kill_report, siem_context))

        # Assess contextual factors
        factors.extend(self._assess_contextual_factors(kill_report, siem_context))

        # Calculate overall risk score
        total_weight = sum(f.weight for f in factors)
        if total_weight > 0:
            risk_score = sum(f.weighted_score for f in factors) / total_weight
        else:
            risk_score = 0.5  # Default to medium risk

        # Normalize to 0-1 range
        risk_score = max(0.0, min(1.0, risk_score))

        # Determine risk level
        risk_level = self._score_to_level(risk_score)

        # Calculate confidence
        confidence = self._calculate_confidence(factors, siem_context)

        # Determine eligibility
        auto_approve_eligible = (
            risk_score <= self.thresholds.auto_approve_max_score
            and confidence >= self.thresholds.auto_approve_min_confidence
        )

        requires_escalation = risk_score >= self.thresholds.escalation_min_score

        # Generate recommendations
        recommendations = self._generate_recommendations(
            risk_level, risk_score, factors, kill_report
        )

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

    def _assess_threat_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> List[RiskFactor]:
        """Assess threat-related risk factors."""
        factors = []

        # Smith confidence
        smith_score = kill_report.confidence_score
        factors.append(RiskFactor(
            name="smith_confidence",
            category=RiskCategory.THREAT,
            raw_value=smith_score,
            weight=self.weights.smith_confidence,
            weighted_score=smith_score * self.weights.smith_confidence,
            description=f"Smith kill confidence: {smith_score:.0%}",
            evidence=[f"confidence_score={smith_score}"],
        ))

        # SIEM risk score
        siem_score = siem_context.risk_score
        factors.append(RiskFactor(
            name="siem_risk_score",
            category=RiskCategory.THREAT,
            raw_value=siem_score,
            weight=self.weights.siem_risk_score,
            weighted_score=siem_score * self.weights.siem_risk_score,
            description=f"SIEM risk score: {siem_score:.0%}",
            evidence=[siem_context.recommendation],
        ))

        # Threat indicators
        if siem_context.threat_indicators:
            max_threat = max(ti.threat_score for ti in siem_context.threat_indicators)
            avg_threat = sum(ti.threat_score for ti in siem_context.threat_indicators) / len(siem_context.threat_indicators)
            indicator_score = (max_threat + avg_threat) / 2
        else:
            indicator_score = 0.0

        factors.append(RiskFactor(
            name="threat_indicators",
            category=RiskCategory.THREAT,
            raw_value=indicator_score,
            weight=self.weights.threat_indicators,
            weighted_score=indicator_score * self.weights.threat_indicators,
            description=f"{len(siem_context.threat_indicators)} threat indicators",
            evidence=[ti.indicator_type for ti in siem_context.threat_indicators],
        ))

        return factors

    def _assess_behavioral_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> List[RiskFactor]:
        """Assess behavioral risk factors."""
        factors = []

        # Kill reason scoring
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
            category=RiskCategory.BEHAVIORAL,
            raw_value=reason_score,
            weight=self.weights.kill_reason,
            weighted_score=reason_score * self.weights.kill_reason,
            description=f"Kill reason: {kill_report.kill_reason.value}",
            evidence=kill_report.evidence[:3],
        ))

        # Severity scoring
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
            category=RiskCategory.BEHAVIORAL,
            raw_value=severity_score,
            weight=self.weights.severity,
            weighted_score=severity_score * self.weights.severity,
            description=f"Severity: {kill_report.severity.value}",
            evidence=[],
        ))

        return factors

    def _assess_historical_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> List[RiskFactor]:
        """Assess historical risk factors."""
        factors = []

        # False positive history (inverted - more FPs = lower risk)
        fp_count = siem_context.false_positive_history
        if fp_count == 0:
            fp_score = 0.8  # No history = higher risk
        elif fp_count <= 2:
            fp_score = 0.5
        elif fp_count <= 5:
            fp_score = 0.3
        else:
            fp_score = 0.1  # Many FPs = lower risk

        factors.append(RiskFactor(
            name="false_positive_history",
            category=RiskCategory.HISTORICAL,
            raw_value=fp_score,
            weight=self.weights.false_positive_history,
            weighted_score=fp_score * self.weights.false_positive_history,
            description=f"False positive history: {fp_count} prior FPs",
            evidence=[f"fp_count={fp_count}"],
        ))

        # Module incident history
        module_history = self._get_module_history(kill_report.target_module)
        incident_count = module_history.get("incident_count_30d", 0)
        if incident_count == 0:
            history_score = 0.2
        elif incident_count <= 3:
            history_score = 0.4
        elif incident_count <= 7:
            history_score = 0.6
        else:
            history_score = 0.8

        factors.append(RiskFactor(
            name="module_incident_history",
            category=RiskCategory.HISTORICAL,
            raw_value=history_score,
            weight=self.weights.module_incident_history,
            weighted_score=history_score * self.weights.module_incident_history,
            description=f"Module incidents (30d): {incident_count}",
            evidence=[],
        ))

        return factors

    def _assess_contextual_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> List[RiskFactor]:
        """Assess contextual risk factors."""
        factors = []

        # Dependency impact
        dep_count = len(kill_report.dependencies)
        if dep_count == 0:
            dep_score = 0.1
        elif dep_count <= 2:
            dep_score = 0.3
        elif dep_count <= 5:
            dep_score = 0.6
        else:
            dep_score = 0.9

        factors.append(RiskFactor(
            name="dependency_impact",
            category=RiskCategory.CONTEXTUAL,
            raw_value=dep_score,
            weight=self.weights.dependency_impact,
            weighted_score=dep_score * self.weights.dependency_impact,
            description=f"Downstream dependencies: {dep_count}",
            evidence=kill_report.dependencies[:5],
        ))

        # Module criticality
        is_critical = kill_report.target_module in self.critical_modules
        criticality_score = 0.9 if is_critical else 0.3

        factors.append(RiskFactor(
            name="module_criticality",
            category=RiskCategory.CONTEXTUAL,
            raw_value=criticality_score,
            weight=self.weights.module_criticality,
            weighted_score=criticality_score * self.weights.module_criticality,
            description=f"Critical module: {'Yes' if is_critical else 'No'}",
            evidence=[],
        ))

        # Time of day (higher risk during business hours)
        hour = datetime.now(timezone.utc).hour
        if 9 <= hour <= 17:  # Business hours
            time_score = 0.6
        elif 6 <= hour <= 9 or 17 <= hour <= 21:  # Transition hours
            time_score = 0.4
        else:  # Off hours
            time_score = 0.2

        factors.append(RiskFactor(
            name="time_of_day",
            category=RiskCategory.CONTEXTUAL,
            raw_value=time_score,
            weight=self.weights.time_of_day,
            weighted_score=time_score * self.weights.time_of_day,
            description=f"Time factor (UTC hour {hour})",
            evidence=[],
        ))

        return factors

    def _get_module_history(self, module: str) -> Dict[str, Any]:
        """Get historical data for a module."""
        if module in self._history_cache:
            return self._history_cache[module]

        if self.history_provider:
            try:
                history = self.history_provider.get_module_history(module)
                self._history_cache[module] = history
                return history
            except Exception as e:
                logger.warning(f"Failed to get module history: {e}")

        return {"incident_count_30d": 0}

    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score < self.thresholds.minimal_max:
            return RiskLevel.MINIMAL
        elif score < self.thresholds.low_max:
            return RiskLevel.LOW
        elif score < self.thresholds.medium_max:
            return RiskLevel.MEDIUM
        elif score < self.thresholds.high_max:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _calculate_confidence(
        self,
        factors: List[RiskFactor],
        siem_context: SIEMContextResponse,
    ) -> float:
        """Calculate confidence in the risk assessment."""
        confidence = 0.5  # Base confidence

        # More data = more confidence
        if siem_context.historical_behavior:
            confidence += 0.15
        if siem_context.threat_indicators:
            confidence += 0.1
        if siem_context.false_positive_history > 0:
            confidence += 0.1

        # Consistent signals = more confidence
        threat_factors = [f for f in factors if f.category == RiskCategory.THREAT]
        if threat_factors:
            scores = [f.raw_value for f in threat_factors]
            variance = sum((s - sum(scores)/len(scores))**2 for s in scores) / len(scores)
            if variance < 0.1:  # Low variance = consistent signals
                confidence += 0.15

        return min(1.0, max(0.0, confidence))

    def _generate_recommendations(
        self,
        risk_level: RiskLevel,
        risk_score: float,
        factors: List[RiskFactor],
        kill_report: KillReport,
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        if risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW):
            recommendations.append("Low risk - safe to auto-approve")
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.append("Medium risk - manual review recommended")
            top_factors = sorted(factors, key=lambda f: f.weighted_score, reverse=True)[:2]
            for f in top_factors:
                recommendations.append(f"Review: {f.description}")
        elif risk_level == RiskLevel.HIGH:
            recommendations.append("High risk - escalate to senior operator")
            recommendations.append("Investigate before resurrection")
        else:
            recommendations.append("Critical risk - do not resurrect without investigation")
            recommendations.append("Consider incident response procedures")

        # Kill reason specific recommendations
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
    history_provider: Optional[Any] = None,
) -> RiskAssessor:
    """Factory function to create a risk assessor."""
    risk_config = config.get("risk", {})

    # Load weights
    weight_config = risk_config.get("weights", {})
    weights = RiskWeights(
        smith_confidence=weight_config.get("smith_confidence", 0.20),
        siem_risk_score=weight_config.get("siem_risk_score", 0.15),
        threat_indicators=weight_config.get("threat_indicators", 0.15),
        kill_reason=weight_config.get("kill_reason", 0.10),
        severity=weight_config.get("severity", 0.10),
        false_positive_history=weight_config.get("false_positive_history", 0.10),
        module_incident_history=weight_config.get("module_incident_history", 0.05),
        dependency_impact=weight_config.get("dependency_impact", 0.05),
        module_criticality=weight_config.get("module_criticality", 0.05),
        time_of_day=weight_config.get("time_of_day", 0.05),
    )

    # Load thresholds
    threshold_config = risk_config.get("thresholds", {})
    thresholds = RiskThresholds(
        auto_approve_max_score=threshold_config.get("auto_approve_max_score", 0.3),
        auto_approve_min_confidence=threshold_config.get("auto_approve_min_confidence", 0.85),
        escalation_min_score=threshold_config.get("escalation_min_score", 0.7),
        deny_min_score=threshold_config.get("deny_min_score", 0.85),
    )

    # Get critical modules
    critical_modules = config.get("constitution", {}).get(
        "constraints", {}
    ).get("always_require_approval", [])

    return AdvancedRiskAssessor(
        weights=weights,
        thresholds=thresholds,
        critical_modules=critical_modules,
        history_provider=history_provider,
    )
