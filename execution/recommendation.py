"""
Medic Agent Recommendation Engine

Generates structured resurrection proposals with detailed context
for human review and approval workflows.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from core.models import (
    KillReport,
    SIEMContextResponse,
    ResurrectionDecision,
    DecisionOutcome,
    RiskLevel,
    ResurrectionRequest,
    ResurrectionStatus,
)
from core.logger import get_logger

logger = get_logger("execution.recommendation")


class RecommendationType(Enum):
    """Type of resurrection recommendation."""
    APPROVE = "approve"              # Recommend approval
    DENY = "deny"                    # Recommend denial
    REVIEW_CAREFULLY = "review"      # Needs careful review
    ESCALATE = "escalate"            # Escalate to senior operator


class UrgencyLevel(Enum):
    """Urgency of the recommendation."""
    CRITICAL = "critical"    # Immediate action required
    HIGH = "high"            # Action within 15 minutes
    MEDIUM = "medium"        # Action within 1 hour
    LOW = "low"              # Action within 24 hours


@dataclass
class ResurrectionProposal:
    """
    Structured proposal for resurrection review.

    Contains all information needed for a human operator
    to make an informed approval decision.
    """
    proposal_id: str
    created_at: datetime

    # References
    kill_report: KillReport
    siem_context: SIEMContextResponse
    decision: ResurrectionDecision

    # Recommendation
    recommendation: RecommendationType
    urgency: UrgencyLevel

    # Summary for quick review
    summary: str
    key_factors: List[str]

    # Risk breakdown
    risk_factors: Dict[str, float]
    mitigating_factors: List[str]
    aggravating_factors: List[str]

    # Historical context
    module_history: Dict[str, Any]
    similar_incidents: List[Dict[str, Any]]

    # Suggested actions
    suggested_pre_checks: List[str]
    suggested_post_checks: List[str]
    rollback_strategy: str

    # Expiration
    expires_at: datetime

    # State
    status: str = "pending"  # pending, approved, denied, expired
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "proposal_id": self.proposal_id,
            "created_at": self.created_at.isoformat(),
            "kill_id": self.kill_report.kill_id,
            "decision_id": self.decision.decision_id,
            "target_module": self.kill_report.target_module,
            "target_instance_id": self.kill_report.target_instance_id,
            "recommendation": self.recommendation.value,
            "urgency": self.urgency.value,
            "summary": self.summary,
            "key_factors": self.key_factors,
            "risk_factors": self.risk_factors,
            "risk_level": self.decision.risk_level.value,
            "risk_score": self.decision.risk_score,
            "confidence": self.decision.confidence,
            "mitigating_factors": self.mitigating_factors,
            "aggravating_factors": self.aggravating_factors,
            "module_history": self.module_history,
            "similar_incidents": self.similar_incidents,
            "suggested_pre_checks": self.suggested_pre_checks,
            "suggested_post_checks": self.suggested_post_checks,
            "rollback_strategy": self.rollback_strategy,
            "expires_at": self.expires_at.isoformat(),
            "status": self.status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_notes": self.review_notes,
        }

    def get_display_summary(self) -> str:
        """Generate human-readable summary for display."""
        lines = [
            f"{'='*60}",
            f"RESURRECTION PROPOSAL: {self.proposal_id[:8]}",
            f"{'='*60}",
            f"",
            f"Target: {self.kill_report.target_module} ({self.kill_report.target_instance_id})",
            f"Kill Reason: {self.kill_report.kill_reason.value}",
            f"Severity: {self.kill_report.severity.value}",
            f"",
            f"RECOMMENDATION: {self.recommendation.value.upper()}",
            f"Urgency: {self.urgency.value}",
            f"Risk: {self.decision.risk_level.value} ({self.decision.risk_score:.0%})",
            f"Confidence: {self.decision.confidence:.0%}",
            f"",
            f"Summary: {self.summary}",
            f"",
            "Key Factors:",
        ]

        for factor in self.key_factors:
            lines.append(f"  - {factor}")

        if self.mitigating_factors:
            lines.append("")
            lines.append("Mitigating Factors:")
            for factor in self.mitigating_factors:
                lines.append(f"  + {factor}")

        if self.aggravating_factors:
            lines.append("")
            lines.append("Aggravating Factors:")
            for factor in self.aggravating_factors:
                lines.append(f"  ! {factor}")

        lines.extend([
            "",
            f"Expires: {self.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"{'='*60}",
        ])

        return "\n".join(lines)


class RecommendationEngine:
    """
    Generates resurrection proposals from decisions.

    Enriches decisions with additional context, historical data,
    and actionable recommendations for human reviewers.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        decision_logger: Optional[Any] = None,
    ):
        self.config = config or {}
        self.decision_logger = decision_logger

        # Default timeout in hours
        self.default_timeout_hours = self.config.get(
            "default_timeout_hours", 24
        )

        # Urgency thresholds
        self.urgency_thresholds = self.config.get("urgency_thresholds", {
            "critical_min_severity": "critical",
            "high_min_severity": "high",
            "medium_max_risk": 0.6,
        })

    def generate_proposal(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
        decision: ResurrectionDecision,
    ) -> ResurrectionProposal:
        """
        Generate a resurrection proposal from a decision.

        Args:
            kill_report: The original kill report
            siem_context: SIEM context data
            decision: The resurrection decision

        Returns:
            ResurrectionProposal with full context
        """
        logger.info(
            "Generating resurrection proposal",
            kill_id=kill_report.kill_id,
            decision_id=decision.decision_id,
        )

        # Determine recommendation type
        recommendation = self._determine_recommendation(decision, siem_context)

        # Determine urgency
        urgency = self._determine_urgency(kill_report, decision)

        # Generate summary
        summary = self._generate_summary(kill_report, decision, recommendation)

        # Extract key factors
        key_factors = self._extract_key_factors(
            kill_report, siem_context, decision
        )

        # Calculate risk factors
        risk_factors = self._calculate_risk_factors(
            kill_report, siem_context, decision
        )

        # Identify mitigating and aggravating factors
        mitigating = self._identify_mitigating_factors(
            kill_report, siem_context, decision
        )
        aggravating = self._identify_aggravating_factors(
            kill_report, siem_context, decision
        )

        # Get module history
        module_history = self._get_module_history(kill_report.target_module)

        # Find similar incidents
        similar_incidents = self._find_similar_incidents(kill_report, decision)

        # Generate suggested checks
        pre_checks = self._suggest_pre_checks(kill_report, decision)
        post_checks = self._suggest_post_checks(kill_report, decision)

        # Define rollback strategy
        rollback_strategy = self._define_rollback_strategy(
            kill_report, decision
        )

        # Calculate expiration
        from datetime import timedelta
        timeout_hours = self._calculate_timeout(urgency)
        expires_at = datetime.utcnow() + timedelta(hours=timeout_hours)

        proposal = ResurrectionProposal(
            proposal_id=str(uuid.uuid4()),
            created_at=datetime.utcnow(),
            kill_report=kill_report,
            siem_context=siem_context,
            decision=decision,
            recommendation=recommendation,
            urgency=urgency,
            summary=summary,
            key_factors=key_factors,
            risk_factors=risk_factors,
            mitigating_factors=mitigating,
            aggravating_factors=aggravating,
            module_history=module_history,
            similar_incidents=similar_incidents,
            suggested_pre_checks=pre_checks,
            suggested_post_checks=post_checks,
            rollback_strategy=rollback_strategy,
            expires_at=expires_at,
        )

        logger.info(
            "Proposal generated",
            proposal_id=proposal.proposal_id,
            recommendation=recommendation.value,
            urgency=urgency.value,
        )

        return proposal

    def _determine_recommendation(
        self,
        decision: ResurrectionDecision,
        siem_context: SIEMContextResponse,
    ) -> RecommendationType:
        """Determine the recommendation type based on decision and context."""
        if decision.outcome == DecisionOutcome.DENY:
            return RecommendationType.DENY

        if decision.outcome in (DecisionOutcome.APPROVE_AUTO, DecisionOutcome.APPROVE_MANUAL):
            return RecommendationType.APPROVE

        # For pending review, assess based on risk
        if decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return RecommendationType.ESCALATE

        if decision.risk_level == RiskLevel.MEDIUM:
            return RecommendationType.REVIEW_CAREFULLY

        return RecommendationType.APPROVE

    def _determine_urgency(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
    ) -> UrgencyLevel:
        """Determine urgency level for the proposal."""
        from core.models import Severity

        # Critical severity = critical urgency
        if kill_report.severity == Severity.CRITICAL:
            return UrgencyLevel.CRITICAL

        # High severity or many dependencies = high urgency
        if kill_report.severity == Severity.HIGH or len(kill_report.dependencies) > 3:
            return UrgencyLevel.HIGH

        # Medium risk = medium urgency
        if decision.risk_level == RiskLevel.MEDIUM:
            return UrgencyLevel.MEDIUM

        return UrgencyLevel.LOW

    def _generate_summary(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
        recommendation: RecommendationType,
    ) -> str:
        """Generate a concise summary of the proposal."""
        action = {
            RecommendationType.APPROVE: "Resurrection recommended",
            RecommendationType.DENY: "Resurrection NOT recommended",
            RecommendationType.REVIEW_CAREFULLY: "Careful review required",
            RecommendationType.ESCALATE: "Escalation required",
        }[recommendation]

        return (
            f"{action} for {kill_report.target_module}. "
            f"Killed due to {kill_report.kill_reason.value} "
            f"with {kill_report.confidence_score:.0%} confidence. "
            f"Risk assessment: {decision.risk_level.value} ({decision.risk_score:.0%})."
        )

    def _extract_key_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
        decision: ResurrectionDecision,
    ) -> List[str]:
        """Extract the most important factors for the decision."""
        factors = []

        # Kill reason
        factors.append(
            f"Kill reason: {kill_report.kill_reason.value} "
            f"(severity: {kill_report.severity.value})"
        )

        # Smith confidence
        factors.append(
            f"Smith confidence: {kill_report.confidence_score:.0%}"
        )

        # SIEM risk
        factors.append(
            f"SIEM risk score: {siem_context.risk_score:.0%}"
        )

        # False positive history
        if siem_context.false_positive_history > 0:
            factors.append(
                f"Prior false positives: {siem_context.false_positive_history}"
            )

        # Threat indicators
        if siem_context.threat_indicators:
            max_score = max(ti.threat_score for ti in siem_context.threat_indicators)
            factors.append(
                f"Threat indicators: {len(siem_context.threat_indicators)} "
                f"(max score: {max_score:.0%})"
            )

        # Dependencies
        if kill_report.dependencies:
            factors.append(
                f"Affected dependencies: {len(kill_report.dependencies)}"
            )

        return factors

    def _calculate_risk_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
        decision: ResurrectionDecision,
    ) -> Dict[str, float]:
        """Calculate detailed risk factor breakdown."""
        return {
            "smith_confidence": kill_report.confidence_score,
            "siem_risk": siem_context.risk_score,
            "severity_weight": self._severity_to_score(kill_report.severity),
            "dependency_risk": min(1.0, len(kill_report.dependencies) * 0.1),
            "overall_risk": decision.risk_score,
        }

    def _severity_to_score(self, severity) -> float:
        """Convert severity to numeric score."""
        from core.models import Severity
        scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }
        return scores.get(severity, 0.5)

    def _identify_mitigating_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
        decision: ResurrectionDecision,
    ) -> List[str]:
        """Identify factors that reduce risk."""
        factors = []

        # High false positive history
        if siem_context.false_positive_history >= 3:
            factors.append(
                f"Module has {siem_context.false_positive_history} prior false positives"
            )

        # Low Smith confidence
        if kill_report.confidence_score < 0.6:
            factors.append(
                f"Low Smith confidence ({kill_report.confidence_score:.0%})"
            )

        # No threat indicators
        if not siem_context.threat_indicators:
            factors.append("No active threat indicators from SIEM")

        # Low SIEM risk
        if siem_context.risk_score < 0.3:
            factors.append(f"Low SIEM risk score ({siem_context.risk_score:.0%})")

        # Resource exhaustion (usually recoverable)
        from core.models import KillReason
        if kill_report.kill_reason == KillReason.RESOURCE_EXHAUSTION:
            factors.append("Kill due to resource exhaustion (typically recoverable)")

        # SIEM recommendation
        if "false_positive" in siem_context.recommendation.lower():
            factors.append(f"SIEM suggests false positive: {siem_context.recommendation}")

        return factors

    def _identify_aggravating_factors(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
        decision: ResurrectionDecision,
    ) -> List[str]:
        """Identify factors that increase risk."""
        factors = []

        # High threat indicators
        high_threats = [
            ti for ti in siem_context.threat_indicators
            if ti.threat_score > 0.7
        ]
        if high_threats:
            factors.append(
                f"{len(high_threats)} high-severity threat indicator(s)"
            )

        # Confirmed threat
        from core.models import KillReason
        if kill_report.kill_reason == KillReason.THREAT_DETECTED:
            factors.append("Kill was for detected threat")

        # High Smith confidence
        if kill_report.confidence_score > 0.9:
            factors.append(
                f"Very high Smith confidence ({kill_report.confidence_score:.0%})"
            )

        # Many dependencies
        if len(kill_report.dependencies) > 5:
            factors.append(
                f"High dependency count ({len(kill_report.dependencies)})"
            )

        # No false positive history
        if siem_context.false_positive_history == 0:
            factors.append("No prior false positive history")

        # High SIEM risk
        if siem_context.risk_score > 0.7:
            factors.append(f"High SIEM risk score ({siem_context.risk_score:.0%})")

        return factors

    def _get_module_history(self, module: str) -> Dict[str, Any]:
        """Get historical data for the module."""
        history = {
            "module": module,
            "total_kills_30d": 0,
            "total_resurrections_30d": 0,
            "success_rate": 0.0,
            "avg_time_to_stable": None,
            "last_incident": None,
        }

        # Query decision logger if available
        if self.decision_logger:
            try:
                records = self.decision_logger.get_module_history(module, days=30)
                if records:
                    history["total_kills_30d"] = len(records)

                    approved = [
                        r for r in records
                        if r.decision.outcome in (
                            DecisionOutcome.APPROVE_AUTO,
                            DecisionOutcome.APPROVE_MANUAL,
                        )
                    ]
                    history["total_resurrections_30d"] = len(approved)

                    if records:
                        history["last_incident"] = records[0].recorded_at.isoformat()
            except Exception as e:
                logger.warning(f"Failed to get module history: {e}")

        return history

    def _find_similar_incidents(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
    ) -> List[Dict[str, Any]]:
        """Find similar historical incidents."""
        similar = []

        if self.decision_logger:
            try:
                # Get recent decisions with same kill reason
                from datetime import timedelta
                records = self.decision_logger.get_decisions(
                    date=datetime.utcnow(),
                    limit=100,
                )

                for record in records:
                    if (
                        record.kill_report.kill_reason == kill_report.kill_reason
                        and record.kill_report.kill_id != kill_report.kill_id
                    ):
                        similar.append({
                            "kill_id": record.kill_report.kill_id,
                            "module": record.kill_report.target_module,
                            "outcome": record.decision.outcome.value,
                            "date": record.recorded_at.isoformat(),
                        })

                        if len(similar) >= 5:
                            break

            except Exception as e:
                logger.warning(f"Failed to find similar incidents: {e}")

        return similar

    def _suggest_pre_checks(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
    ) -> List[str]:
        """Suggest pre-resurrection verification steps."""
        checks = []

        # Always check dependencies
        if kill_report.dependencies:
            checks.append(
                f"Verify dependency status: {', '.join(kill_report.dependencies[:3])}"
            )

        # Check based on kill reason
        from core.models import KillReason
        if kill_report.kill_reason == KillReason.THREAT_DETECTED:
            checks.append("Verify threat has been contained/remediated")
            checks.append("Check for related indicators of compromise")

        if kill_report.kill_reason == KillReason.RESOURCE_EXHAUSTION:
            checks.append("Verify resource limits are appropriate")
            checks.append("Check for memory leaks or resource-intensive operations")

        if kill_report.kill_reason == KillReason.ANOMALY_BEHAVIOR:
            checks.append("Review recent code deployments")
            checks.append("Check for configuration changes")

        # General checks
        checks.append("Verify module configuration is correct")
        checks.append("Check for any pending patches or updates")

        return checks

    def _suggest_post_checks(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
    ) -> List[str]:
        """Suggest post-resurrection monitoring steps."""
        checks = [
            "Monitor CPU and memory usage for first 5 minutes",
            "Verify health endpoints respond correctly",
            "Check log output for errors or warnings",
        ]

        # Add dependency checks
        if kill_report.dependencies:
            checks.append("Verify downstream dependencies are functioning")

        # Risk-based monitoring
        if decision.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH):
            checks.append("Enable enhanced monitoring for 1 hour")
            checks.append("Prepare rollback procedure")

        return checks

    def _define_rollback_strategy(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
    ) -> str:
        """Define the rollback strategy if resurrection fails."""
        if decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return (
                "IMMEDIATE: Kill module at first sign of anomaly. "
                "No grace period. Notify Smith of manual termination."
            )

        if decision.risk_level == RiskLevel.MEDIUM:
            return (
                "STANDARD: Monitor for 5 minutes. Kill if health checks fail "
                "or anomalous behavior detected. Log detailed metrics."
            )

        return (
            "RELAXED: Monitor for 15 minutes. Allow minor issues. "
            "Only rollback on sustained failures or security concerns."
        )

    def _calculate_timeout(self, urgency: UrgencyLevel) -> int:
        """Calculate timeout hours based on urgency."""
        timeouts = {
            UrgencyLevel.CRITICAL: 1,
            UrgencyLevel.HIGH: 4,
            UrgencyLevel.MEDIUM: 12,
            UrgencyLevel.LOW: 24,
        }
        return timeouts.get(urgency, self.default_timeout_hours)


def create_recommendation_engine(
    config: Dict[str, Any],
    decision_logger: Optional[Any] = None,
) -> RecommendationEngine:
    """Factory function to create a recommendation engine."""
    return RecommendationEngine(
        config=config.get("recommendation", {}),
        decision_logger=decision_logger,
    )
