"""
Medic Agent Adaptive Threshold System

Dynamically adjusts risk thresholds based on historical outcomes
to improve decision accuracy over time.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import json
import statistics

from learning.outcome_store import OutcomeStore, OutcomeType, ResurrectionOutcome
from core.risk import RiskThresholds, RiskWeights
from core.logger import get_logger

logger = get_logger("learning.threshold_adapter")


class AdjustmentType(Enum):
    """Type of threshold adjustment."""
    INCREASE = "increase"
    DECREASE = "decrease"
    NO_CHANGE = "no_change"


@dataclass
class ThresholdAdjustment:
    """Record of a threshold adjustment."""
    adjustment_id: str
    timestamp: datetime
    threshold_name: str
    old_value: float
    new_value: float
    adjustment_type: AdjustmentType
    reason: str
    confidence: float
    supporting_data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "adjustment_id": self.adjustment_id,
            "timestamp": self.timestamp.isoformat(),
            "threshold_name": self.threshold_name,
            "old_value": round(self.old_value, 4),
            "new_value": round(self.new_value, 4),
            "adjustment_type": self.adjustment_type.value,
            "reason": self.reason,
            "confidence": round(self.confidence, 3),
            "supporting_data": self.supporting_data,
        }


@dataclass
class AdaptiveConfig:
    """Configuration for adaptive threshold system."""
    enabled: bool = True
    min_samples_required: int = 50
    analysis_window_days: int = 30
    max_adjustment_percent: float = 10.0  # Max 10% change per adjustment
    adjustment_cooldown_hours: int = 24
    target_auto_approve_accuracy: float = 0.95
    target_success_rate: float = 0.90
    require_approval: bool = True  # Require human approval for changes


@dataclass
class CurrentThresholds:
    """Current threshold values with metadata."""
    risk_thresholds: RiskThresholds
    risk_weights: RiskWeights
    last_updated: datetime
    version: int = 1
    adjustment_history: List[ThresholdAdjustment] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "risk_thresholds": {
                "auto_approve_max_score": self.risk_thresholds.auto_approve_max_score,
                "auto_approve_min_confidence": self.risk_thresholds.auto_approve_min_confidence,
                "escalation_min_score": self.risk_thresholds.escalation_min_score,
                "deny_min_score": self.risk_thresholds.deny_min_score,
            },
            "last_updated": self.last_updated.isoformat(),
            "version": self.version,
            "adjustment_count": len(self.adjustment_history),
        }


@dataclass
class AdjustmentProposal:
    """Proposed threshold adjustment awaiting approval."""
    proposal_id: str
    created_at: datetime
    adjustments: List[ThresholdAdjustment]
    overall_confidence: float
    expected_impact: Dict[str, Any]
    status: str = "pending"  # pending, approved, rejected
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "proposal_id": self.proposal_id,
            "created_at": self.created_at.isoformat(),
            "adjustments": [a.to_dict() for a in self.adjustments],
            "overall_confidence": round(self.overall_confidence, 3),
            "expected_impact": self.expected_impact,
            "status": self.status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
        }


class ThresholdAdapter:
    """
    Adaptive threshold adjustment system.

    Analyzes outcome data and proposes threshold adjustments to
    improve decision accuracy while maintaining safety constraints.
    """

    def __init__(
        self,
        outcome_store: OutcomeStore,
        config: Optional[AdaptiveConfig] = None,
        initial_thresholds: Optional[RiskThresholds] = None,
        initial_weights: Optional[RiskWeights] = None,
    ):
        self.outcome_store = outcome_store
        self.config = config or AdaptiveConfig()

        self.current = CurrentThresholds(
            risk_thresholds=initial_thresholds or RiskThresholds(),
            risk_weights=initial_weights or RiskWeights(),
            last_updated=datetime.now(timezone.utc),
        )

        self._pending_proposals: Dict[str, AdjustmentProposal] = {}
        self._last_analysis: Optional[datetime] = None

        logger.info("ThresholdAdapter initialized", enabled=self.config.enabled)

    def analyze_and_propose(self) -> Optional[AdjustmentProposal]:
        """
        Analyze outcomes and propose threshold adjustments.

        Returns:
            AdjustmentProposal if changes are recommended, None otherwise
        """
        if not self.config.enabled:
            logger.debug("Adaptive thresholds disabled")
            return None

        # Check cooldown
        if self._last_analysis:
            elapsed = (datetime.now(timezone.utc) - self._last_analysis).total_seconds() / 3600
            if elapsed < self.config.adjustment_cooldown_hours:
                logger.debug(f"Cooldown active: {elapsed:.1f}h since last analysis")
                return None

        self._last_analysis = datetime.now(timezone.utc)

        # Get outcomes for analysis
        since = datetime.now(timezone.utc) - timedelta(days=self.config.analysis_window_days)
        outcomes = self.outcome_store.get_recent_outcomes(limit=1000, since=since)

        if len(outcomes) < self.config.min_samples_required:
            logger.info(f"Insufficient samples: {len(outcomes)} < {self.config.min_samples_required}")
            return None

        adjustments = []

        # Analyze auto-approve threshold
        auto_approve_adj = self._analyze_auto_approve_threshold(outcomes)
        if auto_approve_adj:
            adjustments.append(auto_approve_adj)

        # Analyze confidence threshold
        confidence_adj = self._analyze_confidence_threshold(outcomes)
        if confidence_adj:
            adjustments.append(confidence_adj)

        # Analyze risk weights
        weight_adjs = self._analyze_risk_weights(outcomes)
        adjustments.extend(weight_adjs)

        if not adjustments:
            logger.info("No threshold adjustments recommended")
            return None

        import uuid
        proposal = AdjustmentProposal(
            proposal_id=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            adjustments=adjustments,
            overall_confidence=statistics.mean(a.confidence for a in adjustments),
            expected_impact=self._estimate_impact(adjustments, outcomes),
        )

        self._pending_proposals[proposal.proposal_id] = proposal

        logger.info(
            "Threshold adjustment proposal created",
            proposal_id=proposal.proposal_id,
            adjustment_count=len(adjustments),
        )

        return proposal

    def _analyze_auto_approve_threshold(
        self,
        outcomes: List[ResurrectionOutcome],
    ) -> Optional[ThresholdAdjustment]:
        """Analyze and propose auto-approve threshold changes."""
        import uuid

        auto_approved = [o for o in outcomes if o.was_auto_approved]

        if len(auto_approved) < 10:
            return None

        # Calculate current accuracy
        auto_success = [o for o in auto_approved if o.outcome_type == OutcomeType.SUCCESS]
        accuracy = len(auto_success) / len(auto_approved)

        current_threshold = self.current.risk_thresholds.auto_approve_max_score
        target_accuracy = self.config.target_auto_approve_accuracy

        # If accuracy is too low, tighten threshold
        if accuracy < target_accuracy:
            # Find risk scores of failures
            auto_failures = [o for o in auto_approved if o.outcome_type != OutcomeType.SUCCESS]
            if not auto_failures:
                return None

            avg_failure_risk = statistics.mean(o.original_risk_score for o in auto_failures)

            # New threshold should be below average failure risk
            new_threshold = min(
                current_threshold,
                avg_failure_risk * 0.8,
            )

            # Apply max adjustment limit
            max_change = current_threshold * (self.config.max_adjustment_percent / 100)
            new_threshold = max(new_threshold, current_threshold - max_change)

            if abs(new_threshold - current_threshold) < 0.01:
                return None

            return ThresholdAdjustment(
                adjustment_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                threshold_name="auto_approve_max_score",
                old_value=current_threshold,
                new_value=new_threshold,
                adjustment_type=AdjustmentType.DECREASE,
                reason=f"Auto-approve accuracy {accuracy:.1%} below target {target_accuracy:.1%}",
                confidence=min(0.9, 0.5 + len(auto_approved) / 200),
                supporting_data={
                    "current_accuracy": accuracy,
                    "target_accuracy": target_accuracy,
                    "auto_approved_count": len(auto_approved),
                    "avg_failure_risk": avg_failure_risk,
                },
            )

        # If accuracy is much higher than target, could loosen threshold
        elif accuracy > target_accuracy + 0.05 and accuracy > 0.98:
            # Find max risk score among successes
            success_risks = [o.original_risk_score for o in auto_success]
            max_success_risk = max(success_risks)

            new_threshold = min(
                max_success_risk * 1.1,
                current_threshold * (1 + self.config.max_adjustment_percent / 100),
                0.5,  # Hard cap at 0.5
            )

            if abs(new_threshold - current_threshold) < 0.01:
                return None

            return ThresholdAdjustment(
                adjustment_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                threshold_name="auto_approve_max_score",
                old_value=current_threshold,
                new_value=new_threshold,
                adjustment_type=AdjustmentType.INCREASE,
                reason=f"High accuracy {accuracy:.1%} suggests threshold can be relaxed",
                confidence=0.6,  # Lower confidence for loosening
                supporting_data={
                    "current_accuracy": accuracy,
                    "max_success_risk": max_success_risk,
                    "auto_approved_count": len(auto_approved),
                },
            )

        return None

    def _analyze_confidence_threshold(
        self,
        outcomes: List[ResurrectionOutcome],
    ) -> Optional[ThresholdAdjustment]:
        """Analyze and propose confidence threshold changes."""
        import uuid

        auto_approved = [o for o in outcomes if o.was_auto_approved]

        if len(auto_approved) < 10:
            return None

        # Group by confidence buckets
        low_conf = [o for o in auto_approved if o.original_confidence < 0.85]
        high_conf = [o for o in auto_approved if o.original_confidence >= 0.85]

        if len(low_conf) < 5 or len(high_conf) < 5:
            return None

        low_success_rate = len([o for o in low_conf if o.outcome_type == OutcomeType.SUCCESS]) / len(low_conf)
        high_success_rate = len([o for o in high_conf if o.outcome_type == OutcomeType.SUCCESS]) / len(high_conf)

        current_threshold = self.current.risk_thresholds.auto_approve_min_confidence

        # If low confidence has much worse outcomes, raise threshold
        if high_success_rate > low_success_rate + 0.1:
            new_threshold = min(
                current_threshold * (1 + self.config.max_adjustment_percent / 100),
                0.95,
            )

            if abs(new_threshold - current_threshold) < 0.01:
                return None

            return ThresholdAdjustment(
                adjustment_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                threshold_name="auto_approve_min_confidence",
                old_value=current_threshold,
                new_value=new_threshold,
                adjustment_type=AdjustmentType.INCREASE,
                reason=f"Low-confidence outcomes ({low_success_rate:.1%}) worse than high ({high_success_rate:.1%})",
                confidence=0.75,
                supporting_data={
                    "low_conf_success_rate": low_success_rate,
                    "high_conf_success_rate": high_success_rate,
                    "low_conf_count": len(low_conf),
                    "high_conf_count": len(high_conf),
                },
            )

        return None

    def _analyze_risk_weights(
        self,
        outcomes: List[ResurrectionOutcome],
    ) -> List[ThresholdAdjustment]:
        """Analyze risk weights for potential adjustments."""
        # This is a simplified version - full implementation would
        # involve correlation analysis between individual risk factors
        # and outcomes, which requires storing factor-level data
        return []

    def _estimate_impact(
        self,
        adjustments: List[ThresholdAdjustment],
        outcomes: List[ResurrectionOutcome],
    ) -> Dict[str, Any]:
        """Estimate the impact of proposed adjustments."""
        impact = {
            "estimated_accuracy_change": 0.0,
            "estimated_auto_approve_volume_change": 0.0,
            "affected_decisions": 0,
        }

        for adj in adjustments:
            if adj.threshold_name == "auto_approve_max_score":
                # Estimate how many decisions would change
                if adj.adjustment_type == AdjustmentType.DECREASE:
                    affected = [
                        o for o in outcomes
                        if adj.new_value < o.original_risk_score <= adj.old_value
                    ]
                    impact["affected_decisions"] += len(affected)
                    impact["estimated_auto_approve_volume_change"] -= len(affected)
                    # These would have been auto-approved but now require review
                    failures_avoided = [
                        o for o in affected
                        if o.outcome_type != OutcomeType.SUCCESS
                    ]
                    if affected:
                        impact["estimated_accuracy_change"] += len(failures_avoided) / len(outcomes)

        return impact

    def approve_proposal(
        self,
        proposal_id: str,
        approved_by: str,
    ) -> bool:
        """Approve and apply a threshold adjustment proposal."""
        if proposal_id not in self._pending_proposals:
            logger.warning(f"Proposal not found: {proposal_id}")
            return False

        proposal = self._pending_proposals[proposal_id]

        if proposal.status != "pending":
            logger.warning(f"Proposal already {proposal.status}")
            return False

        # Apply adjustments
        for adj in proposal.adjustments:
            self._apply_adjustment(adj)

        proposal.status = "approved"
        proposal.approved_by = approved_by
        proposal.approved_at = datetime.now(timezone.utc)

        self.current.version += 1
        self.current.last_updated = datetime.now(timezone.utc)

        logger.info(
            "Threshold adjustments applied",
            proposal_id=proposal_id,
            approved_by=approved_by,
            adjustments=len(proposal.adjustments),
        )

        return True

    def reject_proposal(self, proposal_id: str, reason: str = "") -> bool:
        """Reject a threshold adjustment proposal."""
        if proposal_id not in self._pending_proposals:
            return False

        proposal = self._pending_proposals[proposal_id]
        proposal.status = "rejected"

        logger.info(f"Proposal rejected: {proposal_id}", reason=reason)
        return True

    def _apply_adjustment(self, adjustment: ThresholdAdjustment) -> None:
        """Apply a single threshold adjustment."""
        if hasattr(self.current.risk_thresholds, adjustment.threshold_name):
            setattr(
                self.current.risk_thresholds,
                adjustment.threshold_name,
                adjustment.new_value,
            )
        elif hasattr(self.current.risk_weights, adjustment.threshold_name):
            setattr(
                self.current.risk_weights,
                adjustment.threshold_name,
                adjustment.new_value,
            )

        self.current.adjustment_history.append(adjustment)

        logger.info(
            f"Applied threshold adjustment: {adjustment.threshold_name}",
            old_value=adjustment.old_value,
            new_value=adjustment.new_value,
        )

    def get_current_thresholds(self) -> CurrentThresholds:
        """Get current threshold configuration."""
        return self.current

    def get_pending_proposals(self) -> List[AdjustmentProposal]:
        """Get all pending proposals."""
        return [
            p for p in self._pending_proposals.values()
            if p.status == "pending"
        ]

    def get_adjustment_history(self, limit: int = 50) -> List[ThresholdAdjustment]:
        """Get history of applied adjustments."""
        return list(reversed(self.current.adjustment_history[-limit:]))

    def simulate_adjustment(
        self,
        adjustment: ThresholdAdjustment,
        outcomes: Optional[List[ResurrectionOutcome]] = None,
    ) -> Dict[str, Any]:
        """Simulate the effect of an adjustment on historical outcomes."""
        if outcomes is None:
            since = datetime.now(timezone.utc) - timedelta(days=self.config.analysis_window_days)
            outcomes = self.outcome_store.get_recent_outcomes(limit=1000, since=since)

        results = {
            "total_outcomes": len(outcomes),
            "would_change": 0,
            "false_positives_caught": 0,
            "true_negatives_missed": 0,
        }

        if adjustment.threshold_name == "auto_approve_max_score":
            for o in outcomes:
                old_auto = o.original_risk_score <= adjustment.old_value
                new_auto = o.original_risk_score <= adjustment.new_value

                if old_auto != new_auto:
                    results["would_change"] += 1
                    if not new_auto and o.outcome_type != OutcomeType.SUCCESS:
                        results["false_positives_caught"] += 1
                    if not new_auto and o.outcome_type == OutcomeType.SUCCESS:
                        results["true_negatives_missed"] += 1

        return results


def create_threshold_adapter(
    outcome_store: OutcomeStore,
    config: Dict[str, Any],
) -> ThresholdAdapter:
    """Factory function to create threshold adapter."""
    learning_config = config.get("learning", {})
    threshold_config = learning_config.get("threshold_adjustment", {})

    adaptive_config = AdaptiveConfig(
        enabled=threshold_config.get("enabled", False),
        min_samples_required=threshold_config.get("min_samples", 50),
        analysis_window_days=threshold_config.get("analysis_window_days", 30),
        max_adjustment_percent=threshold_config.get("max_adjustment_percent", 10),
        adjustment_cooldown_hours=threshold_config.get("cooldown_hours", 24),
        target_auto_approve_accuracy=threshold_config.get("target_accuracy", 0.95),
        require_approval=threshold_config.get("require_approval", True),
    )

    # Load initial thresholds from config
    risk_config = config.get("risk", {})
    threshold_values = risk_config.get("thresholds", {})

    initial_thresholds = RiskThresholds(
        auto_approve_max_score=threshold_values.get("auto_approve_max_score", 0.3),
        auto_approve_min_confidence=threshold_values.get("auto_approve_min_confidence", 0.85),
        escalation_min_score=threshold_values.get("escalation_min_score", 0.7),
        deny_min_score=threshold_values.get("deny_min_score", 0.85),
    )

    return ThresholdAdapter(
        outcome_store=outcome_store,
        config=adaptive_config,
        initial_thresholds=initial_thresholds,
    )
