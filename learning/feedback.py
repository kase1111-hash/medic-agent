"""
Medic Agent Feedback Loop Processor

Processes human and automated feedback to update outcome records
and trigger learning system updates.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from learning.outcome_store import (
    OutcomeStore,
    ResurrectionOutcome,
    OutcomeType,
    FeedbackSource,
)
from core.logger import get_logger

logger = get_logger("learning.feedback")


class FeedbackType(Enum):
    """Types of feedback that can be provided."""
    OUTCOME_CORRECTION = "outcome_correction"     # Correct the outcome type
    DECISION_CORRECTION = "decision_correction"   # Correct the decision (should have been different)
    FALSE_POSITIVE_REPORT = "false_positive"      # Report Smith kill as false positive
    TRUE_POSITIVE_CONFIRM = "true_positive"       # Confirm Smith kill was correct
    QUALITY_RATING = "quality_rating"             # Rate decision quality
    COMMENT = "comment"                           # General comment/observation


@dataclass
class Feedback:
    """Feedback record."""
    feedback_id: str
    outcome_id: str
    kill_id: str
    feedback_type: FeedbackType
    source: FeedbackSource
    submitted_by: str
    submitted_at: datetime
    value: Any  # Type depends on feedback_type
    comment: Optional[str] = None
    processed: bool = False
    processed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "feedback_id": self.feedback_id,
            "outcome_id": self.outcome_id,
            "kill_id": self.kill_id,
            "feedback_type": self.feedback_type.value,
            "source": self.source.value,
            "submitted_by": self.submitted_by,
            "submitted_at": self.submitted_at.isoformat(),
            "value": self.value,
            "comment": self.comment,
            "processed": self.processed,
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
        }


@dataclass
class FeedbackStats:
    """Aggregated feedback statistics."""
    total_feedback: int
    feedback_by_type: Dict[str, int]
    false_positive_reports: int
    true_positive_confirms: int
    decision_corrections: int
    avg_quality_rating: Optional[float]
    top_feedbackers: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_feedback": self.total_feedback,
            "feedback_by_type": self.feedback_by_type,
            "false_positive_reports": self.false_positive_reports,
            "true_positive_confirms": self.true_positive_confirms,
            "decision_corrections": self.decision_corrections,
            "avg_quality_rating": self.avg_quality_rating,
            "top_feedbackers": self.top_feedbackers,
        }


class FeedbackProcessor:
    """
    Processes feedback and updates the learning system.

    Handles:
    - Human operator feedback on decisions
    - Automated feedback from monitoring
    - False positive/true positive classification
    - Decision quality ratings
    """

    def __init__(
        self,
        outcome_store: OutcomeStore,
        on_feedback_processed: Optional[Callable] = None,
    ):
        self.outcome_store = outcome_store
        self.on_feedback_processed = on_feedback_processed

        self._feedback_history: List[Feedback] = []
        self._pending_feedback: Dict[str, Feedback] = {}

        logger.info("FeedbackProcessor initialized")

    def submit_feedback(
        self,
        outcome_id: str,
        feedback_type: FeedbackType,
        value: Any,
        submitted_by: str,
        source: FeedbackSource = FeedbackSource.HUMAN_OPERATOR,
        comment: Optional[str] = None,
    ) -> Feedback:
        """
        Submit feedback for an outcome.

        Args:
            outcome_id: ID of the outcome to provide feedback on
            feedback_type: Type of feedback
            value: Feedback value (depends on type)
            submitted_by: Identifier of who submitted the feedback
            source: Source of the feedback
            comment: Optional comment

        Returns:
            Created Feedback object
        """
        # Get the outcome
        outcome = self.outcome_store.get_outcome(outcome_id)
        if not outcome:
            raise ValueError(f"Outcome not found: {outcome_id}")

        feedback = Feedback(
            feedback_id=str(uuid.uuid4()),
            outcome_id=outcome_id,
            kill_id=outcome.kill_id,
            feedback_type=feedback_type,
            source=source,
            submitted_by=submitted_by,
            submitted_at=datetime.now(timezone.utc),
            value=value,
            comment=comment,
        )

        self._pending_feedback[feedback.feedback_id] = feedback

        logger.info(
            "Feedback submitted",
            feedback_id=feedback.feedback_id,
            outcome_id=outcome_id,
            feedback_type=feedback_type.value,
            submitted_by=submitted_by,
        )

        # Auto-process simple feedback types
        if feedback_type in (
            FeedbackType.FALSE_POSITIVE_REPORT,
            FeedbackType.TRUE_POSITIVE_CONFIRM,
            FeedbackType.COMMENT,
        ):
            self.process_feedback(feedback.feedback_id)

        return feedback

    def process_feedback(self, feedback_id: str) -> bool:
        """
        Process pending feedback and update outcome.

        Args:
            feedback_id: ID of the feedback to process

        Returns:
            True if processed successfully
        """
        if feedback_id not in self._pending_feedback:
            # Check if already processed
            if any(f.feedback_id == feedback_id for f in self._feedback_history):
                logger.warning(f"Feedback already processed: {feedback_id}")
                return False
            logger.warning(f"Feedback not found: {feedback_id}")
            return False

        feedback = self._pending_feedback[feedback_id]

        try:
            updates = self._generate_updates(feedback)

            if updates:
                self.outcome_store.update_outcome(feedback.outcome_id, updates)

            feedback.processed = True
            feedback.processed_at = datetime.now(timezone.utc)

            self._feedback_history.append(feedback)
            del self._pending_feedback[feedback_id]

            logger.info(
                "Feedback processed",
                feedback_id=feedback_id,
                updates=list(updates.keys()) if updates else [],
            )

            # Trigger callback
            if self.on_feedback_processed:
                try:
                    self.on_feedback_processed(feedback, updates)
                except Exception as e:
                    logger.error(f"Feedback callback error: {e}")

            return True

        except Exception as e:
            logger.error(f"Error processing feedback: {e}", exc_info=True)
            return False

    def _generate_updates(self, feedback: Feedback) -> Dict[str, Any]:
        """Generate outcome updates based on feedback."""
        updates = {
            "feedback_source": feedback.source,
            "human_feedback": feedback.comment,
        }

        if feedback.feedback_type == FeedbackType.OUTCOME_CORRECTION:
            if isinstance(feedback.value, str):
                updates["outcome_type"] = OutcomeType(feedback.value)
            elif isinstance(feedback.value, OutcomeType):
                updates["outcome_type"] = feedback.value

        elif feedback.feedback_type == FeedbackType.DECISION_CORRECTION:
            updates["corrected_decision"] = feedback.value

        elif feedback.feedback_type == FeedbackType.FALSE_POSITIVE_REPORT:
            updates["outcome_type"] = OutcomeType.FALSE_POSITIVE

        elif feedback.feedback_type == FeedbackType.TRUE_POSITIVE_CONFIRM:
            updates["outcome_type"] = OutcomeType.TRUE_POSITIVE

        elif feedback.feedback_type == FeedbackType.QUALITY_RATING:
            # Store rating in metadata
            outcome = self.outcome_store.get_outcome(feedback.outcome_id)
            if outcome:
                metadata = outcome.metadata.copy()
                metadata["quality_rating"] = feedback.value
                updates["metadata"] = metadata

        elif feedback.feedback_type == FeedbackType.COMMENT:
            # Just store the comment
            pass

        return updates

    def report_false_positive(
        self,
        kill_id: str,
        reported_by: str,
        reason: Optional[str] = None,
    ) -> Optional[Feedback]:
        """
        Report a Smith kill as a false positive.

        Args:
            kill_id: The kill ID that was a false positive
            reported_by: Who reported the false positive
            reason: Optional explanation

        Returns:
            Created Feedback if outcome found
        """
        # Find outcome by kill_id
        outcomes = self.outcome_store.get_recent_outcomes(limit=1000)
        matching = [o for o in outcomes if o.kill_id == kill_id]

        if not matching:
            logger.warning(f"No outcome found for kill_id: {kill_id}")
            return None

        outcome = matching[0]

        return self.submit_feedback(
            outcome_id=outcome.outcome_id,
            feedback_type=FeedbackType.FALSE_POSITIVE_REPORT,
            value=True,
            submitted_by=reported_by,
            comment=reason,
        )

    def confirm_true_positive(
        self,
        kill_id: str,
        confirmed_by: str,
        reason: Optional[str] = None,
    ) -> Optional[Feedback]:
        """
        Confirm a Smith kill was a true positive.

        Args:
            kill_id: The kill ID that was correctly identified
            confirmed_by: Who confirmed
            reason: Optional explanation

        Returns:
            Created Feedback if outcome found
        """
        outcomes = self.outcome_store.get_recent_outcomes(limit=1000)
        matching = [o for o in outcomes if o.kill_id == kill_id]

        if not matching:
            logger.warning(f"No outcome found for kill_id: {kill_id}")
            return None

        outcome = matching[0]

        return self.submit_feedback(
            outcome_id=outcome.outcome_id,
            feedback_type=FeedbackType.TRUE_POSITIVE_CONFIRM,
            value=True,
            submitted_by=confirmed_by,
            comment=reason,
        )

    def correct_decision(
        self,
        outcome_id: str,
        correct_decision: str,
        corrected_by: str,
        reason: Optional[str] = None,
    ) -> Feedback:
        """
        Submit a decision correction.

        Args:
            outcome_id: Outcome to correct
            correct_decision: What the decision should have been
            corrected_by: Who submitted the correction
            reason: Why the original decision was wrong

        Returns:
            Created Feedback
        """
        return self.submit_feedback(
            outcome_id=outcome_id,
            feedback_type=FeedbackType.DECISION_CORRECTION,
            value=correct_decision,
            submitted_by=corrected_by,
            comment=reason,
        )

    def rate_decision(
        self,
        outcome_id: str,
        rating: int,
        rated_by: str,
        comment: Optional[str] = None,
    ) -> Feedback:
        """
        Rate the quality of a decision (1-5 scale).

        Args:
            outcome_id: Outcome to rate
            rating: Quality rating (1-5)
            rated_by: Who provided the rating
            comment: Optional comment

        Returns:
            Created Feedback
        """
        if not 1 <= rating <= 5:
            raise ValueError("Rating must be between 1 and 5")

        return self.submit_feedback(
            outcome_id=outcome_id,
            feedback_type=FeedbackType.QUALITY_RATING,
            value=rating,
            submitted_by=rated_by,
            comment=comment,
        )

    def submit_automated_feedback(
        self,
        outcome_id: str,
        outcome_type: OutcomeType,
        health_score: Optional[float] = None,
        time_to_healthy: Optional[float] = None,
        anomalies_detected: int = 0,
        required_rollback: bool = False,
    ) -> None:
        """
        Submit automated feedback from monitoring system.

        Args:
            outcome_id: Outcome to update
            outcome_type: Determined outcome type
            health_score: Health score after resurrection
            time_to_healthy: Time to reach healthy state
            anomalies_detected: Number of anomalies detected
            required_rollback: Whether rollback was required
        """
        updates = {
            "outcome_type": outcome_type,
            "feedback_source": FeedbackSource.AUTOMATED,
        }

        if health_score is not None:
            updates["health_score_after"] = health_score
        if time_to_healthy is not None:
            updates["time_to_healthy"] = time_to_healthy
        if anomalies_detected:
            updates["anomalies_detected"] = anomalies_detected
        if required_rollback:
            updates["required_rollback"] = True
            updates["outcome_type"] = OutcomeType.ROLLBACK

        self.outcome_store.update_outcome(outcome_id, updates)

        logger.info(
            "Automated feedback recorded",
            outcome_id=outcome_id,
            outcome_type=outcome_type.value,
        )

    def get_pending_feedback(self) -> List[Feedback]:
        """Get all pending feedback awaiting processing."""
        return list(self._pending_feedback.values())

    def get_feedback_history(
        self,
        limit: int = 100,
        feedback_type: Optional[FeedbackType] = None,
    ) -> List[Feedback]:
        """Get feedback history with optional filtering."""
        history = self._feedback_history

        if feedback_type:
            history = [f for f in history if f.feedback_type == feedback_type]

        return list(reversed(history[-limit:]))

    def get_statistics(self) -> FeedbackStats:
        """Get aggregated feedback statistics."""
        all_feedback = self._feedback_history

        # Count by type
        by_type = {}
        for f in all_feedback:
            key = f.feedback_type.value
            by_type[key] = by_type.get(key, 0) + 1

        # Calculate ratings
        ratings = [
            f.value for f in all_feedback
            if f.feedback_type == FeedbackType.QUALITY_RATING
            and isinstance(f.value, (int, float))
        ]
        avg_rating = sum(ratings) / len(ratings) if ratings else None

        # Top feedbackers
        from collections import Counter
        feedbackers = Counter(f.submitted_by for f in all_feedback)
        top = [
            {"user": user, "count": count}
            for user, count in feedbackers.most_common(5)
        ]

        return FeedbackStats(
            total_feedback=len(all_feedback),
            feedback_by_type=by_type,
            false_positive_reports=by_type.get("false_positive", 0),
            true_positive_confirms=by_type.get("true_positive", 0),
            decision_corrections=by_type.get("decision_correction", 0),
            avg_quality_rating=avg_rating,
            top_feedbackers=top,
        )


class AutomatedFeedbackCollector:
    """
    Collects feedback automatically from the monitoring system.

    Integrates with the resurrection monitor to determine
    outcomes and submit feedback.
    """

    def __init__(
        self,
        feedback_processor: FeedbackProcessor,
        outcome_store: OutcomeStore,
    ):
        self.feedback_processor = feedback_processor
        self.outcome_store = outcome_store

        logger.info("AutomatedFeedbackCollector initialized")

    def on_monitoring_complete(
        self,
        request_id: str,
        success: bool,
        health_score: float,
        time_to_healthy: float,
        anomalies: List[Any],
    ) -> None:
        """
        Handle monitoring completion event.

        Args:
            request_id: Resurrection request ID
            success: Whether monitoring completed successfully
            health_score: Final health score
            time_to_healthy: Time to reach healthy state
            anomalies: List of detected anomalies
        """
        # Find outcome by request ID
        outcomes = self.outcome_store.get_recent_outcomes(limit=500)

        # Look for matching outcome in metadata or create one
        matching = [
            o for o in outcomes
            if o.metadata.get("request_id") == request_id
        ]

        if not matching:
            logger.warning(f"No outcome found for request: {request_id}")
            return

        outcome = matching[0]

        # Determine outcome type
        if success and health_score >= 0.8:
            outcome_type = OutcomeType.SUCCESS
        elif success:
            outcome_type = OutcomeType.PARTIAL_SUCCESS
        else:
            outcome_type = OutcomeType.FAILURE

        self.feedback_processor.submit_automated_feedback(
            outcome_id=outcome.outcome_id,
            outcome_type=outcome_type,
            health_score=health_score,
            time_to_healthy=time_to_healthy,
            anomalies_detected=len(anomalies),
        )

    def on_rollback_triggered(
        self,
        request_id: str,
        reason: str,
    ) -> None:
        """
        Handle rollback event.

        Args:
            request_id: Resurrection request ID
            reason: Reason for rollback
        """
        outcomes = self.outcome_store.get_recent_outcomes(limit=500)

        matching = [
            o for o in outcomes
            if o.metadata.get("request_id") == request_id
        ]

        if not matching:
            logger.warning(f"No outcome found for request: {request_id}")
            return

        outcome = matching[0]

        self.feedback_processor.submit_automated_feedback(
            outcome_id=outcome.outcome_id,
            outcome_type=OutcomeType.ROLLBACK,
            required_rollback=True,
        )


def create_feedback_processor(
    outcome_store: OutcomeStore,
    on_feedback_processed: Optional[Callable] = None,
) -> FeedbackProcessor:
    """Factory function to create feedback processor."""
    return FeedbackProcessor(
        outcome_store=outcome_store,
        on_feedback_processed=on_feedback_processed,
    )


def create_automated_collector(
    feedback_processor: FeedbackProcessor,
    outcome_store: OutcomeStore,
) -> AutomatedFeedbackCollector:
    """Factory function to create automated feedback collector."""
    return AutomatedFeedbackCollector(
        feedback_processor=feedback_processor,
        outcome_store=outcome_store,
    )
