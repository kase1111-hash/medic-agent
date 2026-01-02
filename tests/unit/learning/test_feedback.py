"""
Unit tests for the FeedbackProcessor module.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock

from learning.outcome_store import (
    InMemoryOutcomeStore,
    ResurrectionOutcome,
    OutcomeType,
    FeedbackSource,
)
from learning.feedback import (
    FeedbackProcessor,
    AutomatedFeedbackCollector,
    Feedback,
    FeedbackType,
    FeedbackStats,
    create_feedback_processor,
    create_automated_collector,
)


class TestFeedback:
    """Tests for Feedback dataclass."""

    def test_create_feedback(self):
        """Test creating a Feedback instance."""
        feedback = Feedback(
            feedback_id="fb-001",
            outcome_id="out-001",
            kill_id="kill-001",
            feedback_type=FeedbackType.FALSE_POSITIVE_REPORT,
            source=FeedbackSource.HUMAN_OPERATOR,
            submitted_by="operator-1",
            submitted_at=datetime.utcnow(),
            value=True,
            comment="Smith was wrong",
        )

        assert feedback.feedback_id == "fb-001"
        assert feedback.feedback_type == FeedbackType.FALSE_POSITIVE_REPORT
        assert feedback.processed is False

    def test_to_dict(self):
        """Test serializing feedback to dict."""
        now = datetime.utcnow()
        feedback = Feedback(
            feedback_id="fb-001",
            outcome_id="out-001",
            kill_id="kill-001",
            feedback_type=FeedbackType.DECISION_CORRECTION,
            source=FeedbackSource.HUMAN_OPERATOR,
            submitted_by="admin",
            submitted_at=now,
            value="deny",
            comment="Should have been denied",
            processed=True,
            processed_at=now,
        )

        data = feedback.to_dict()

        assert data["feedback_type"] == "decision_correction"
        assert data["value"] == "deny"
        assert data["processed"] is True


class TestFeedbackStats:
    """Tests for FeedbackStats dataclass."""

    def test_create_stats(self):
        """Test creating FeedbackStats instance."""
        stats = FeedbackStats(
            total_feedback=100,
            feedback_by_type={"false_positive": 30, "true_positive": 20},
            false_positive_reports=30,
            true_positive_confirms=20,
            decision_corrections=10,
            avg_quality_rating=4.2,
            top_feedbackers=[{"user": "admin", "count": 50}],
        )

        assert stats.total_feedback == 100
        assert stats.false_positive_reports == 30

    def test_to_dict(self):
        """Test serializing stats to dict."""
        stats = FeedbackStats(
            total_feedback=50,
            feedback_by_type={},
            false_positive_reports=10,
            true_positive_confirms=5,
            decision_corrections=3,
            avg_quality_rating=3.5,
            top_feedbackers=[],
        )

        data = stats.to_dict()

        assert data["total_feedback"] == 50
        assert data["avg_quality_rating"] == 3.5


class TestFeedbackProcessor:
    """Tests for FeedbackProcessor."""

    @pytest.fixture
    def outcome_store(self):
        """Create a fresh InMemoryOutcomeStore."""
        return InMemoryOutcomeStore()

    @pytest.fixture
    def sample_outcome(self, outcome_store):
        """Create and store a sample outcome."""
        outcome = ResurrectionOutcome(
            outcome_id="test-out-001",
            decision_id="dec-001",
            kill_id="kill-001",
            target_module="test-service",
            timestamp=datetime.utcnow(),
            outcome_type=OutcomeType.UNDETERMINED,
            original_risk_score=0.3,
            original_confidence=0.9,
            original_decision="approve_auto",
            was_auto_approved=True,
        )
        outcome_store.store_outcome(outcome)
        return outcome

    @pytest.fixture
    def processor(self, outcome_store):
        """Create a FeedbackProcessor."""
        return FeedbackProcessor(outcome_store)

    def test_initialization(self, processor):
        """Test FeedbackProcessor initialization."""
        assert processor.outcome_store is not None
        assert len(processor._feedback_history) == 0
        assert len(processor._pending_feedback) == 0

    def test_submit_feedback(self, processor, sample_outcome):
        """Test submitting feedback."""
        feedback = processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.COMMENT,
            value="Test comment",
            submitted_by="operator",
        )

        assert feedback is not None
        assert feedback.feedback_type == FeedbackType.COMMENT
        assert feedback.submitted_by == "operator"

    def test_submit_feedback_nonexistent_outcome(self, processor):
        """Test submitting feedback for nonexistent outcome raises error."""
        with pytest.raises(ValueError):
            processor.submit_feedback(
                outcome_id="nonexistent",
                feedback_type=FeedbackType.COMMENT,
                value="Test",
                submitted_by="operator",
            )

    def test_auto_process_simple_feedback(self, processor, sample_outcome):
        """Test that simple feedback types are auto-processed."""
        feedback = processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.FALSE_POSITIVE_REPORT,
            value=True,
            submitted_by="operator",
        )

        # Should be processed automatically
        assert feedback.processed is True
        assert feedback.processed_at is not None

        # Check outcome was updated
        updated = processor.outcome_store.get_outcome("test-out-001")
        assert updated.outcome_type == OutcomeType.FALSE_POSITIVE

    def test_report_false_positive(self, processor, sample_outcome):
        """Test reporting a false positive."""
        feedback = processor.report_false_positive(
            kill_id="kill-001",
            reported_by="security-team",
            reason="Module was not compromised",
        )

        assert feedback is not None
        assert feedback.feedback_type == FeedbackType.FALSE_POSITIVE_REPORT

        # Verify outcome updated
        outcome = processor.outcome_store.get_outcome("test-out-001")
        assert outcome.outcome_type == OutcomeType.FALSE_POSITIVE

    def test_report_false_positive_not_found(self, processor):
        """Test reporting FP for unknown kill returns None."""
        result = processor.report_false_positive(
            kill_id="unknown-kill",
            reported_by="operator",
        )

        assert result is None

    def test_confirm_true_positive(self, processor, sample_outcome):
        """Test confirming a true positive."""
        feedback = processor.confirm_true_positive(
            kill_id="kill-001",
            confirmed_by="incident-response",
            reason="Confirmed malicious activity",
        )

        assert feedback is not None
        assert feedback.feedback_type == FeedbackType.TRUE_POSITIVE_CONFIRM

        # Verify outcome updated
        outcome = processor.outcome_store.get_outcome("test-out-001")
        assert outcome.outcome_type == OutcomeType.TRUE_POSITIVE

    def test_correct_decision(self, processor, sample_outcome):
        """Test submitting a decision correction."""
        feedback = processor.correct_decision(
            outcome_id="test-out-001",
            correct_decision="deny",
            corrected_by="supervisor",
            reason="Risk was underestimated",
        )

        assert feedback is not None
        assert feedback.feedback_type == FeedbackType.DECISION_CORRECTION
        assert feedback.value == "deny"

    def test_rate_decision(self, processor, sample_outcome):
        """Test rating a decision."""
        feedback = processor.rate_decision(
            outcome_id="test-out-001",
            rating=4,
            rated_by="reviewer",
            comment="Good decision",
        )

        assert feedback is not None
        assert feedback.feedback_type == FeedbackType.QUALITY_RATING
        assert feedback.value == 4

    def test_rate_decision_invalid_rating(self, processor, sample_outcome):
        """Test that invalid rating raises error."""
        with pytest.raises(ValueError):
            processor.rate_decision(
                outcome_id="test-out-001",
                rating=6,  # Invalid: must be 1-5
                rated_by="reviewer",
            )

    def test_submit_automated_feedback(self, processor, sample_outcome):
        """Test submitting automated feedback."""
        processor.submit_automated_feedback(
            outcome_id="test-out-001",
            outcome_type=OutcomeType.SUCCESS,
            health_score=0.95,
            time_to_healthy=30.0,
            anomalies_detected=0,
        )

        outcome = processor.outcome_store.get_outcome("test-out-001")

        assert outcome.outcome_type == OutcomeType.SUCCESS
        assert outcome.health_score_after == 0.95
        assert outcome.time_to_healthy == 30.0

    def test_submit_automated_rollback_feedback(self, processor, sample_outcome):
        """Test submitting automated rollback feedback."""
        processor.submit_automated_feedback(
            outcome_id="test-out-001",
            outcome_type=OutcomeType.FAILURE,
            required_rollback=True,
        )

        outcome = processor.outcome_store.get_outcome("test-out-001")

        assert outcome.outcome_type == OutcomeType.ROLLBACK
        assert outcome.required_rollback is True

    def test_get_pending_feedback(self, processor, sample_outcome):
        """Test getting pending feedback."""
        # Submit feedback that requires processing
        processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.DECISION_CORRECTION,
            value="deny",
            submitted_by="operator",
        )

        pending = processor.get_pending_feedback()

        assert len(pending) == 1
        assert pending[0].feedback_type == FeedbackType.DECISION_CORRECTION

    def test_process_feedback(self, processor, sample_outcome):
        """Test manually processing feedback."""
        feedback = processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.DECISION_CORRECTION,
            value="deny",
            submitted_by="operator",
        )

        success = processor.process_feedback(feedback.feedback_id)

        assert success is True
        assert feedback.processed is True

        # Verify outcome updated
        outcome = processor.outcome_store.get_outcome("test-out-001")
        assert outcome.corrected_decision == "deny"

    def test_process_already_processed_feedback(self, processor, sample_outcome):
        """Test processing already processed feedback returns False."""
        feedback = processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.FALSE_POSITIVE_REPORT,
            value=True,
            submitted_by="operator",
        )

        # Already auto-processed
        result = processor.process_feedback(feedback.feedback_id)

        assert result is False

    def test_get_feedback_history(self, processor, sample_outcome):
        """Test getting feedback history."""
        # Submit multiple feedbacks
        for i in range(5):
            processor.submit_feedback(
                outcome_id="test-out-001",
                feedback_type=FeedbackType.COMMENT,
                value=f"Comment {i}",
                submitted_by=f"user-{i}",
            )

        history = processor.get_feedback_history()

        assert len(history) == 5

    def test_get_feedback_history_filtered(self, processor, sample_outcome):
        """Test getting filtered feedback history."""
        processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.COMMENT,
            value="Comment",
            submitted_by="user",
        )
        processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.FALSE_POSITIVE_REPORT,
            value=True,
            submitted_by="user",
        )

        comments = processor.get_feedback_history(feedback_type=FeedbackType.COMMENT)
        fp_reports = processor.get_feedback_history(feedback_type=FeedbackType.FALSE_POSITIVE_REPORT)

        assert len(comments) == 1
        assert len(fp_reports) == 1

    def test_get_statistics(self, processor, sample_outcome):
        """Test getting feedback statistics."""
        # Submit various feedbacks
        processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.FALSE_POSITIVE_REPORT,
            value=True,
            submitted_by="user-1",
        )

        # Need to create more outcomes for more feedback
        for i in range(4):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service",
                timestamp=datetime.utcnow(),
                outcome_type=OutcomeType.SUCCESS,
                original_risk_score=0.2,
                original_confidence=0.9,
                original_decision="approve_auto",
                was_auto_approved=True,
            )
            processor.outcome_store.store_outcome(outcome)

            processor.rate_decision(
                outcome_id=f"out-{i}",
                rating=4,
                rated_by="user-1",
            )

        stats = processor.get_statistics()

        assert stats.total_feedback >= 5
        assert stats.false_positive_reports >= 1

    def test_callback_on_feedback_processed(self, outcome_store, sample_outcome):
        """Test callback is called when feedback is processed."""
        callback = Mock()
        processor = FeedbackProcessor(outcome_store, on_feedback_processed=callback)

        processor.submit_feedback(
            outcome_id="test-out-001",
            feedback_type=FeedbackType.FALSE_POSITIVE_REPORT,
            value=True,
            submitted_by="operator",
        )

        callback.assert_called_once()


class TestAutomatedFeedbackCollector:
    """Tests for AutomatedFeedbackCollector."""

    @pytest.fixture
    def outcome_store(self):
        """Create a fresh InMemoryOutcomeStore."""
        return InMemoryOutcomeStore()

    @pytest.fixture
    def processor(self, outcome_store):
        """Create a FeedbackProcessor."""
        return FeedbackProcessor(outcome_store)

    @pytest.fixture
    def collector(self, processor, outcome_store):
        """Create an AutomatedFeedbackCollector."""
        return AutomatedFeedbackCollector(processor, outcome_store)

    @pytest.fixture
    def sample_outcome(self, outcome_store):
        """Create and store a sample outcome with request_id in metadata."""
        outcome = ResurrectionOutcome(
            outcome_id="test-out-001",
            decision_id="dec-001",
            kill_id="kill-001",
            target_module="test-service",
            timestamp=datetime.utcnow(),
            outcome_type=OutcomeType.UNDETERMINED,
            original_risk_score=0.3,
            original_confidence=0.9,
            original_decision="approve_auto",
            was_auto_approved=True,
            metadata={"request_id": "req-001"},
        )
        outcome_store.store_outcome(outcome)
        return outcome

    def test_on_monitoring_complete_success(self, collector, sample_outcome):
        """Test handling successful monitoring completion."""
        collector.on_monitoring_complete(
            request_id="req-001",
            success=True,
            health_score=0.95,
            time_to_healthy=30.0,
            anomalies=[],
        )

        outcome = collector.outcome_store.get_outcome("test-out-001")

        assert outcome.outcome_type == OutcomeType.SUCCESS
        assert outcome.health_score_after == 0.95

    def test_on_monitoring_complete_partial(self, collector, sample_outcome):
        """Test handling partial success monitoring completion."""
        collector.on_monitoring_complete(
            request_id="req-001",
            success=True,
            health_score=0.6,  # Below 0.8 threshold
            time_to_healthy=60.0,
            anomalies=["high_cpu"],
        )

        outcome = collector.outcome_store.get_outcome("test-out-001")

        assert outcome.outcome_type == OutcomeType.PARTIAL_SUCCESS

    def test_on_monitoring_complete_failure(self, collector, sample_outcome):
        """Test handling failed monitoring completion."""
        collector.on_monitoring_complete(
            request_id="req-001",
            success=False,
            health_score=0.3,
            time_to_healthy=0,
            anomalies=["crash", "oom"],
        )

        outcome = collector.outcome_store.get_outcome("test-out-001")

        assert outcome.outcome_type == OutcomeType.FAILURE

    def test_on_monitoring_complete_unknown_request(self, collector):
        """Test handling monitoring for unknown request."""
        # Should not raise, just log warning
        collector.on_monitoring_complete(
            request_id="unknown-req",
            success=True,
            health_score=0.9,
            time_to_healthy=30.0,
            anomalies=[],
        )

    def test_on_rollback_triggered(self, collector, sample_outcome):
        """Test handling rollback event."""
        collector.on_rollback_triggered(
            request_id="req-001",
            reason="Anomaly detected",
        )

        outcome = collector.outcome_store.get_outcome("test-out-001")

        assert outcome.outcome_type == OutcomeType.ROLLBACK
        assert outcome.required_rollback is True

    def test_on_rollback_unknown_request(self, collector):
        """Test handling rollback for unknown request."""
        # Should not raise, just log warning
        collector.on_rollback_triggered(
            request_id="unknown-req",
            reason="Test",
        )


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_feedback_processor(self):
        """Test creating feedback processor via factory."""
        store = InMemoryOutcomeStore()
        processor = create_feedback_processor(store)

        assert isinstance(processor, FeedbackProcessor)

    def test_create_feedback_processor_with_callback(self):
        """Test creating processor with callback."""
        store = InMemoryOutcomeStore()
        callback = Mock()

        processor = create_feedback_processor(store, on_feedback_processed=callback)

        assert processor.on_feedback_processed is callback

    def test_create_automated_collector(self):
        """Test creating automated collector via factory."""
        store = InMemoryOutcomeStore()
        processor = FeedbackProcessor(store)

        collector = create_automated_collector(processor, store)

        assert isinstance(collector, AutomatedFeedbackCollector)
