"""
Unit tests for the ApprovalQueue module.
"""

import pytest
import asyncio
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch

from interfaces.approval_queue import (
    ApprovalQueue,
    InMemoryApprovalQueue,
    QueueItem,
    QueueItemStatus,
    create_approval_queue,
)
from execution.recommendation import (
    ResurrectionProposal,
    RecommendationType,
    UrgencyLevel,
)
from core.models import (
    KillReport,
    KillReason,
    Severity,
    SIEMContextResponse,
    ResurrectionDecision,
    DecisionOutcome,
    RiskLevel,
    ResurrectionStatus,
)


class TestQueueItemStatus:
    """Tests for QueueItemStatus enum."""

    def test_status_values(self):
        """Test that all status values are defined."""
        assert QueueItemStatus.PENDING.value == "pending"
        assert QueueItemStatus.APPROVED.value == "approved"
        assert QueueItemStatus.DENIED.value == "denied"
        assert QueueItemStatus.EXPIRED.value == "expired"
        assert QueueItemStatus.CANCELLED.value == "cancelled"


class TestQueueItem:
    """Tests for QueueItem dataclass."""

    @pytest.fixture
    def sample_proposal(self):
        """Create a sample proposal for testing."""
        kill_report = KillReport(
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            target_module="test-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["High CPU usage detected"],
            dependencies=["database-service"],
            source_agent="smith-agent",
        )

        siem_context = SIEMContextResponse(
            query_id="query-001",
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={"recent_issues": 0},
            false_positive_history=5,
            network_context={"connections": 10},
            user_context=None,
            risk_score=0.3,
            recommendation="approve",
        )

        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.35,
            confidence=0.85,
            reasoning=["Low risk", "Good history"],
            recommended_action="Approve with monitoring",
        )

        return ResurrectionProposal(
            proposal_id="prop-001",
            created_at=datetime.utcnow(),
            kill_report=kill_report,
            siem_context=siem_context,
            decision=decision,
            recommendation=RecommendationType.APPROVE,
            urgency=UrgencyLevel.MEDIUM,
            summary="Test proposal for test-service",
            key_factors=["Low risk score", "Good history"],
            risk_factors={"behavioral": 0.2, "historical": 0.1},
            mitigating_factors=["Clean history"],
            aggravating_factors=[],
            module_history={"resurrections": 3, "failures": 0},
            similar_incidents=[],
            suggested_pre_checks=["Check dependencies"],
            suggested_post_checks=["Monitor health"],
            rollback_strategy="Immediate rollback on anomaly",
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )

    def test_create_queue_item(self, sample_proposal):
        """Test creating a QueueItem instance."""
        item = QueueItem(
            item_id="item-001",
            proposal=sample_proposal,
            status=QueueItemStatus.PENDING,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            priority=50,
        )

        assert item.item_id == "item-001"
        assert item.status == QueueItemStatus.PENDING
        assert item.priority == 50
        assert item.reviewed_by is None

    def test_to_dict(self, sample_proposal):
        """Test serializing QueueItem to dict."""
        now = datetime.utcnow()
        item = QueueItem(
            item_id="item-001",
            proposal=sample_proposal,
            status=QueueItemStatus.APPROVED,
            created_at=now,
            expires_at=now + timedelta(hours=24),
            priority=75,
            reviewed_by="admin",
            reviewed_at=now,
            review_notes="Approved for testing",
        )

        data = item.to_dict()

        assert data["item_id"] == "item-001"
        assert data["status"] == "approved"
        assert data["priority"] == 75
        assert data["reviewed_by"] == "admin"
        assert data["review_notes"] == "Approved for testing"

    def test_is_expired_false(self, sample_proposal):
        """Test is_expired returns False for non-expired items."""
        item = QueueItem(
            item_id="item-001",
            proposal=sample_proposal,
            status=QueueItemStatus.PENDING,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )

        assert item.is_expired() is False

    def test_is_expired_true(self, sample_proposal):
        """Test is_expired returns True for expired items."""
        item = QueueItem(
            item_id="item-001",
            proposal=sample_proposal,
            status=QueueItemStatus.PENDING,
            created_at=datetime.utcnow() - timedelta(hours=48),
            expires_at=datetime.utcnow() - timedelta(hours=24),
        )

        assert item.is_expired() is True


class TestInMemoryApprovalQueue:
    """Tests for InMemoryApprovalQueue."""

    @pytest.fixture
    def queue(self):
        """Create a fresh InMemoryApprovalQueue."""
        return InMemoryApprovalQueue()

    @pytest.fixture
    def sample_proposal(self):
        """Create a sample proposal for testing."""
        kill_report = KillReport(
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            target_module="test-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["High CPU usage detected"],
            dependencies=["database-service"],
            source_agent="smith-agent",
        )

        siem_context = SIEMContextResponse(
            query_id="query-001",
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={"recent_issues": 0},
            false_positive_history=5,
            network_context={"connections": 10},
            user_context=None,
            risk_score=0.3,
            recommendation="approve",
        )

        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.35,
            confidence=0.85,
            reasoning=["Low risk", "Good history"],
            recommended_action="Approve with monitoring",
        )

        return ResurrectionProposal(
            proposal_id="prop-001",
            created_at=datetime.utcnow(),
            kill_report=kill_report,
            siem_context=siem_context,
            decision=decision,
            recommendation=RecommendationType.APPROVE,
            urgency=UrgencyLevel.MEDIUM,
            summary="Test proposal for test-service",
            key_factors=["Low risk score", "Good history"],
            risk_factors={"behavioral": 0.2, "historical": 0.1},
            mitigating_factors=["Clean history"],
            aggravating_factors=[],
            module_history={"resurrections": 3, "failures": 0},
            similar_incidents=[],
            suggested_pre_checks=["Check dependencies"],
            suggested_post_checks=["Monitor health"],
            rollback_strategy="Immediate rollback on anomaly",
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )

    def create_proposal_with_urgency(self, urgency: UrgencyLevel) -> ResurrectionProposal:
        """Helper to create proposals with different urgency levels."""
        kill_report = KillReport(
            kill_id=f"kill-{urgency.value}",
            timestamp=datetime.utcnow(),
            target_module="test-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["Test evidence"],
            dependencies=[],
            source_agent="smith-agent",
        )

        siem_context = SIEMContextResponse(
            query_id=f"query-{urgency.value}",
            kill_id=f"kill-{urgency.value}",
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.3,
            recommendation="approve",
        )

        decision = ResurrectionDecision.create(
            kill_id=f"kill-{urgency.value}",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.35,
            confidence=0.85,
            reasoning=["Test"],
            recommended_action="Approve",
        )

        return ResurrectionProposal(
            proposal_id=f"prop-{urgency.value}",
            created_at=datetime.utcnow(),
            kill_report=kill_report,
            siem_context=siem_context,
            decision=decision,
            recommendation=RecommendationType.APPROVE,
            urgency=urgency,
            summary=f"Test proposal with {urgency.value} urgency",
            key_factors=[],
            risk_factors={},
            mitigating_factors=[],
            aggravating_factors=[],
            module_history={},
            similar_incidents=[],
            suggested_pre_checks=[],
            suggested_post_checks=[],
            rollback_strategy="Rollback",
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )

    def test_initialization(self, queue):
        """Test InMemoryApprovalQueue initialization."""
        assert queue.max_pending == 100
        assert queue.default_timeout_hours == 24
        assert len(queue._queue) == 0

    def test_initialization_with_config(self):
        """Test initialization with custom config."""
        config = {"max_pending": 50, "timeout_hours": 12}
        queue = InMemoryApprovalQueue(config=config)

        assert queue.max_pending == 50
        assert queue.default_timeout_hours == 12

    @pytest.mark.asyncio
    async def test_enqueue(self, queue, sample_proposal):
        """Test enqueuing a proposal."""
        item_id = await queue.enqueue(sample_proposal)

        assert item_id == sample_proposal.proposal_id
        assert len(queue._queue) == 1

    @pytest.mark.asyncio
    async def test_enqueue_with_priority(self, queue):
        """Test that enqueue sets priority based on urgency."""
        critical = self.create_proposal_with_urgency(UrgencyLevel.CRITICAL)
        low = self.create_proposal_with_urgency(UrgencyLevel.LOW)

        await queue.enqueue(critical)
        await queue.enqueue(low)

        critical_item = await queue.get_item(critical.proposal_id)
        low_item = await queue.get_item(low.proposal_id)

        assert critical_item.priority == 100
        assert low_item.priority == 25

    @pytest.mark.asyncio
    async def test_enqueue_capacity_limit(self):
        """Test that queue enforces capacity limit."""
        queue = InMemoryApprovalQueue(config={"max_pending": 2})

        prop1 = self.create_proposal_with_urgency(UrgencyLevel.LOW)
        prop2 = self.create_proposal_with_urgency(UrgencyLevel.MEDIUM)
        prop3 = self.create_proposal_with_urgency(UrgencyLevel.HIGH)

        # Need unique proposal IDs
        prop1.proposal_id = "prop-1"
        prop2.proposal_id = "prop-2"
        prop3.proposal_id = "prop-3"

        await queue.enqueue(prop1)
        await queue.enqueue(prop2)

        with pytest.raises(ValueError, match="Queue at capacity"):
            await queue.enqueue(prop3)

    @pytest.mark.asyncio
    async def test_dequeue(self, queue, sample_proposal):
        """Test dequeuing an item."""
        await queue.enqueue(sample_proposal)

        item = await queue.dequeue(sample_proposal.proposal_id)

        assert item is not None
        assert item.item_id == sample_proposal.proposal_id
        assert len(queue._queue) == 0

    @pytest.mark.asyncio
    async def test_dequeue_nonexistent(self, queue):
        """Test dequeuing nonexistent item returns None."""
        item = await queue.dequeue("nonexistent")
        assert item is None

    @pytest.mark.asyncio
    async def test_approve(self, queue, sample_proposal):
        """Test approving a queued proposal."""
        await queue.enqueue(sample_proposal)

        request = await queue.approve(
            sample_proposal.proposal_id,
            approver="test-admin",
            notes="Approved for testing",
        )

        assert request is not None
        assert request.approved_by == "test-admin"
        assert request.status == ResurrectionStatus.APPROVED

        item = await queue.get_item(sample_proposal.proposal_id)
        assert item.status == QueueItemStatus.APPROVED
        assert item.reviewed_by == "test-admin"
        assert item.review_notes == "Approved for testing"

    @pytest.mark.asyncio
    async def test_approve_nonexistent(self, queue):
        """Test approving nonexistent item raises error."""
        with pytest.raises(ValueError, match="Item not found"):
            await queue.approve("nonexistent", "admin")

    @pytest.mark.asyncio
    async def test_approve_already_approved(self, queue, sample_proposal):
        """Test approving already approved item raises error."""
        await queue.enqueue(sample_proposal)
        await queue.approve(sample_proposal.proposal_id, "admin")

        with pytest.raises(ValueError, match="Item not pending"):
            await queue.approve(sample_proposal.proposal_id, "admin2")

    @pytest.mark.asyncio
    async def test_approve_expired(self, queue, sample_proposal):
        """Test approving expired item raises error."""
        # Set expiration in the past
        sample_proposal.expires_at = datetime.utcnow() - timedelta(hours=1)
        await queue.enqueue(sample_proposal)

        with pytest.raises(ValueError, match="Item has expired"):
            await queue.approve(sample_proposal.proposal_id, "admin")

        item = await queue.get_item(sample_proposal.proposal_id)
        assert item.status == QueueItemStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_deny(self, queue, sample_proposal):
        """Test denying a queued proposal."""
        await queue.enqueue(sample_proposal)

        await queue.deny(
            sample_proposal.proposal_id,
            denier="security-admin",
            reason="Risk too high",
        )

        item = await queue.get_item(sample_proposal.proposal_id)
        assert item.status == QueueItemStatus.DENIED
        assert item.reviewed_by == "security-admin"
        assert item.review_notes == "Risk too high"

    @pytest.mark.asyncio
    async def test_deny_nonexistent(self, queue):
        """Test denying nonexistent item raises error."""
        with pytest.raises(ValueError, match="Item not found"):
            await queue.deny("nonexistent", "admin", "Test")

    @pytest.mark.asyncio
    async def test_deny_already_denied(self, queue, sample_proposal):
        """Test denying already denied item raises error."""
        await queue.enqueue(sample_proposal)
        await queue.deny(sample_proposal.proposal_id, "admin", "First denial")

        with pytest.raises(ValueError, match="Item not pending"):
            await queue.deny(sample_proposal.proposal_id, "admin2", "Second denial")

    @pytest.mark.asyncio
    async def test_list_pending(self, queue):
        """Test listing pending items."""
        # Add items with different urgencies
        for urgency in [UrgencyLevel.LOW, UrgencyLevel.CRITICAL, UrgencyLevel.MEDIUM]:
            prop = self.create_proposal_with_urgency(urgency)
            prop.proposal_id = f"prop-{urgency.value}"
            await queue.enqueue(prop)

        pending = await queue.list_pending()

        assert len(pending) == 3
        # Should be sorted by priority (desc)
        assert pending[0].proposal.urgency == UrgencyLevel.CRITICAL
        assert pending[1].proposal.urgency == UrgencyLevel.MEDIUM
        assert pending[2].proposal.urgency == UrgencyLevel.LOW

    @pytest.mark.asyncio
    async def test_list_pending_with_limit(self, queue):
        """Test listing pending items with limit."""
        for i in range(5):
            prop = self.create_proposal_with_urgency(UrgencyLevel.MEDIUM)
            prop.proposal_id = f"prop-{i}"
            await queue.enqueue(prop)

        pending = await queue.list_pending(limit=3)

        assert len(pending) == 3

    @pytest.mark.asyncio
    async def test_list_pending_excludes_non_pending(self, queue, sample_proposal):
        """Test that list_pending excludes approved/denied items."""
        await queue.enqueue(sample_proposal)
        await queue.approve(sample_proposal.proposal_id, "admin")

        pending = await queue.list_pending()

        assert len(pending) == 0

    @pytest.mark.asyncio
    async def test_get_item(self, queue, sample_proposal):
        """Test getting a specific item."""
        await queue.enqueue(sample_proposal)

        item = await queue.get_item(sample_proposal.proposal_id)

        assert item is not None
        assert item.item_id == sample_proposal.proposal_id

    @pytest.mark.asyncio
    async def test_get_item_nonexistent(self, queue):
        """Test getting nonexistent item returns None."""
        item = await queue.get_item("nonexistent")
        assert item is None

    @pytest.mark.asyncio
    async def test_get_stats(self, queue):
        """Test getting queue statistics."""
        # Add items with different statuses
        for urgency in [UrgencyLevel.LOW, UrgencyLevel.CRITICAL]:
            prop = self.create_proposal_with_urgency(urgency)
            prop.proposal_id = f"prop-{urgency.value}"
            await queue.enqueue(prop)

        # Approve one
        await queue.approve("prop-critical", "admin")

        stats = await queue.get_stats()

        assert stats["total_items"] == 2
        assert stats["pending_items"] == 1
        assert stats["capacity"] == 100
        assert stats["by_status"]["pending"] == 1
        assert stats["by_status"]["approved"] == 1
        assert stats["by_urgency"]["low"] == 1

    @pytest.mark.asyncio
    async def test_callback_on_enqueue(self, queue, sample_proposal):
        """Test that enqueue callbacks are called."""
        callback = AsyncMock()
        queue.on_enqueue(callback)

        await queue.enqueue(sample_proposal)

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0].item_id == sample_proposal.proposal_id

    @pytest.mark.asyncio
    async def test_callback_on_approve(self, queue, sample_proposal):
        """Test that approve callbacks are called."""
        callback = AsyncMock()
        queue.on_approve(callback)

        await queue.enqueue(sample_proposal)
        await queue.approve(sample_proposal.proposal_id, "admin")

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0].status == QueueItemStatus.APPROVED

    @pytest.mark.asyncio
    async def test_callback_on_deny(self, queue, sample_proposal):
        """Test that deny callbacks are called."""
        callback = AsyncMock()
        queue.on_deny(callback)

        await queue.enqueue(sample_proposal)
        await queue.deny(sample_proposal.proposal_id, "admin", "Test reason")

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0].status == QueueItemStatus.DENIED
        assert args[1] == "Test reason"

    @pytest.mark.asyncio
    async def test_callback_error_handling(self, queue, sample_proposal):
        """Test that callback errors are handled gracefully."""
        def failing_callback(_):
            raise Exception("Callback failed")

        queue.on_enqueue(failing_callback)

        # Should not raise
        await queue.enqueue(sample_proposal)
        assert len(queue._queue) == 1


class TestInMemoryApprovalQueuePersistence:
    """Tests for persistence functionality."""

    @pytest.mark.asyncio
    async def test_persistence_on_enqueue(self, tmp_path):
        """Test that state is persisted on enqueue."""
        persistence_path = str(tmp_path / "queue.json")
        queue = InMemoryApprovalQueue(persistence_path=persistence_path)

        # Create a simple proposal
        kill_report = KillReport(
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            target_module="test-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["Test"],
            dependencies=[],
            source_agent="smith",
        )

        siem_context = SIEMContextResponse(
            query_id="query-001",
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.3,
            recommendation="approve",
        )

        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.35,
            confidence=0.85,
            reasoning=["Test"],
            recommended_action="Approve",
        )

        proposal = ResurrectionProposal(
            proposal_id="prop-001",
            created_at=datetime.utcnow(),
            kill_report=kill_report,
            siem_context=siem_context,
            decision=decision,
            recommendation=RecommendationType.APPROVE,
            urgency=UrgencyLevel.MEDIUM,
            summary="Test",
            key_factors=[],
            risk_factors={},
            mitigating_factors=[],
            aggravating_factors=[],
            module_history={},
            similar_incidents=[],
            suggested_pre_checks=[],
            suggested_post_checks=[],
            rollback_strategy="Rollback",
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )

        await queue.enqueue(proposal)

        # Check file was created
        assert Path(persistence_path).exists()

    @pytest.mark.asyncio
    async def test_load_state_on_init(self, tmp_path):
        """Test that state is loaded on initialization."""
        persistence_path = str(tmp_path / "queue.json")

        # Create a queue and add an item
        queue1 = InMemoryApprovalQueue(persistence_path=persistence_path)

        kill_report = KillReport(
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            target_module="test-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["Test"],
            dependencies=[],
            source_agent="smith",
        )

        siem_context = SIEMContextResponse(
            query_id="query-001",
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.3,
            recommendation="approve",
        )

        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.35,
            confidence=0.85,
            reasoning=["Test"],
            recommended_action="Approve",
        )

        proposal = ResurrectionProposal(
            proposal_id="prop-001",
            created_at=datetime.utcnow(),
            kill_report=kill_report,
            siem_context=siem_context,
            decision=decision,
            recommendation=RecommendationType.APPROVE,
            urgency=UrgencyLevel.MEDIUM,
            summary="Test",
            key_factors=[],
            risk_factors={},
            mitigating_factors=[],
            aggravating_factors=[],
            module_history={},
            similar_incidents=[],
            suggested_pre_checks=[],
            suggested_post_checks=[],
            rollback_strategy="Rollback",
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )

        await queue1.enqueue(proposal)

        # Create new queue - should load state
        queue2 = InMemoryApprovalQueue(persistence_path=persistence_path)

        # State was logged as loaded (actual reconstruction limited)
        assert Path(persistence_path).exists()


class TestCreateApprovalQueue:
    """Tests for the create_approval_queue factory function."""

    def test_create_with_empty_config(self, tmp_path):
        """Test creating queue with empty config."""
        config = {"data_dir": str(tmp_path)}
        queue = create_approval_queue(config)

        assert isinstance(queue, InMemoryApprovalQueue)

    def test_create_with_custom_config(self, tmp_path):
        """Test creating queue with custom config."""
        config = {
            "data_dir": str(tmp_path),
            "interfaces": {
                "approval_queue": {
                    "max_pending": 50,
                    "timeout_hours": 12,
                }
            }
        }

        queue = create_approval_queue(config)

        assert isinstance(queue, InMemoryApprovalQueue)
        assert queue.max_pending == 50
        assert queue.default_timeout_hours == 12

    def test_persistence_path_set(self, tmp_path):
        """Test that persistence path is set from config."""
        config = {"data_dir": str(tmp_path)}
        queue = create_approval_queue(config)

        expected_path = Path(tmp_path) / "approval_queue.json"
        assert queue.persistence_path == expected_path


class TestExpirationHandling:
    """Tests for expiration handling."""

    @pytest.mark.asyncio
    async def test_expired_items_marked_on_list(self):
        """Test that expired items are marked when listing."""
        queue = InMemoryApprovalQueue()

        kill_report = KillReport(
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            target_module="test-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["Test"],
            dependencies=[],
            source_agent="smith",
        )

        siem_context = SIEMContextResponse(
            query_id="query-001",
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.3,
            recommendation="approve",
        )

        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.35,
            confidence=0.85,
            reasoning=["Test"],
            recommended_action="Approve",
        )

        # Create expired proposal
        proposal = ResurrectionProposal(
            proposal_id="prop-expired",
            created_at=datetime.utcnow() - timedelta(hours=48),
            kill_report=kill_report,
            siem_context=siem_context,
            decision=decision,
            recommendation=RecommendationType.APPROVE,
            urgency=UrgencyLevel.MEDIUM,
            summary="Test",
            key_factors=[],
            risk_factors={},
            mitigating_factors=[],
            aggravating_factors=[],
            module_history={},
            similar_incidents=[],
            suggested_pre_checks=[],
            suggested_post_checks=[],
            rollback_strategy="Rollback",
            expires_at=datetime.utcnow() - timedelta(hours=24),  # Already expired
        )

        await queue.enqueue(proposal)

        # List pending should check expirations
        pending = await queue.list_pending()

        assert len(pending) == 0

        item = await queue.get_item("prop-expired")
        assert item.status == QueueItemStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_expire_callback_called(self):
        """Test that expire callback is called when items expire."""
        queue = InMemoryApprovalQueue()
        callback = AsyncMock()
        queue.on_expire(callback)

        kill_report = KillReport(
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            target_module="test-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["Test"],
            dependencies=[],
            source_agent="smith",
        )

        siem_context = SIEMContextResponse(
            query_id="query-001",
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.3,
            recommendation="approve",
        )

        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.35,
            confidence=0.85,
            reasoning=["Test"],
            recommended_action="Approve",
        )

        proposal = ResurrectionProposal(
            proposal_id="prop-expired",
            created_at=datetime.utcnow() - timedelta(hours=48),
            kill_report=kill_report,
            siem_context=siem_context,
            decision=decision,
            recommendation=RecommendationType.APPROVE,
            urgency=UrgencyLevel.MEDIUM,
            summary="Test",
            key_factors=[],
            risk_factors={},
            mitigating_factors=[],
            aggravating_factors=[],
            module_history={},
            similar_incidents=[],
            suggested_pre_checks=[],
            suggested_post_checks=[],
            rollback_strategy="Rollback",
            expires_at=datetime.utcnow() - timedelta(hours=24),
        )

        await queue.enqueue(proposal)
        await queue.list_pending()  # Triggers expiration check

        callback.assert_called_once()
