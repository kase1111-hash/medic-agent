"""
Unit tests for the SmithNegotiator module.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from integration.smith_negotiator import (
    SmithNegotiator,
    SmithConnection,
    Negotiation,
    NegotiationMessage,
    NegotiationType,
    NegotiationState,
    NegotiationOutcome,
    create_smith_negotiator,
)
from core.models import KillReport, KillReason, Severity


class TestNegotiationEnums:
    """Tests for negotiation enums."""

    def test_negotiation_state_values(self):
        """Test NegotiationState enum values."""
        assert NegotiationState.INITIATED.value == "initiated"
        assert NegotiationState.AWAITING_RESPONSE.value == "awaiting_response"
        assert NegotiationState.AGREED.value == "agreed"
        assert NegotiationState.DISAGREED.value == "disagreed"
        assert NegotiationState.TIMEOUT.value == "timeout"

    def test_negotiation_type_values(self):
        """Test NegotiationType enum values."""
        assert NegotiationType.PRE_KILL_CONSULTATION.value == "pre_kill_consultation"
        assert NegotiationType.POST_KILL_APPEAL.value == "post_kill_appeal"
        assert NegotiationType.RESURRECTION_CLEARANCE.value == "resurrection_clearance"
        assert NegotiationType.THRESHOLD_DISCUSSION.value == "threshold_discussion"

    def test_negotiation_outcome_values(self):
        """Test NegotiationOutcome enum values."""
        assert NegotiationOutcome.APPROVED.value == "approved"
        assert NegotiationOutcome.DENIED.value == "denied"
        assert NegotiationOutcome.CONDITIONAL.value == "conditional"
        assert NegotiationOutcome.NO_RESPONSE.value == "no_response"


class TestNegotiationMessage:
    """Tests for NegotiationMessage dataclass."""

    def test_create_message(self):
        """Test creating a NegotiationMessage instance."""
        now = datetime.utcnow()
        msg = NegotiationMessage(
            message_id="msg-001",
            sender="medic",
            timestamp=now,
            message_type="request",
            content={"action": "query"},
        )

        assert msg.message_id == "msg-001"
        assert msg.sender == "medic"
        assert msg.message_type == "request"

    def test_to_dict(self):
        """Test serializing message to dict."""
        now = datetime.utcnow()
        msg = NegotiationMessage(
            message_id="msg-001",
            sender="smith",
            timestamp=now,
            message_type="response",
            content={"status": "approved"},
        )

        data = msg.to_dict()

        assert data["message_id"] == "msg-001"
        assert data["sender"] == "smith"
        assert data["content"]["status"] == "approved"


class TestNegotiation:
    """Tests for Negotiation dataclass."""

    def test_create_negotiation(self):
        """Test creating a Negotiation instance."""
        now = datetime.utcnow()
        neg = Negotiation(
            negotiation_id="neg-001",
            negotiation_type=NegotiationType.RESURRECTION_CLEARANCE,
            state=NegotiationState.INITIATED,
            initiated_at=now,
            initiated_by="medic",
            subject={"module": "test-service"},
        )

        assert neg.negotiation_id == "neg-001"
        assert neg.negotiation_type == NegotiationType.RESURRECTION_CLEARANCE
        assert neg.state == NegotiationState.INITIATED
        assert neg.outcome is None

    def test_to_dict(self):
        """Test serializing negotiation to dict."""
        now = datetime.utcnow()
        neg = Negotiation(
            negotiation_id="neg-001",
            negotiation_type=NegotiationType.PRE_KILL_CONSULTATION,
            state=NegotiationState.AGREED,
            initiated_at=now,
            initiated_by="smith",
            subject={"module": "api-service"},
            outcome=NegotiationOutcome.APPROVED,
            completed_at=now,
        )

        data = neg.to_dict()

        assert data["negotiation_id"] == "neg-001"
        assert data["negotiation_type"] == "pre_kill_consultation"
        assert data["state"] == "agreed"
        assert data["outcome"] == "approved"


class TestSmithConnection:
    """Tests for SmithConnection dataclass."""

    def test_default_values(self):
        """Test default connection values."""
        conn = SmithConnection()

        assert conn.endpoint == "redis://localhost:6379"
        assert conn.request_topic == "medic.to_smith"
        assert conn.response_topic == "smith.to_medic"
        assert conn.timeout_seconds == 30
        assert conn.enabled is True

    def test_custom_values(self):
        """Test custom connection values."""
        conn = SmithConnection(
            endpoint="redis://smith-server:6380",
            timeout_seconds=60,
            enabled=False,
        )

        assert conn.endpoint == "redis://smith-server:6380"
        assert conn.timeout_seconds == 60
        assert conn.enabled is False


class TestSmithNegotiator:
    """Tests for SmithNegotiator."""

    @pytest.fixture
    def negotiator(self):
        """Create a SmithNegotiator with disabled connection for testing."""
        conn = SmithConnection(enabled=False)
        return SmithNegotiator(connection=conn)

    @pytest.fixture
    def enabled_negotiator(self):
        """Create a SmithNegotiator with enabled connection."""
        conn = SmithConnection(enabled=True)
        return SmithNegotiator(connection=conn)

    @pytest.fixture
    def sample_kill_report(self):
        """Create a sample kill report."""
        return KillReport(
            kill_id="kill-001",
            timestamp=datetime.utcnow(),
            target_module="test-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["High CPU usage"],
            dependencies=["database"],
            source_agent="smith-agent",
        )

    def test_initialization(self, negotiator):
        """Test SmithNegotiator initialization."""
        assert negotiator.connection is not None
        assert negotiator.connection.enabled is False
        assert len(negotiator._negotiations) == 0
        assert negotiator._stats["total_negotiations"] == 0

    @pytest.mark.asyncio
    async def test_request_pre_kill_consultation(self, negotiator):
        """Test requesting pre-kill consultation."""
        negotiation = await negotiator.request_pre_kill_consultation(
            module="test-service",
            kill_reason=KillReason.THREAT_DETECTED,
            smith_confidence=0.9,
            medic_assessment={
                "risk_score": 0.3,
                "recommendation": "approve",
                "fp_history": 5,
            },
        )

        assert negotiation is not None
        assert negotiation.negotiation_type == NegotiationType.PRE_KILL_CONSULTATION
        assert negotiation.outcome == NegotiationOutcome.APPROVED  # Mock response
        assert len(negotiation.messages) >= 1

    @pytest.mark.asyncio
    async def test_appeal_kill_decision(self, negotiator, sample_kill_report):
        """Test appealing a kill decision."""
        negotiation = await negotiator.appeal_kill_decision(
            kill_report=sample_kill_report,
            appeal_reason="Module was incorrectly identified as threat",
            evidence={"fp_rate": 0.4, "historical_success": 0.95},
        )

        assert negotiation is not None
        assert negotiation.negotiation_type == NegotiationType.POST_KILL_APPEAL
        assert negotiation.subject["kill_id"] == "kill-001"
        assert negotiation.subject["appeal_reason"] == "Module was incorrectly identified as threat"

    @pytest.mark.asyncio
    async def test_request_resurrection_clearance(self, negotiator):
        """Test requesting resurrection clearance."""
        negotiation = await negotiator.request_resurrection_clearance(
            module="test-service",
            kill_id="kill-001",
            resurrection_reason="Module is critical for operations",
            risk_assessment={"risk_score": 0.2, "confidence": 0.9},
        )

        assert negotiation is not None
        assert negotiation.negotiation_type == NegotiationType.RESURRECTION_CLEARANCE
        assert negotiation.subject["module"] == "test-service"
        assert negotiation.outcome == NegotiationOutcome.APPROVED

    @pytest.mark.asyncio
    async def test_query_module_status(self, negotiator):
        """Test querying module status."""
        status = await negotiator.query_module_status("test-service")

        assert status is not None
        assert "mock" in status or "status" in status

    @pytest.mark.asyncio
    async def test_negotiate_thresholds(self, negotiator):
        """Test threshold negotiation."""
        negotiation = await negotiator.negotiate_thresholds(
            proposed_thresholds={
                "auto_approve_max_score": 0.35,
                "auto_approve_min_confidence": 0.9,
            },
            justification="Based on historical performance",
        )

        assert negotiation is not None
        assert negotiation.negotiation_type == NegotiationType.THRESHOLD_DISCUSSION
        assert "proposed_thresholds" in negotiation.subject

    @pytest.mark.asyncio
    async def test_negotiation_with_custom_sender(self):
        """Test negotiation with custom message sender."""
        mock_sender = AsyncMock(return_value={"status": "approved", "details": "test"})
        conn = SmithConnection(enabled=True, timeout_seconds=5)
        negotiator = SmithNegotiator(connection=conn, message_sender=mock_sender)

        negotiation = await negotiator.request_resurrection_clearance(
            module="test-service",
            kill_id="kill-001",
            resurrection_reason="Test",
            risk_assessment={"risk_score": 0.2, "confidence": 0.9},
        )

        mock_sender.assert_called_once()
        assert negotiation.outcome == NegotiationOutcome.APPROVED

    @pytest.mark.asyncio
    async def test_negotiation_timeout(self):
        """Test negotiation timeout handling."""
        async def slow_sender(*args, **kwargs):
            await asyncio.sleep(10)
            return {"status": "approved"}

        conn = SmithConnection(enabled=True, timeout_seconds=0.1)
        negotiator = SmithNegotiator(connection=conn, message_sender=slow_sender)

        negotiation = await negotiator.request_resurrection_clearance(
            module="test-service",
            kill_id="kill-001",
            resurrection_reason="Test",
            risk_assessment={"risk_score": 0.2},
        )

        assert negotiation.state == NegotiationState.TIMEOUT
        assert negotiation.outcome == NegotiationOutcome.NO_RESPONSE
        assert negotiator._stats["timeouts"] == 1

    @pytest.mark.asyncio
    async def test_process_response_approved(self, negotiator):
        """Test processing approved response."""
        now = datetime.utcnow()
        neg = Negotiation(
            negotiation_id="neg-001",
            negotiation_type=NegotiationType.RESURRECTION_CLEARANCE,
            state=NegotiationState.AWAITING_RESPONSE,
            initiated_at=now,
            initiated_by="medic",
            subject={"module": "test"},
        )

        negotiator._process_response(neg, {"status": "approved", "details": "ok"})

        assert neg.state == NegotiationState.AGREED
        assert neg.outcome == NegotiationOutcome.APPROVED

    @pytest.mark.asyncio
    async def test_process_response_denied(self, negotiator):
        """Test processing denied response."""
        now = datetime.utcnow()
        neg = Negotiation(
            negotiation_id="neg-001",
            negotiation_type=NegotiationType.RESURRECTION_CLEARANCE,
            state=NegotiationState.AWAITING_RESPONSE,
            initiated_at=now,
            initiated_by="medic",
            subject={"module": "test"},
        )

        negotiator._process_response(neg, {"status": "denied", "reason": "threat active"})

        assert neg.state == NegotiationState.DISAGREED
        assert neg.outcome == NegotiationOutcome.DENIED

    @pytest.mark.asyncio
    async def test_process_response_conditional(self, negotiator):
        """Test processing conditional response."""
        now = datetime.utcnow()
        neg = Negotiation(
            negotiation_id="neg-001",
            negotiation_type=NegotiationType.RESURRECTION_CLEARANCE,
            state=NegotiationState.AWAITING_RESPONSE,
            initiated_at=now,
            initiated_by="medic",
            subject={"module": "test"},
        )

        negotiator._process_response(neg, {"status": "conditional", "conditions": ["monitor closely"]})

        assert neg.state == NegotiationState.AGREED
        assert neg.outcome == NegotiationOutcome.CONDITIONAL

    @pytest.mark.asyncio
    async def test_process_response_deferred(self, negotiator):
        """Test processing deferred response."""
        now = datetime.utcnow()
        neg = Negotiation(
            negotiation_id="neg-001",
            negotiation_type=NegotiationType.RESURRECTION_CLEARANCE,
            state=NegotiationState.AWAITING_RESPONSE,
            initiated_at=now,
            initiated_by="medic",
            subject={"module": "test"},
        )

        negotiator._process_response(neg, {"status": "defer", "reason": "need more data"})

        assert neg.state == NegotiationState.IN_DISCUSSION
        assert neg.outcome == NegotiationOutcome.DEFERRED

    @pytest.mark.asyncio
    async def test_handle_pre_kill_notification_high_confidence(self, negotiator):
        """Test handling pre-kill notification with high confidence."""
        response = await negotiator.handle_incoming_message({
            "type": "pre_kill_notification",
            "module": "test-service",
            "kill_reason": "threat_detected",
            "confidence": 0.9,
        })

        assert response is not None
        assert response["type"] == "pre_kill_response"
        assert response["medic_position"] == "no_objection"

    @pytest.mark.asyncio
    async def test_handle_pre_kill_notification_low_confidence(self, negotiator):
        """Test handling pre-kill notification with low confidence."""
        response = await negotiator.handle_incoming_message({
            "type": "pre_kill_notification",
            "module": "test-service",
            "kill_reason": "anomaly_behavior",
            "confidence": 0.5,
        })

        assert response is not None
        assert response["medic_position"] == "request_review"

    @pytest.mark.asyncio
    async def test_handle_threshold_proposal(self, negotiator):
        """Test handling threshold proposal from Smith."""
        response = await negotiator.handle_incoming_message({
            "type": "threshold_proposal",
            "proposed_thresholds": {"kill_threshold": 0.8},
        })

        assert response is not None
        assert response["type"] == "threshold_response"
        assert response["medic_response"] == "will_review"

    @pytest.mark.asyncio
    async def test_handle_negotiation_response(self, negotiator):
        """Test handling negotiation response."""
        # First create a negotiation
        negotiation = await negotiator.request_resurrection_clearance(
            module="test-service",
            kill_id="kill-001",
            resurrection_reason="Test",
            risk_assessment={"risk_score": 0.2},
        )

        # Now simulate a late response
        response = await negotiator.handle_incoming_message({
            "type": "negotiation_response",
            "negotiation_id": negotiation.negotiation_id,
            "status": "approved",
        })

        # Response should be None for negotiation responses
        assert response is None

    @pytest.mark.asyncio
    async def test_get_negotiation(self, negotiator):
        """Test getting a negotiation by ID."""
        negotiation = await negotiator.request_resurrection_clearance(
            module="test-service",
            kill_id="kill-001",
            resurrection_reason="Test",
            risk_assessment={"risk_score": 0.2},
        )

        retrieved = negotiator.get_negotiation(negotiation.negotiation_id)

        assert retrieved is not None
        assert retrieved.negotiation_id == negotiation.negotiation_id

    def test_get_negotiation_nonexistent(self, negotiator):
        """Test getting nonexistent negotiation returns None."""
        result = negotiator.get_negotiation("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_active_negotiations(self, negotiator):
        """Test getting active negotiations."""
        # Create some negotiations
        await negotiator.request_resurrection_clearance(
            module="service-1",
            kill_id="kill-001",
            resurrection_reason="Test",
            risk_assessment={"risk_score": 0.2},
        )

        # All completed (mock response), so none active
        active = negotiator.get_active_negotiations()
        assert len(active) == 0

    @pytest.mark.asyncio
    async def test_get_history(self, negotiator):
        """Test getting negotiation history."""
        for i in range(3):
            await negotiator.request_resurrection_clearance(
                module=f"service-{i}",
                kill_id=f"kill-{i}",
                resurrection_reason="Test",
                risk_assessment={"risk_score": 0.2},
            )

        history = negotiator.get_history(limit=2)

        assert len(history) == 2
        # Most recent first
        assert "service-2" in history[0].subject["module"]

    @pytest.mark.asyncio
    async def test_get_statistics(self, negotiator):
        """Test getting negotiation statistics."""
        # Create successful negotiation
        await negotiator.request_resurrection_clearance(
            module="test-service",
            kill_id="kill-001",
            resurrection_reason="Test",
            risk_assessment={"risk_score": 0.2},
        )

        stats = negotiator.get_statistics()

        assert stats["total_negotiations"] == 1
        assert stats["successful"] == 1
        assert stats["active_negotiations"] == 0
        assert stats["success_rate"] == 1.0


class TestCreateSmithNegotiator:
    """Tests for the create_smith_negotiator factory function."""

    def test_create_with_empty_config(self):
        """Test creating negotiator with empty config."""
        negotiator = create_smith_negotiator({})

        assert isinstance(negotiator, SmithNegotiator)
        assert negotiator.connection.enabled is True

    def test_create_with_custom_config(self):
        """Test creating negotiator with custom config."""
        config = {
            "smith": {
                "event_bus": {
                    "host": "redis://custom-host:6380",
                },
                "negotiation": {
                    "request_topic": "custom.request",
                    "response_topic": "custom.response",
                    "timeout_seconds": 60,
                    "enabled": False,
                },
            }
        }

        negotiator = create_smith_negotiator(config)

        assert negotiator.connection.request_topic == "custom.request"
        assert negotiator.connection.response_topic == "custom.response"
        assert negotiator.connection.timeout_seconds == 60
        assert negotiator.connection.enabled is False

    def test_create_with_message_sender(self):
        """Test creating negotiator with custom message sender."""
        mock_sender = AsyncMock()

        negotiator = create_smith_negotiator({}, message_sender=mock_sender)

        assert negotiator.message_sender is mock_sender


class TestNegotiationStats:
    """Tests for negotiation statistics tracking."""

    @pytest.mark.asyncio
    async def test_stats_increment_on_success(self):
        """Test that stats increment on successful negotiation."""
        conn = SmithConnection(enabled=False)
        negotiator = SmithNegotiator(connection=conn)

        await negotiator.request_resurrection_clearance(
            module="test",
            kill_id="kill-001",
            resurrection_reason="Test",
            risk_assessment={"risk_score": 0.2},
        )

        assert negotiator._stats["total_negotiations"] == 1
        assert negotiator._stats["successful"] == 1
        assert negotiator._stats["failed"] == 0

    @pytest.mark.asyncio
    async def test_stats_increment_on_timeout(self):
        """Test that stats increment on timeout."""
        async def slow_sender(*args, **kwargs):
            await asyncio.sleep(10)
            return {}

        conn = SmithConnection(enabled=True, timeout_seconds=0.1)
        negotiator = SmithNegotiator(connection=conn, message_sender=slow_sender)

        await negotiator.request_resurrection_clearance(
            module="test",
            kill_id="kill-001",
            resurrection_reason="Test",
            risk_assessment={"risk_score": 0.2},
        )

        assert negotiator._stats["timeouts"] == 1
        assert negotiator._stats["failed"] == 1

    @pytest.mark.asyncio
    async def test_success_rate_calculation(self):
        """Test success rate calculation."""
        conn = SmithConnection(enabled=False)
        negotiator = SmithNegotiator(connection=conn)

        # Create 4 negotiations (all succeed with mock)
        for i in range(4):
            await negotiator.request_resurrection_clearance(
                module=f"test-{i}",
                kill_id=f"kill-{i}",
                resurrection_reason="Test",
                risk_assessment={"risk_score": 0.2},
            )

        stats = negotiator.get_statistics()

        assert stats["total_negotiations"] == 4
        assert stats["success_rate"] == 1.0

    def test_success_rate_zero_negotiations(self):
        """Test success rate with zero negotiations."""
        conn = SmithConnection(enabled=False)
        negotiator = SmithNegotiator(connection=conn)

        stats = negotiator.get_statistics()

        assert stats["success_rate"] == 0.0
