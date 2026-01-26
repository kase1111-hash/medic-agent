"""
Unit tests for the VetoProtocol module.
"""

import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, AsyncMock, MagicMock

from integration.veto_protocol import (
    VetoProtocol,
    VetoConfig,
    VetoRequest,
    VetoResponse,
    VetoDecision,
    VetoReason,
    VetoStatistics,
    create_veto_protocol,
)
from core.models import KillReason, Severity


class TestVetoEnums:
    """Tests for veto enums."""

    def test_veto_decision_values(self):
        """Test VetoDecision enum values."""
        assert VetoDecision.APPROVE_KILL.value == "approve_kill"
        assert VetoDecision.VETO.value == "veto"
        assert VetoDecision.DELAY.value == "delay"
        assert VetoDecision.CONDITIONAL.value == "conditional"

    def test_veto_reason_values(self):
        """Test VetoReason enum values."""
        assert VetoReason.HIGH_FALSE_POSITIVE_HISTORY.value == "high_fp_history"
        assert VetoReason.RECENT_SUCCESSFUL_RESURRECTION.value == "recent_resurrection"
        assert VetoReason.LOW_RISK_ASSESSMENT.value == "low_risk"
        assert VetoReason.CRITICAL_DEPENDENCY.value == "critical_dependency"


class TestVetoRequest:
    """Tests for VetoRequest dataclass."""

    def test_create_request(self):
        """Test creating a VetoRequest instance."""
        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-001",
            module="test-service",
            instance_id="instance-001",
            kill_reason=KillReason.THREAT_DETECTED,
            severity=Severity.HIGH,
            smith_confidence=0.85,
            evidence=["Suspicious network traffic"],
            dependencies=["database", "cache"],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        assert request.request_id == "req-001"
        assert request.module == "test-service"
        assert request.smith_confidence == 0.85

    def test_to_dict(self):
        """Test serializing request to dict."""
        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-001",
            module="api-service",
            instance_id="instance-002",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            smith_confidence=0.7,
            evidence=["High CPU"],
            dependencies=[],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        data = request.to_dict()

        assert data["request_id"] == "req-001"
        assert data["kill_reason"] == "anomaly_behavior"
        assert data["severity"] == "medium"
        assert data["smith_confidence"] == 0.7


class TestVetoResponse:
    """Tests for VetoResponse dataclass."""

    def test_create_response(self):
        """Test creating a VetoResponse instance."""
        response = VetoResponse(
            request_id="req-001",
            decision=VetoDecision.VETO,
            veto_reasons=[VetoReason.HIGH_FALSE_POSITIVE_HISTORY],
            medic_confidence=0.85,
            explanation="High FP history suggests this is a false positive",
        )

        assert response.request_id == "req-001"
        assert response.decision == VetoDecision.VETO
        assert len(response.veto_reasons) == 1

    def test_to_dict(self):
        """Test serializing response to dict."""
        response = VetoResponse(
            request_id="req-001",
            decision=VetoDecision.DELAY,
            veto_reasons=[VetoReason.LOW_RISK_ASSESSMENT],
            medic_confidence=0.65,
            explanation="Need more time to analyze",
            delay_seconds=30,
        )

        data = response.to_dict()

        assert data["decision"] == "delay"
        assert "low_risk" in data["veto_reasons"]
        assert data["medic_confidence"] == 0.65
        assert data["delay_seconds"] == 30


class TestVetoConfig:
    """Tests for VetoConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = VetoConfig()

        assert config.enabled is True
        assert config.default_timeout_seconds == 30
        assert config.max_vetos_per_hour == 10
        assert config.veto_cooldown_seconds == 300
        assert config.min_fp_history_for_veto == 3
        assert config.max_risk_for_veto == 0.3

    def test_custom_values(self):
        """Test custom configuration values."""
        config = VetoConfig(
            enabled=False,
            max_vetos_per_hour=5,
            veto_cooldown_seconds=600,
        )

        assert config.enabled is False
        assert config.max_vetos_per_hour == 5
        assert config.veto_cooldown_seconds == 600


class TestVetoStatistics:
    """Tests for VetoStatistics dataclass."""

    def test_create_statistics(self):
        """Test creating VetoStatistics instance."""
        stats = VetoStatistics(
            total_requests=100,
            approved_kills=70,
            vetoed_kills=20,
            delayed_kills=10,
            veto_rate=0.2,
            avg_response_time_ms=15.5,
        )

        assert stats.total_requests == 100
        assert stats.vetoed_kills == 20
        assert stats.veto_rate == 0.2

    def test_to_dict(self):
        """Test serializing statistics to dict."""
        stats = VetoStatistics(
            total_requests=50,
            approved_kills=40,
            vetoed_kills=5,
            delayed_kills=5,
            veto_rate=0.1,
            avg_response_time_ms=12.345,
        )

        data = stats.to_dict()

        assert data["total_requests"] == 50
        assert data["veto_rate"] == 0.1
        assert data["avg_response_time_ms"] == 12.3


class TestVetoProtocol:
    """Tests for VetoProtocol."""

    @pytest.fixture
    def protocol(self):
        """Create a VetoProtocol with default config."""
        return VetoProtocol()

    @pytest.fixture
    def disabled_protocol(self):
        """Create a disabled VetoProtocol."""
        config = VetoConfig(enabled=False)
        return VetoProtocol(config=config)

    @pytest.fixture
    def sample_request(self):
        """Create a sample veto request."""
        now = datetime.now(timezone.utc)
        return VetoRequest(
            request_id="req-001",
            module="test-service",
            instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            smith_confidence=0.75,
            evidence=["High CPU usage"],
            dependencies=["database"],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

    def test_initialization(self, protocol):
        """Test VetoProtocol initialization."""
        assert protocol.config.enabled is True
        assert len(protocol._pending_requests) == 0
        assert len(protocol._request_history) == 0

    @pytest.mark.asyncio
    async def test_handle_veto_request_disabled(self, disabled_protocol, sample_request):
        """Test that disabled protocol approves all kills."""
        response = await disabled_protocol.handle_veto_request(sample_request)

        assert response.decision == VetoDecision.APPROVE_KILL
        assert "disabled" in response.explanation.lower()

    @pytest.mark.asyncio
    async def test_handle_veto_request_high_confidence(self, protocol):
        """Test that high Smith confidence results in approval."""
        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-high-conf",
            module="test-service",
            instance_id="instance-001",
            kill_reason=KillReason.THREAT_DETECTED,
            severity=Severity.CRITICAL,
            smith_confidence=0.95,  # High confidence
            evidence=["Known malware signature"],
            dependencies=[],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        response = await protocol.handle_veto_request(request)

        assert response.decision == VetoDecision.APPROVE_KILL
        assert "high" in response.explanation.lower()

    @pytest.mark.asyncio
    async def test_handle_veto_request_with_fp_history(self, protocol):
        """Test that high FP history triggers veto."""
        # Mock outcome store with FP history
        mock_outcome = MagicMock()
        mock_outcome.outcome_type.value = "false_positive"
        mock_outcome.timestamp = datetime.now(timezone.utc)

        mock_store = MagicMock()
        mock_store.get_outcomes_by_module.return_value = [mock_outcome] * 5

        protocol.outcome_store = mock_store

        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-fp-history",
            module="known-fp-service",
            instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            smith_confidence=0.6,
            evidence=["Unusual behavior"],
            dependencies=[],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        response = await protocol.handle_veto_request(request)

        # Should delay or veto due to FP history
        assert response.decision in (VetoDecision.VETO, VetoDecision.DELAY)
        assert VetoReason.HIGH_FALSE_POSITIVE_HISTORY in response.veto_reasons

    @pytest.mark.asyncio
    async def test_handle_veto_request_with_critical_dependencies(self, protocol):
        """Test that critical dependencies affect decision."""
        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-deps",
            module="critical-service",
            instance_id="instance-001",
            kill_reason=KillReason.POLICY_VIOLATION,
            severity=Severity.MEDIUM,
            smith_confidence=0.7,
            evidence=["Policy violation detected"],
            dependencies=["service-1", "service-2", "service-3", "service-4", "service-5", "service-6"],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        response = await protocol.handle_veto_request(request)

        # Should delay due to many dependencies
        assert response.decision in (VetoDecision.DELAY, VetoDecision.CONDITIONAL)

    @pytest.mark.asyncio
    async def test_rate_limiting_global(self, protocol):
        """Test global rate limiting for vetos."""
        # Exhaust veto limit
        protocol._vetos_this_hour = [datetime.now(timezone.utc)] * protocol.config.max_vetos_per_hour

        # Mock high FP history to trigger potential veto
        mock_outcome = MagicMock()
        mock_outcome.outcome_type.value = "false_positive"
        mock_outcome.timestamp = datetime.now(timezone.utc)

        mock_store = MagicMock()
        mock_store.get_outcomes_by_module.return_value = [mock_outcome] * 10

        protocol.outcome_store = mock_store

        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-limited",
            module="test-service",
            instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            smith_confidence=0.5,
            evidence=["Test"],
            dependencies=[],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        response = await protocol.handle_veto_request(request)

        # Should approve due to rate limit
        assert response.decision == VetoDecision.APPROVE_KILL
        assert "would_have_vetoed" in str(response.conditions)

    @pytest.mark.asyncio
    async def test_rate_limiting_per_module(self, protocol):
        """Test per-module cooldown."""
        module = "cooldown-service"
        protocol._last_veto_by_module[module] = datetime.now(timezone.utc)

        # Mock FP history
        mock_outcome = MagicMock()
        mock_outcome.outcome_type.value = "false_positive"
        mock_outcome.timestamp = datetime.now(timezone.utc)

        mock_store = MagicMock()
        mock_store.get_outcomes_by_module.return_value = [mock_outcome] * 10

        protocol.outcome_store = mock_store

        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-cooldown",
            module=module,
            instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            smith_confidence=0.5,
            evidence=["Test"],
            dependencies=[],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        response = await protocol.handle_veto_request(request)

        # Should approve due to cooldown
        assert response.decision == VetoDecision.APPROVE_KILL

    @pytest.mark.asyncio
    async def test_veto_callback(self, protocol, sample_request):
        """Test that veto callback is called."""
        callback = AsyncMock()
        protocol.on_veto_decision = callback

        await protocol.handle_veto_request(sample_request)

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0] == sample_request
        assert isinstance(args[1], VetoResponse)

    @pytest.mark.asyncio
    async def test_veto_callback_error_handling(self, protocol, sample_request):
        """Test that callback errors are handled gracefully."""
        async def failing_callback(*args):
            raise Exception("Callback failed")

        protocol.on_veto_decision = failing_callback

        # Should not raise
        response = await protocol.handle_veto_request(sample_request)
        assert response is not None

    @pytest.mark.asyncio
    async def test_response_time_tracking(self, protocol, sample_request):
        """Test that response times are tracked."""
        await protocol.handle_veto_request(sample_request)

        assert len(protocol._response_times) == 1
        assert protocol._response_times[0] > 0

    @pytest.mark.asyncio
    async def test_history_tracking(self, protocol, sample_request):
        """Test that request history is tracked."""
        await protocol.handle_veto_request(sample_request)

        assert len(protocol._request_history) == 1
        req, resp = protocol._request_history[0]
        assert req.request_id == sample_request.request_id

    @pytest.mark.asyncio
    async def test_history_limit(self, protocol):
        """Test that history is limited to prevent memory issues."""
        # Create many requests
        for i in range(600):
            now = datetime.now(timezone.utc)
            request = VetoRequest(
                request_id=f"req-{i}",
                module="test-service",
                instance_id="instance-001",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.MEDIUM,
                smith_confidence=0.95,
                evidence=["Test"],
                dependencies=[],
                received_at=now,
                deadline=now + timedelta(seconds=30),
            )
            await protocol.handle_veto_request(request)

        assert len(protocol._request_history) <= 500

    def test_get_pending_requests(self, protocol):
        """Test getting pending requests."""
        pending = protocol.get_pending_requests()
        assert pending == []

    @pytest.mark.asyncio
    async def test_get_statistics(self, protocol):
        """Test getting veto statistics."""
        # Create some requests
        for i in range(5):
            now = datetime.now(timezone.utc)
            request = VetoRequest(
                request_id=f"req-stats-{i}",
                module="test-service",
                instance_id="instance-001",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.MEDIUM,
                smith_confidence=0.95,
                evidence=["Test"],
                dependencies=[],
                received_at=now,
                deadline=now + timedelta(seconds=30),
            )
            await protocol.handle_veto_request(request)

        stats = protocol.get_statistics()

        assert stats.total_requests == 5
        assert stats.avg_response_time_ms > 0

    def test_get_statistics_empty(self, protocol):
        """Test statistics with no requests."""
        stats = protocol.get_statistics()

        assert stats.total_requests == 0
        assert stats.veto_rate == 0.0
        assert stats.avg_response_time_ms == 0.0

    @pytest.mark.asyncio
    async def test_get_history(self, protocol):
        """Test getting veto history."""
        for i in range(3):
            now = datetime.now(timezone.utc)
            request = VetoRequest(
                request_id=f"req-hist-{i}",
                module="test-service",
                instance_id="instance-001",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.MEDIUM,
                smith_confidence=0.95,
                evidence=["Test"],
                dependencies=[],
                received_at=now,
                deadline=now + timedelta(seconds=30),
            )
            await protocol.handle_veto_request(request)

        history = protocol.get_history(limit=2)

        assert len(history) == 2
        # Most recent first
        assert history[0][0].request_id == "req-hist-2"

    @pytest.mark.asyncio
    async def test_get_history_filtered(self, protocol):
        """Test getting filtered veto history."""
        # Create requests that will be approved (high Smith confidence)
        for i in range(3):
            now = datetime.now(timezone.utc)
            request = VetoRequest(
                request_id=f"req-filt-{i}",
                module="test-service",
                instance_id="instance-001",
                kill_reason=KillReason.THREAT_DETECTED,
                severity=Severity.CRITICAL,
                smith_confidence=0.99,
                evidence=["Confirmed threat"],
                dependencies=[],
                received_at=now,
                deadline=now + timedelta(seconds=30),
            )
            await protocol.handle_veto_request(request)

        approved = protocol.get_history(decision=VetoDecision.APPROVE_KILL)

        assert len(approved) == 3


class TestCreateVetoProtocol:
    """Tests for the create_veto_protocol factory function."""

    def test_create_with_empty_config(self):
        """Test creating protocol with empty config."""
        protocol = create_veto_protocol({})

        assert isinstance(protocol, VetoProtocol)
        assert protocol.config.enabled is False  # Default from factory

    def test_create_with_custom_config(self):
        """Test creating protocol with custom config."""
        config = {
            "smith": {
                "veto_protocol": {
                    "enabled": True,
                    "timeout_seconds": 60,
                    "max_vetos_per_hour": 20,
                    "cooldown_seconds": 600,
                    "min_fp_for_veto": 5,
                    "max_risk_for_veto": 0.2,
                }
            }
        }

        protocol = create_veto_protocol(config)

        assert protocol.config.enabled is True
        assert protocol.config.default_timeout_seconds == 60
        assert protocol.config.max_vetos_per_hour == 20
        assert protocol.config.veto_cooldown_seconds == 600
        assert protocol.config.min_fp_history_for_veto == 5
        assert protocol.config.max_risk_for_veto == 0.2

    def test_create_with_dependencies(self):
        """Test creating protocol with dependencies."""
        mock_engine = Mock()
        mock_store = Mock()
        mock_callback = Mock()

        protocol = create_veto_protocol(
            {},
            decision_engine=mock_engine,
            outcome_store=mock_store,
            on_veto_decision=mock_callback,
        )

        assert protocol.decision_engine is mock_engine
        assert protocol.outcome_store is mock_store
        assert protocol.on_veto_decision is mock_callback


class TestVetoDecisionLogic:
    """Tests for veto decision logic edge cases."""

    @pytest.fixture
    def protocol_with_mocks(self):
        """Create protocol with mocked dependencies."""
        mock_outcome = MagicMock()
        mock_outcome.outcome_type.value = "false_positive"
        mock_outcome.timestamp = datetime.now(timezone.utc)

        mock_store = MagicMock()
        mock_store.get_outcomes_by_module.return_value = [mock_outcome] * 5

        protocol = VetoProtocol(outcome_store=mock_store)
        return protocol

    @pytest.mark.asyncio
    async def test_multiple_veto_reasons_triggers_veto(self, protocol_with_mocks):
        """Test that multiple veto reasons trigger a veto."""
        protocol = protocol_with_mocks

        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-multi-reason",
            module="test-service",
            instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            smith_confidence=0.3,  # Low confidence = low risk
            evidence=["Minor anomaly"],
            dependencies=["s1", "s2", "s3", "s4", "s5", "s6"],  # Many deps
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        response = await protocol.handle_veto_request(request)

        # Multiple reasons should trigger veto
        assert response.decision == VetoDecision.VETO
        assert len(response.veto_reasons) >= 2

    @pytest.mark.asyncio
    async def test_single_veto_reason_triggers_delay(self, protocol_with_mocks):
        """Test that single veto reason triggers delay."""
        protocol = protocol_with_mocks

        # Set FP history to exactly min_fp_history_for_veto (3) - one veto reason
        mock_outcome = MagicMock()
        mock_outcome.outcome_type.value = "false_positive"
        mock_outcome.timestamp = datetime.now(timezone.utc)
        protocol.outcome_store.get_outcomes_by_module.return_value = [mock_outcome] * 3

        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-single-reason",
            module="test-service",
            instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            smith_confidence=0.85,  # High confidence - no low risk reason
            evidence=["Uncertain behavior"],
            dependencies=[],  # No critical dependency reason
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        response = await protocol.handle_veto_request(request)

        # Single veto reason (FP history) should trigger delay
        assert response.decision == VetoDecision.DELAY
        assert response.delay_seconds is not None
        assert VetoReason.HIGH_FALSE_POSITIVE_HISTORY in response.veto_reasons

    @pytest.mark.asyncio
    async def test_conditional_approval(self):
        """Test conditional approval case."""
        protocol = VetoProtocol()

        now = datetime.now(timezone.utc)
        request = VetoRequest(
            request_id="req-conditional",
            module="test-service",
            instance_id="instance-001",
            kill_reason=KillReason.POLICY_VIOLATION,
            severity=Severity.MEDIUM,
            smith_confidence=0.75,
            evidence=["Policy check failed"],
            dependencies=[],
            received_at=now,
            deadline=now + timedelta(seconds=30),
        )

        response = await protocol.handle_veto_request(request)

        # Should be conditional approval
        assert response.decision == VetoDecision.CONDITIONAL
        assert response.conditions is not None
        assert "monitor_after_kill" in response.conditions
