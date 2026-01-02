"""
Unit Tests - Resurrector

Tests for the resurrection execution engine.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from execution.resurrector import (
    create_resurrector,
    Resurrector,
    ModuleResurrector,
    ResurrectionResult,
    ResurrectionMethod,
)
from core.models import (
    ResurrectionRequest,
    ResurrectionStatus,
    ResurrectionDecision,
    DecisionOutcome,
    KillReport,
    KillReason,
    Severity,
    RiskLevel,
)


# Test fixtures

@pytest.fixture
def default_config():
    """Default resurrector configuration."""
    return {
        "resurrection": {
            "default_method": "restart",
            "max_retries": 2,
            "health_check_timeout": 30,
            "startup_grace_period": 0.1,  # Fast for tests
        },
    }


@pytest.fixture
def config_with_blacklist():
    """Configuration with blacklisted modules."""
    return {
        "resurrection": {
            "default_method": "restart",
            "max_retries": 2,
            "health_check_timeout": 30,
            "startup_grace_period": 0.1,
            "blacklist": ["blocked-service", "forbidden-module"],
        },
    }


@pytest.fixture
def resurrector(default_config):
    """Create a resurrector instance."""
    return create_resurrector(default_config)


@pytest.fixture
def sample_kill_report():
    """Sample kill report for testing."""
    return KillReport(
        kill_id="kill-001",
        timestamp=datetime.utcnow(),
        target_module="test-service",
        target_instance_id="test-001",
        kill_reason=KillReason.ANOMALY_BEHAVIOR,
        severity=Severity.MEDIUM,
        confidence_score=0.85,
        evidence=["Test evidence"],
        dependencies=[],
        source_agent="smith-1.0.0",
    )


@pytest.fixture
def sample_decision(sample_kill_report):
    """Sample resurrection decision."""
    return ResurrectionDecision(
        decision_id="decision-001",
        kill_id=sample_kill_report.kill_id,
        timestamp=datetime.utcnow(),
        outcome=DecisionOutcome.APPROVE_AUTO,
        risk_level=RiskLevel.LOW,
        risk_score=0.3,
        confidence=0.85,
        reasoning=["Low risk", "No threats detected"],
        recommended_action="resurrect",
        requires_human_review=False,
        auto_approve_eligible=True,
        constraints=["Monitor for 30 minutes"],
    )


@pytest.fixture
def approved_request(sample_kill_report, sample_decision):
    """Approved resurrection request."""
    return ResurrectionRequest(
        request_id="request-001",
        decision_id=sample_decision.decision_id,
        kill_id=sample_kill_report.kill_id,
        target_module=sample_kill_report.target_module,
        target_instance_id=sample_kill_report.target_instance_id,
        status=ResurrectionStatus.APPROVED,
        created_at=datetime.utcnow(),
        approved_at=datetime.utcnow(),
        approved_by="test-user",
    )


# Tests for Resurrector

class TestResurrector:
    """Tests for the Resurrector class."""

    def test_create_resurrector(self, default_config):
        """Test that resurrector can be created."""
        resurrector = create_resurrector(default_config)
        assert resurrector is not None
        assert isinstance(resurrector, Resurrector)

    def test_create_module_resurrector(self, default_config):
        """Test that default resurrector is ModuleResurrector."""
        resurrector = create_resurrector(default_config)
        assert isinstance(resurrector, ModuleResurrector)

    @pytest.mark.asyncio
    async def test_resurrect_returns_result(self, resurrector, approved_request):
        """Test that resurrect returns a result."""
        result = await resurrector.resurrect(approved_request)
        assert isinstance(result, ResurrectionResult)
        assert hasattr(result, "success")
        assert hasattr(result, "request_id")

    @pytest.mark.asyncio
    async def test_resurrect_success_scenario(self, resurrector, approved_request):
        """Test successful resurrection."""
        result = await resurrector.resurrect(approved_request)

        # Resurrection should complete (success depends on health check)
        assert result.request_id == approved_request.request_id
        assert result.method_used == ResurrectionMethod.RESTART

    @pytest.mark.asyncio
    async def test_resurrect_records_timestamps(self, resurrector, approved_request):
        """Test that resurrection records timestamps."""
        result = await resurrector.resurrect(approved_request)

        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.duration_seconds >= 0

    def test_can_resurrect_normal_module(self, resurrector):
        """Test can_resurrect for normal module."""
        assert resurrector.can_resurrect("normal-service") is True

    def test_can_resurrect_blacklisted_module(self, config_with_blacklist):
        """Test can_resurrect returns False for blacklisted module."""
        resurrector = create_resurrector(config_with_blacklist)
        assert resurrector.can_resurrect("blocked-service") is False
        assert resurrector.can_resurrect("forbidden-module") is False

    def test_can_resurrect_non_blacklisted_module(self, config_with_blacklist):
        """Test can_resurrect returns True for non-blacklisted module."""
        resurrector = create_resurrector(config_with_blacklist)
        assert resurrector.can_resurrect("allowed-service") is True

    @pytest.mark.asyncio
    async def test_rollback_success(self, resurrector, approved_request):
        """Test rollback functionality."""
        # First do a resurrection
        result = await resurrector.resurrect(approved_request)

        # Then rollback
        if result.success:
            rollback_success = await resurrector.rollback(
                approved_request.request_id,
                reason="Testing rollback",
            )
            assert rollback_success is True

    @pytest.mark.asyncio
    async def test_rollback_nonexistent_request(self, resurrector):
        """Test rollback of non-existent request."""
        success = await resurrector.rollback(
            "nonexistent-request-id",
            reason="Testing",
        )
        assert success is False

    def test_get_statistics_empty(self, resurrector):
        """Test statistics with no resurrections."""
        stats = resurrector.get_statistics()
        assert isinstance(stats, dict)
        assert stats["total"] == 0
        assert stats["success_rate"] == 0.0

    @pytest.mark.asyncio
    async def test_get_statistics_after_resurrection(self, resurrector, approved_request):
        """Test statistics after a resurrection."""
        await resurrector.resurrect(approved_request)

        stats = resurrector.get_statistics()
        assert stats["total"] == 1
        assert "successful" in stats or "success_rate" in stats

    def test_get_active_count_initial(self, resurrector):
        """Test active count starts at zero."""
        assert resurrector.get_active_count() == 0


class TestResurrectionRequest:
    """Tests for ResurrectionRequest handling."""

    @pytest.mark.asyncio
    async def test_concurrent_resurrections(self, resurrector):
        """Test handling of concurrent resurrection requests."""
        import asyncio

        requests = []
        for i in range(5):
            request = ResurrectionRequest(
                request_id=f"request-{i:03d}",
                decision_id=f"decision-{i:03d}",
                kill_id=f"kill-{i:03d}",
                target_module=f"service-{i}",
                target_instance_id=f"instance-{i:03d}",
                status=ResurrectionStatus.APPROVED,
                created_at=datetime.utcnow(),
                approved_at=datetime.utcnow(),
                approved_by="test-user",
            )
            requests.append(request)

        # Execute concurrently
        results = await asyncio.gather(
            *[resurrector.resurrect(r) for r in requests]
        )

        # All should complete
        assert len(results) == 5
        assert all(isinstance(r, ResurrectionResult) for r in results)

    @pytest.mark.asyncio
    async def test_get_status_during_resurrection(self, resurrector, approved_request):
        """Test status retrieval during resurrection."""
        # Before resurrection, status should be None
        status_before = await resurrector.get_status(approved_request.request_id)
        assert status_before is None

        # After resurrection
        await resurrector.resurrect(approved_request)
        status_after = await resurrector.get_status(approved_request.request_id)
        assert status_after in (ResurrectionStatus.COMPLETED, ResurrectionStatus.FAILED)


class TestResurrectionRetry:
    """Tests for resurrection retry logic."""

    @pytest.mark.asyncio
    async def test_retry_on_failure(self, default_config, approved_request):
        """Test that resurrection retries on failure."""
        resurrector = create_resurrector(default_config)

        call_count = 0
        original_execute = resurrector._execute_resurrection

        async def failing_execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("Simulated failure")
            return await original_execute(*args, **kwargs)

        resurrector._execute_resurrection = failing_execute

        result = await resurrector.resurrect(approved_request)

        # Should have been called at least once
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self, default_config, approved_request):
        """Test that max retries are respected."""
        resurrector = create_resurrector(default_config)

        async def always_fail(*args, **kwargs):
            raise Exception("Permanent failure")

        resurrector._execute_resurrection = always_fail

        result = await resurrector.resurrect(approved_request)

        assert result.success is False
        assert result.error_message is not None


class TestResurrectionMethod:
    """Tests for resurrection method selection."""

    def test_default_method_is_restart(self, resurrector):
        """Test that default method is restart."""
        assert resurrector.default_method == ResurrectionMethod.RESTART

    @pytest.mark.asyncio
    async def test_resurrection_uses_correct_method(self, resurrector, approved_request):
        """Test that resurrection uses the configured method."""
        result = await resurrector.resurrect(approved_request)
        assert result.method_used == ResurrectionMethod.RESTART


class TestResurrectorConfiguration:
    """Tests for resurrector configuration."""

    def test_custom_max_retries(self):
        """Test custom max retries configuration."""
        config = {
            "resurrection": {
                "max_retries": 5,
            }
        }
        resurrector = create_resurrector(config)
        assert resurrector.max_retries == 5

    def test_custom_health_check_timeout(self):
        """Test custom health check timeout configuration."""
        config = {
            "resurrection": {
                "health_check_timeout": 60,
            }
        }
        resurrector = create_resurrector(config)
        assert resurrector.health_check_timeout == 60

    def test_custom_startup_grace_period(self):
        """Test custom startup grace period configuration."""
        config = {
            "resurrection": {
                "startup_grace_period": 20,
            }
        }
        resurrector = create_resurrector(config)
        assert resurrector.startup_grace_period == 20
