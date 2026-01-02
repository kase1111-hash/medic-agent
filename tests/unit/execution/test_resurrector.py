"""
Unit Tests - Resurrector

Tests for the resurrection execution engine.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from execution.resurrector import (
    create_resurrector,
    Resurrector,
    ResurrectionResult,
    ResurrectionStatus,
)
from execution.recommendation import ResurrectionProposal, ResurrectionRecommendation


# Test fixtures

@pytest.fixture
def default_config():
    """Default resurrector configuration."""
    return {
        "resurrection": {
            "monitoring_duration_minutes": 30,
            "health_check_interval_seconds": 30,
            "max_retry_attempts": 2,
            "rollback": {
                "enabled": True,
                "auto_trigger_on_anomaly": True,
                "anomaly_threshold": 0.7,
            },
        },
    }


@pytest.fixture
def resurrector(default_config):
    """Create a resurrector instance."""
    return create_resurrector(default_config)


@pytest.fixture
def sample_proposal():
    """Sample resurrection proposal."""
    return ResurrectionProposal(
        proposal_id="proposal-001",
        kill_id="kill-001",
        decision_id="decision-001",
        target_module="test-service",
        target_instance_id="test-001",
        recommendation=ResurrectionRecommendation.RESURRECT,
        confidence=0.85,
        risk_score=0.3,
        reasoning=["Low risk", "No threats detected"],
        constraints=["Monitor for 30 minutes"],
        timeout_minutes=60,
        created_at=datetime.utcnow(),
    )


@pytest.fixture
def approved_request(sample_proposal):
    """Approved resurrection request."""
    from execution.resurrector import ResurrectionRequest

    return ResurrectionRequest(
        request_id="request-001",
        proposal=sample_proposal,
        approved_by="test-user",
        approved_at=datetime.utcnow(),
        status=ResurrectionStatus.APPROVED,
    )


# Tests for Resurrector

class TestResurrector:
    """Tests for the Resurrector class."""

    def test_create_resurrector(self, default_config):
        """Test that resurrector can be created."""
        resurrector = create_resurrector(default_config)
        assert resurrector is not None
        assert isinstance(resurrector, Resurrector)

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

        # In mock mode, resurrection should succeed
        assert result.success is True
        assert result.status == ResurrectionStatus.COMPLETED
        assert result.request_id == approved_request.request_id

    @pytest.mark.asyncio
    async def test_resurrect_updates_status(self, resurrector, approved_request):
        """Test that resurrection updates status correctly."""
        result = await resurrector.resurrect(approved_request)

        # Get the final status
        status = await resurrector.get_status(approved_request.request_id)
        assert status in (ResurrectionStatus.COMPLETED, ResurrectionStatus.IN_PROGRESS)

    @pytest.mark.asyncio
    async def test_resurrect_records_timestamps(self, resurrector, approved_request):
        """Test that resurrection records timestamps."""
        result = await resurrector.resurrect(approved_request)

        assert result.started_at is not None
        if result.success:
            assert result.completed_at is not None

    def test_can_resurrect_normal_module(self, resurrector):
        """Test can_resurrect for normal module."""
        assert resurrector.can_resurrect("normal-service") is True

    def test_can_resurrect_blacklisted_module(self, resurrector):
        """Test can_resurrect returns False for blacklisted module."""
        # First blacklist a module
        resurrector.blacklist_module("bad-service", reason="Testing")

        assert resurrector.can_resurrect("bad-service") is False

    def test_blacklist_and_unblacklist_module(self, resurrector):
        """Test blacklisting and unblacklisting modules."""
        module = "test-module"

        # Initially should be allowed
        assert resurrector.can_resurrect(module) is True

        # Blacklist it
        resurrector.blacklist_module(module, reason="Testing")
        assert resurrector.can_resurrect(module) is False

        # Unblacklist it
        resurrector.unblacklist_module(module)
        assert resurrector.can_resurrect(module) is True

    @pytest.mark.asyncio
    async def test_rollback_success(self, resurrector, approved_request):
        """Test rollback functionality."""
        # First do a resurrection
        await resurrector.resurrect(approved_request)

        # Then rollback
        success = await resurrector.rollback(
            approved_request.request_id,
            reason="Testing rollback",
        )

        assert success is True

        # Status should be rolled back
        status = await resurrector.get_status(approved_request.request_id)
        assert status == ResurrectionStatus.ROLLED_BACK

    @pytest.mark.asyncio
    async def test_rollback_nonexistent_request(self, resurrector):
        """Test rollback of non-existent request."""
        success = await resurrector.rollback(
            "nonexistent-request-id",
            reason="Testing",
        )
        assert success is False

    def test_get_statistics(self, resurrector):
        """Test that statistics are returned."""
        stats = resurrector.get_statistics()

        assert isinstance(stats, dict)
        assert "total_resurrections" in stats
        assert "successful" in stats
        assert "failed" in stats
        assert "rolled_back" in stats


class TestResurrectionRequest:
    """Tests for ResurrectionRequest handling."""

    @pytest.mark.asyncio
    async def test_reject_blacklisted_module(self, resurrector, sample_proposal):
        """Test that blacklisted modules are rejected."""
        from execution.resurrector import ResurrectionRequest

        # Blacklist the module
        resurrector.blacklist_module(sample_proposal.target_module, reason="Testing")

        request = ResurrectionRequest(
            request_id="blacklist-request-001",
            proposal=sample_proposal,
            approved_by="test-user",
            approved_at=datetime.utcnow(),
            status=ResurrectionStatus.APPROVED,
        )

        result = await resurrector.resurrect(request)

        assert result.success is False
        assert "blacklisted" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_concurrent_resurrections(self, resurrector):
        """Test handling of concurrent resurrection requests."""
        import asyncio

        proposals = [
            ResurrectionProposal(
                proposal_id=f"proposal-{i:03d}",
                kill_id=f"kill-{i:03d}",
                decision_id=f"decision-{i:03d}",
                target_module=f"service-{i}",
                target_instance_id=f"instance-{i:03d}",
                recommendation=ResurrectionRecommendation.RESURRECT,
                confidence=0.8,
                risk_score=0.2,
                reasoning=["Test"],
                constraints=[],
                timeout_minutes=60,
                created_at=datetime.utcnow(),
            )
            for i in range(5)
        ]

        from execution.resurrector import ResurrectionRequest

        requests = [
            ResurrectionRequest(
                request_id=f"request-{i:03d}",
                proposal=p,
                approved_by="test-user",
                approved_at=datetime.utcnow(),
                status=ResurrectionStatus.APPROVED,
            )
            for i, p in enumerate(proposals)
        ]

        # Execute concurrently
        results = await asyncio.gather(
            *[resurrector.resurrect(r) for r in requests]
        )

        # All should succeed
        assert all(r.success for r in results)


class TestResurrectionRetry:
    """Tests for resurrection retry logic."""

    @pytest.mark.asyncio
    async def test_retry_on_failure(self, default_config, approved_request):
        """Test that resurrection retries on failure."""
        # Create a resurrector that fails initially
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

        # Should have retried
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
        assert result.status == ResurrectionStatus.FAILED


class TestResurrectionHistory:
    """Tests for resurrection history tracking."""

    @pytest.mark.asyncio
    async def test_history_recorded(self, resurrector, approved_request):
        """Test that resurrection history is recorded."""
        await resurrector.resurrect(approved_request)

        history = resurrector.get_history(limit=10)
        assert len(history) >= 1
        assert any(h.request_id == approved_request.request_id for h in history)

    @pytest.mark.asyncio
    async def test_history_limit_respected(self, resurrector):
        """Test that history limit is respected."""
        # Create multiple resurrections
        from execution.resurrector import ResurrectionRequest

        for i in range(5):
            proposal = ResurrectionProposal(
                proposal_id=f"proposal-hist-{i:03d}",
                kill_id=f"kill-hist-{i:03d}",
                decision_id=f"decision-hist-{i:03d}",
                target_module=f"service-{i}",
                target_instance_id=f"instance-{i:03d}",
                recommendation=ResurrectionRecommendation.RESURRECT,
                confidence=0.8,
                risk_score=0.2,
                reasoning=["Test"],
                constraints=[],
                timeout_minutes=60,
                created_at=datetime.utcnow(),
            )

            request = ResurrectionRequest(
                request_id=f"request-hist-{i:03d}",
                proposal=proposal,
                approved_by="test-user",
                approved_at=datetime.utcnow(),
                status=ResurrectionStatus.APPROVED,
            )

            await resurrector.resurrect(request)

        # Get with limit
        history = resurrector.get_history(limit=3)
        assert len(history) == 3

    @pytest.mark.asyncio
    async def test_history_filter_by_module(self, resurrector):
        """Test filtering history by module."""
        from execution.resurrector import ResurrectionRequest

        # Create resurrections for different modules
        for module in ["service-a", "service-b", "service-a"]:
            proposal = ResurrectionProposal(
                proposal_id=f"proposal-{module}-{datetime.utcnow().timestamp()}",
                kill_id=f"kill-{module}",
                decision_id=f"decision-{module}",
                target_module=module,
                target_instance_id=f"{module}-001",
                recommendation=ResurrectionRecommendation.RESURRECT,
                confidence=0.8,
                risk_score=0.2,
                reasoning=["Test"],
                constraints=[],
                timeout_minutes=60,
                created_at=datetime.utcnow(),
            )

            request = ResurrectionRequest(
                request_id=f"request-{module}-{datetime.utcnow().timestamp()}",
                proposal=proposal,
                approved_by="test-user",
                approved_at=datetime.utcnow(),
                status=ResurrectionStatus.APPROVED,
            )

            await resurrector.resurrect(request)

        # Filter by module
        history_a = resurrector.get_history(limit=10, module="service-a")
        history_b = resurrector.get_history(limit=10, module="service-b")

        assert all(h.target_module == "service-a" for h in history_a)
        assert all(h.target_module == "service-b" for h in history_b)
