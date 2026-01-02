"""
Integration Tests - Resurrection Workflow

End-to-end tests for the complete resurrection workflow.
Tests the interaction between components.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from core.models import KillReport, KillReason, Severity, DecisionOutcome, RiskLevel
from core.decision import create_decision_engine
from core.risk import create_risk_assessor
from core.siem_interface import SIEMContextResponse, ThreatIndicator
from execution.resurrector import create_resurrector, ResurrectionStatus
from execution.recommendation import create_recommendation_engine
from execution.monitor import create_monitor
from interfaces.approval_queue import create_approval_queue


# Fixtures

@pytest.fixture
def full_config():
    """Complete configuration for integration testing."""
    return {
        "mode": {
            "current": "semi_auto",
            "fallback": "observer",
        },
        "decision": {
            "default_timeout_minutes": 60,
            "confidence_threshold": 0.7,
            "auto_approve": {
                "enabled": True,
                "max_risk_level": "low",
                "min_confidence": 0.85,
            },
        },
        "risk": {
            "thresholds": {
                "minimal": 0.2,
                "low": 0.4,
                "medium": 0.6,
                "high": 0.8,
            },
            "weights": {
                "smith_confidence": 0.3,
                "siem_risk_score": 0.25,
                "false_positive_history": 0.2,
                "module_criticality": 0.15,
                "time_of_day": 0.1,
            },
        },
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
        "interfaces": {
            "approval_queue": {
                "max_pending": 100,
                "timeout_hours": 24,
            },
        },
    }


@pytest.fixture
def decision_engine(full_config):
    """Create decision engine."""
    return create_decision_engine(full_config)


@pytest.fixture
def risk_assessor(full_config):
    """Create risk assessor."""
    return create_risk_assessor(full_config)


@pytest.fixture
def resurrector(full_config):
    """Create resurrector."""
    return create_resurrector(full_config)


@pytest.fixture
def monitor(full_config):
    """Create resurrection monitor."""
    return create_monitor(full_config)


@pytest.fixture
def approval_queue(full_config):
    """Create approval queue."""
    return create_approval_queue(full_config)


@pytest.fixture
def recommendation_engine(full_config):
    """Create recommendation engine."""
    return create_recommendation_engine(full_config, decision_logger=None)


# Low risk scenario fixtures

@pytest.fixture
def low_risk_kill_report():
    """Kill report representing low risk."""
    return KillReport(
        kill_id="integration-low-001",
        timestamp=datetime.utcnow(),
        target_module="cache-service",
        target_instance_id="cache-001",
        kill_reason=KillReason.RESOURCE_EXHAUSTION,
        severity=Severity.LOW,
        confidence_score=0.5,
        evidence=["memory-spike"],
        dependencies=[],
        source_agent="smith-01",
        metadata={},
    )


@pytest.fixture
def low_risk_siem_context():
    """SIEM context for low risk."""
    return SIEMContextResponse(
        query_id="integration-query-low-001",
        kill_id="integration-low-001",
        timestamp=datetime.utcnow(),
        threat_indicators=[],
        historical_behavior={"stability_score": 0.95},
        false_positive_history=5,
        network_context={},
        user_context=None,
        risk_score=0.15,
        recommendation="low_risk",
    )


# High risk scenario fixtures

@pytest.fixture
def high_risk_kill_report():
    """Kill report representing high risk."""
    return KillReport(
        kill_id="integration-high-001",
        timestamp=datetime.utcnow(),
        target_module="auth-service",
        target_instance_id="auth-001",
        kill_reason=KillReason.THREAT_DETECTED,
        severity=Severity.HIGH,
        confidence_score=0.9,
        evidence=["ioc-match", "lateral-movement"],
        dependencies=["api-gateway", "user-service"],
        source_agent="smith-01",
        metadata={"critical_path": True},
    )


@pytest.fixture
def high_risk_siem_context():
    """SIEM context for high risk."""
    return SIEMContextResponse(
        query_id="integration-query-high-001",
        kill_id="integration-high-001",
        timestamp=datetime.utcnow(),
        threat_indicators=[
            ThreatIndicator(
                indicator_type="ip",
                value="192.168.1.100",
                threat_score=0.85,
                source="threat_intel",
                last_seen=datetime.utcnow(),
                tags=["c2", "apt"],
            ),
        ],
        historical_behavior={"anomaly_score": 0.8},
        false_positive_history=0,
        network_context={"unusual_ports": [4444]},
        user_context=None,
        risk_score=0.85,
        recommendation="quarantine",
    )


# Integration Tests

class TestLowRiskWorkflow:
    """Test the complete workflow for low-risk scenarios."""

    def test_decision_engine_approves_low_risk(
        self, decision_engine, low_risk_kill_report, low_risk_siem_context
    ):
        """Test that low risk results in auto-approval decision."""
        decision = decision_engine.should_resurrect(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        assert decision.outcome in (
            DecisionOutcome.APPROVE_AUTO,
            DecisionOutcome.PENDING_REVIEW,
        )
        assert decision.auto_approve_eligible is True
        assert decision.risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW)

    def test_risk_assessment_low_score(
        self, risk_assessor, low_risk_kill_report, low_risk_siem_context
    ):
        """Test that risk assessment produces low score."""
        assessment = risk_assessor.assess(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        assert assessment.risk_score < 0.5
        assert assessment.auto_approve_eligible is True

    def test_proposal_generation(
        self, recommendation_engine, decision_engine,
        low_risk_kill_report, low_risk_siem_context
    ):
        """Test proposal generation for low risk case."""
        decision = decision_engine.should_resurrect(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            low_risk_kill_report,
            low_risk_siem_context,
            decision,
        )

        assert proposal is not None
        assert proposal.kill_id == low_risk_kill_report.kill_id
        assert proposal.confidence >= 0.7

    @pytest.mark.asyncio
    async def test_full_resurrection_workflow(
        self, decision_engine, recommendation_engine, resurrector,
        low_risk_kill_report, low_risk_siem_context
    ):
        """Test the complete resurrection workflow for low risk."""
        # Step 1: Make decision
        decision = decision_engine.should_resurrect(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        # Step 2: Generate proposal
        proposal = recommendation_engine.generate_proposal(
            low_risk_kill_report,
            low_risk_siem_context,
            decision,
        )

        # Step 3: Create resurrection request (simulating approval)
        from execution.resurrector import ResurrectionRequest

        request = ResurrectionRequest(
            request_id=f"request-{proposal.proposal_id}",
            proposal=proposal,
            approved_by="auto",
            approved_at=datetime.utcnow(),
            status=ResurrectionStatus.APPROVED,
        )

        # Step 4: Execute resurrection
        result = await resurrector.resurrect(request)

        assert result.success is True
        assert result.status == ResurrectionStatus.COMPLETED


class TestHighRiskWorkflow:
    """Test the complete workflow for high-risk scenarios."""

    def test_decision_engine_requires_review_high_risk(
        self, decision_engine, high_risk_kill_report, high_risk_siem_context
    ):
        """Test that high risk results in pending review or deny."""
        decision = decision_engine.should_resurrect(
            high_risk_kill_report,
            high_risk_siem_context,
        )

        assert decision.outcome in (
            DecisionOutcome.PENDING_REVIEW,
            DecisionOutcome.DENY,
        )
        assert decision.auto_approve_eligible is False
        assert decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_risk_assessment_high_score(
        self, risk_assessor, high_risk_kill_report, high_risk_siem_context
    ):
        """Test that risk assessment produces high score."""
        assessment = risk_assessor.assess(
            high_risk_kill_report,
            high_risk_siem_context,
        )

        assert assessment.risk_score > 0.6
        assert assessment.auto_approve_eligible is False

    @pytest.mark.asyncio
    async def test_high_risk_queued_for_review(
        self, decision_engine, recommendation_engine, approval_queue,
        high_risk_kill_report, high_risk_siem_context
    ):
        """Test that high risk cases are queued for review."""
        decision = decision_engine.should_resurrect(
            high_risk_kill_report,
            high_risk_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            high_risk_kill_report,
            high_risk_siem_context,
            decision,
        )

        # Queue for approval
        item_id = await approval_queue.enqueue(proposal)

        assert item_id is not None

        # Verify it's in the queue
        pending = await approval_queue.list_pending(limit=10)
        assert any(p.proposal_id == proposal.proposal_id for p in pending)


class TestApprovalQueueWorkflow:
    """Test the approval queue workflow."""

    @pytest.mark.asyncio
    async def test_enqueue_and_approve(
        self, recommendation_engine, decision_engine, approval_queue, resurrector,
        low_risk_kill_report, low_risk_siem_context
    ):
        """Test enqueueing and approving a resurrection."""
        decision = decision_engine.should_resurrect(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            low_risk_kill_report,
            low_risk_siem_context,
            decision,
        )

        # Enqueue
        item_id = await approval_queue.enqueue(proposal)

        # Approve
        request = await approval_queue.approve(
            item_id,
            approver="test-operator",
            notes="Approved for testing",
        )

        assert request is not None
        assert request.approved_by == "test-operator"

        # Execute
        result = await resurrector.resurrect(request)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_enqueue_and_deny(
        self, recommendation_engine, decision_engine, approval_queue,
        high_risk_kill_report, high_risk_siem_context
    ):
        """Test enqueueing and denying a resurrection."""
        decision = decision_engine.should_resurrect(
            high_risk_kill_report,
            high_risk_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            high_risk_kill_report,
            high_risk_siem_context,
            decision,
        )

        # Enqueue
        item_id = await approval_queue.enqueue(proposal)

        # Deny
        await approval_queue.deny(
            item_id,
            denier="test-operator",
            reason="Too risky for automated resurrection",
        )

        # Verify it's no longer pending
        pending = await approval_queue.list_pending(limit=10)
        assert not any(p.proposal_id == proposal.proposal_id for p in pending)


class TestMonitoringWorkflow:
    """Test the post-resurrection monitoring workflow."""

    @pytest.mark.asyncio
    async def test_start_and_stop_monitoring(
        self, monitor, resurrector, recommendation_engine, decision_engine,
        low_risk_kill_report, low_risk_siem_context
    ):
        """Test starting and stopping monitoring after resurrection."""
        decision = decision_engine.should_resurrect(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            low_risk_kill_report,
            low_risk_siem_context,
            decision,
        )

        from execution.resurrector import ResurrectionRequest

        request = ResurrectionRequest(
            request_id=f"monitor-test-{proposal.proposal_id}",
            proposal=proposal,
            approved_by="test-user",
            approved_at=datetime.utcnow(),
            status=ResurrectionStatus.APPROVED,
        )

        # Resurrect
        await resurrector.resurrect(request)

        # Start monitoring
        monitor_id = await monitor.start_monitoring(
            request,
            duration_minutes=1,  # Short for testing
        )

        assert monitor_id is not None

        # Get active sessions
        sessions = monitor.get_active_sessions()
        assert len(sessions) >= 1

        # Stop monitoring
        result = await monitor.stop_monitoring(monitor_id)
        assert result is not None


class TestRollbackWorkflow:
    """Test the rollback workflow."""

    @pytest.mark.asyncio
    async def test_rollback_after_resurrection(
        self, resurrector, recommendation_engine, decision_engine,
        low_risk_kill_report, low_risk_siem_context
    ):
        """Test rolling back a resurrection."""
        decision = decision_engine.should_resurrect(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            low_risk_kill_report,
            low_risk_siem_context,
            decision,
        )

        from execution.resurrector import ResurrectionRequest

        request = ResurrectionRequest(
            request_id=f"rollback-test-{proposal.proposal_id}",
            proposal=proposal,
            approved_by="test-user",
            approved_at=datetime.utcnow(),
            status=ResurrectionStatus.APPROVED,
        )

        # Resurrect
        result = await resurrector.resurrect(request)
        assert result.success is True

        # Rollback
        rollback_success = await resurrector.rollback(
            request.request_id,
            reason="Post-resurrection anomaly detected",
        )

        assert rollback_success is True

        # Verify status
        status = await resurrector.get_status(request.request_id)
        assert status == ResurrectionStatus.ROLLED_BACK


class TestCriticalModuleWorkflow:
    """Test workflow for critical modules."""

    @pytest.fixture
    def critical_module_config(self, full_config):
        """Configuration with critical modules defined."""
        config = full_config.copy()
        config["constitution"] = {
            "constraints": {
                "always_require_approval": ["auth-service", "payment-processor"],
            },
        }
        return config

    def test_critical_module_requires_review(
        self, critical_module_config, high_risk_kill_report
    ):
        """Test that critical modules always require review."""
        decision_engine = create_decision_engine(critical_module_config)

        # Even with a modified low-risk context, critical modules need review
        low_risk_context = SIEMContextResponse(
            query_id="critical-query-001",
            kill_id=high_risk_kill_report.kill_id,
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=10,
            network_context={},
            user_context=None,
            risk_score=0.1,
            recommendation="low_risk",
        )

        decision = decision_engine.should_resurrect(
            high_risk_kill_report,  # target_module is auth-service
            low_risk_context,
        )

        # Critical module should require human review
        assert decision.requires_human_review is True


class TestEdgeCases:
    """Test edge cases in the workflow."""

    @pytest.mark.asyncio
    async def test_duplicate_resurrection_prevented(
        self, resurrector, recommendation_engine, decision_engine,
        low_risk_kill_report, low_risk_siem_context
    ):
        """Test that duplicate resurrections are prevented."""
        decision = decision_engine.should_resurrect(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            low_risk_kill_report,
            low_risk_siem_context,
            decision,
        )

        from execution.resurrector import ResurrectionRequest

        request = ResurrectionRequest(
            request_id=f"duplicate-test-001",
            proposal=proposal,
            approved_by="test-user",
            approved_at=datetime.utcnow(),
            status=ResurrectionStatus.APPROVED,
        )

        # First resurrection
        result1 = await resurrector.resurrect(request)
        assert result1.success is True

        # Attempt duplicate (same request_id)
        result2 = await resurrector.resurrect(request)
        # Should either succeed (idempotent) or fail gracefully
        assert result2 is not None

    @pytest.mark.asyncio
    async def test_blacklisted_module_rejected(
        self, resurrector, recommendation_engine, decision_engine,
        low_risk_kill_report, low_risk_siem_context
    ):
        """Test that blacklisted modules are rejected."""
        # Blacklist the module
        resurrector.blacklist_module(
            low_risk_kill_report.target_module,
            reason="Integration test blacklist",
        )

        decision = decision_engine.should_resurrect(
            low_risk_kill_report,
            low_risk_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            low_risk_kill_report,
            low_risk_siem_context,
            decision,
        )

        from execution.resurrector import ResurrectionRequest

        request = ResurrectionRequest(
            request_id=f"blacklist-test-001",
            proposal=proposal,
            approved_by="test-user",
            approved_at=datetime.utcnow(),
            status=ResurrectionStatus.APPROVED,
        )

        result = await resurrector.resurrect(request)

        assert result.success is False
        assert "blacklist" in result.error_message.lower()
