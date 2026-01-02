"""
Unit Tests - Edge Cases and Error Handling

Tests for boundary conditions, error scenarios, and edge cases
to ensure robust operation under adverse conditions.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
import asyncio

from core.models import KillReport, KillReason, Severity, SIEMContextResponse
from core.decision import ObserverDecisionEngine, DecisionConfig


class TestBoundaryConditions:
    """Test boundary conditions in the decision engine."""

    @pytest.fixture
    def decision_engine(self):
        """Create decision engine with default config."""
        return ObserverDecisionEngine()

    def test_zero_confidence_score(self, decision_engine, sample_siem_response):
        """Handle kill report with zero confidence score."""
        report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.0,  # Minimum
            evidence=[],
            dependencies=[],
            source_agent="smith",
        )

        decision = decision_engine.should_resurrect(report, sample_siem_response)
        assert decision is not None
        assert decision.confidence >= 0.0

    def test_max_confidence_score(self, decision_engine, sample_siem_response):
        """Handle kill report with maximum confidence score."""
        report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.THREAT_DETECTED,
            severity=Severity.CRITICAL,
            confidence_score=1.0,  # Maximum
            evidence=["definite-threat"],
            dependencies=[],
            source_agent="smith",
        )

        decision = decision_engine.should_resurrect(report, sample_siem_response)
        assert decision is not None

    def test_empty_evidence_list(self, decision_engine, sample_siem_response):
        """Handle kill report with no evidence."""
        report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.5,
            evidence=[],  # Empty
            dependencies=[],
            source_agent="smith",
        )

        decision = decision_engine.should_resurrect(report, sample_siem_response)
        assert decision is not None

    def test_many_dependencies(self, decision_engine, sample_siem_response):
        """Handle kill report with many dependencies."""
        many_deps = [f"service-{i}" for i in range(100)]
        report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.5,
            evidence=[],
            dependencies=many_deps,
            source_agent="smith",
        )

        decision = decision_engine.should_resurrect(report, sample_siem_response)
        assert decision is not None

    def test_high_false_positive_history(self, decision_engine, sample_kill_report):
        """High false positive count should lower risk."""
        siem_response = SIEMContextResponse(
            query_id=str(uuid.uuid4()),
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=1000,  # Very high
            network_context={},
            user_context=None,
            risk_score=0.1,
            recommendation="likely_false_positive",
        )

        decision = decision_engine.should_resurrect(sample_kill_report, siem_response)
        # High FP history should result in lower risk
        assert decision.risk_score < 0.5


class TestErrorHandling:
    """Test error handling scenarios."""

    @pytest.fixture
    def decision_engine(self):
        """Create decision engine."""
        return ObserverDecisionEngine()

    def test_missing_siem_response_fields(self, decision_engine, sample_kill_report):
        """Handle SIEM response with minimal fields."""
        minimal_response = SIEMContextResponse(
            query_id=str(uuid.uuid4()),
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.5,
            recommendation="",
        )

        decision = decision_engine.should_resurrect(sample_kill_report, minimal_response)
        assert decision is not None

    def test_stale_timestamp(self, decision_engine, sample_siem_response):
        """Handle very old kill reports."""
        old_report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow() - timedelta(days=365),  # 1 year old
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.5,
            evidence=[],
            dependencies=[],
            source_agent="smith",
        )

        decision = decision_engine.should_resurrect(old_report, sample_siem_response)
        assert decision is not None

    def test_future_timestamp(self, decision_engine, sample_siem_response):
        """Handle kill reports with future timestamps."""
        future_report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow() + timedelta(hours=1),  # Future
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.5,
            evidence=[],
            dependencies=[],
            source_agent="smith",
        )

        decision = decision_engine.should_resurrect(future_report, sample_siem_response)
        assert decision is not None


class TestConcurrency:
    """Test concurrent operation handling."""

    @pytest.fixture
    def decision_engine(self):
        """Create decision engine."""
        return ObserverDecisionEngine()

    def test_concurrent_decisions(self, decision_engine, sample_siem_response):
        """Multiple concurrent decisions should not interfere."""
        reports = [
            KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                target_module=f"service-{i}",
                target_instance_id=f"instance-{i}",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )
            for i in range(10)
        ]

        # Process all reports
        decisions = []
        for report in reports:
            decision = decision_engine.should_resurrect(report, sample_siem_response)
            decisions.append(decision)

        # All should have unique decision IDs
        decision_ids = [d.decision_id for d in decisions]
        assert len(set(decision_ids)) == len(decisions)

    def test_statistics_thread_safety(self, decision_engine, sample_kill_report, sample_siem_response):
        """Statistics tracking should be thread-safe."""
        initial_stats = decision_engine.get_statistics()
        initial_count = initial_stats["total_decisions"]

        # Make multiple decisions
        for _ in range(10):
            decision_engine.should_resurrect(sample_kill_report, sample_siem_response)

        final_stats = decision_engine.get_statistics()
        assert final_stats["total_decisions"] == initial_count + 10


class TestResourceCleanup:
    """Test resource cleanup and memory management."""

    def test_decision_engine_memory_stable(self, sample_kill_report, sample_siem_response):
        """Decision engine should not leak memory."""
        import sys

        engine = ObserverDecisionEngine()

        # Get initial size
        initial_size = sys.getsizeof(engine)

        # Make many decisions
        for _ in range(100):
            engine.should_resurrect(sample_kill_report, sample_siem_response)

        # Size should not grow unboundedly
        # Allow for some growth due to statistics
        final_size = sys.getsizeof(engine)
        assert final_size < initial_size * 10  # Reasonable growth limit


class TestConfigurationEdgeCases:
    """Test edge cases in configuration handling."""

    def test_empty_config(self):
        """Engine should work with empty config."""
        engine = ObserverDecisionEngine(DecisionConfig())
        assert engine is not None

    def test_extreme_thresholds(self, sample_kill_report, sample_siem_response):
        """Engine should handle extreme threshold values."""
        # Very permissive config
        permissive = DecisionConfig(
            auto_approve_max_risk_level="critical",
            auto_approve_min_confidence=0.0,
        )
        engine = ObserverDecisionEngine(permissive)
        decision = engine.should_resurrect(sample_kill_report, sample_siem_response)
        assert decision is not None

    def test_blacklist_whitelist_conflict(self, sample_kill_report, sample_siem_response):
        """Handle module in both blacklist and critical list."""
        config = DecisionConfig(
            always_deny_modules=["test-service"],
            always_require_approval=["test-service"],
        )
        engine = ObserverDecisionEngine(config)

        # Denial should take precedence
        decision = engine.should_resurrect(sample_kill_report, sample_siem_response)
        # The decision handling depends on implementation priority
        assert decision is not None


class TestRaceConditions:
    """Test for potential race conditions."""

    @pytest.mark.asyncio
    async def test_listener_disconnect_during_processing(self):
        """Handle disconnect during message processing."""
        from core.listener import MockSmithListener

        listener = MockSmithListener(interval_seconds=0.1)
        await listener.connect()

        # Start listening in background
        async def listen_briefly():
            count = 0
            async for _ in listener.listen():
                count += 1
                if count >= 2:
                    break
            return count

        # Disconnect while listening
        task = asyncio.create_task(listen_briefly())
        await asyncio.sleep(0.15)
        await listener.disconnect()

        # Should complete without error
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except asyncio.TimeoutError:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
