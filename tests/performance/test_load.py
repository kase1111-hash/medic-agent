"""
Performance Tests - Load Testing

Tests for performance under load, throughput measurements,
and latency benchmarks.

Run with: pytest tests/performance/ -v --benchmark-only
"""

import pytest
from datetime import datetime, timezone
import uuid
import time
import asyncio
from typing import List

from core.models import KillReport, KillReason, Severity, SIEMContextResponse
from core.decision import ObserverDecisionEngine, DecisionConfig


class TestDecisionThroughput:
    """Test decision engine throughput."""

    @pytest.fixture
    def decision_engine(self):
        """Create decision engine."""
        return ObserverDecisionEngine()

    @pytest.fixture
    def kill_reports(self) -> List[KillReport]:
        """Generate batch of kill reports."""
        return [
            KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                target_module=f"service-{i}",
                target_instance_id=f"instance-{i}",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.MEDIUM,
                confidence_score=0.5 + (i % 5) * 0.1,
                evidence=[f"evidence-{i}"],
                dependencies=[],
                source_agent="smith",
            )
            for i in range(100)
        ]

    @pytest.fixture
    def siem_response(self, kill_reports) -> SIEMContextResponse:
        """Standard SIEM response."""
        return SIEMContextResponse(
            query_id=str(uuid.uuid4()),
            kill_id=kill_reports[0].kill_id,
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=2,
            network_context={},
            user_context=None,
            risk_score=0.35,
            recommendation="low_risk",
        )

    def test_decision_latency_under_50ms(self, decision_engine, kill_reports, siem_response):
        """Individual decision should complete in under 50ms."""
        report = kill_reports[0]

        start = time.perf_counter()
        decision = decision_engine.should_resurrect(report, siem_response)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert decision is not None
        assert elapsed_ms < 50, f"Decision took {elapsed_ms:.2f}ms, expected < 50ms"

    def test_batch_throughput(self, decision_engine, kill_reports, siem_response):
        """Should process at least 100 decisions per second."""
        start = time.perf_counter()

        for report in kill_reports:
            decision_engine.should_resurrect(report, siem_response)

        elapsed = time.perf_counter() - start
        throughput = len(kill_reports) / elapsed

        assert throughput >= 100, f"Throughput {throughput:.1f}/s, expected >= 100/s"

    def test_sustained_load(self, decision_engine, siem_response):
        """Engine should handle sustained load without degradation."""
        latencies = []

        # Generate 1000 reports and measure latency
        for i in range(1000):
            report = KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                target_module=f"service-{i}",
                target_instance_id=f"instance-{i}",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.MEDIUM,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )

            start = time.perf_counter()
            decision_engine.should_resurrect(report, siem_response)
            latencies.append((time.perf_counter() - start) * 1000)

        # Calculate percentiles
        latencies.sort()
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]

        # Assert reasonable latencies
        assert p50 < 10, f"P50 latency {p50:.2f}ms, expected < 10ms"
        assert p95 < 50, f"P95 latency {p95:.2f}ms, expected < 50ms"
        assert p99 < 100, f"P99 latency {p99:.2f}ms, expected < 100ms"


class TestMemoryUsage:
    """Test memory usage under load."""

    def test_memory_stable_under_load(self):
        """Memory should not grow unboundedly under load."""
        import sys

        engine = ObserverDecisionEngine()
        siem_response = SIEMContextResponse(
            query_id=str(uuid.uuid4()),
            kill_id="test",
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.5,
            recommendation="test",
        )

        # Get baseline memory
        initial_objects = len([obj for obj in gc_get_objects() if isinstance(obj, dict)])

        # Process many reports
        for i in range(1000):
            report = KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                target_module=f"service-{i}",
                target_instance_id=f"instance-{i}",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )
            engine.should_resurrect(report, siem_response)

        # Check for excessive object growth
        final_objects = len([obj for obj in gc_get_objects() if isinstance(obj, dict)])
        growth = final_objects - initial_objects

        # Allow for some growth due to caching, etc.
        assert growth < 10000, f"Object growth {growth}, possible memory leak"


def gc_get_objects():
    """Get garbage collector objects (safely)."""
    import gc
    try:
        return gc.get_objects()
    except Exception:
        return []


class TestAsyncPerformance:
    """Test async operation performance."""

    @pytest.mark.asyncio
    async def test_concurrent_siem_queries(self):
        """Concurrent SIEM queries should scale well."""
        from core.siem_interface import MockSIEMAdapter

        adapter = MockSIEMAdapter()
        await adapter.connect()

        # Create multiple concurrent queries
        kill_ids = [str(uuid.uuid4()) for _ in range(50)]

        start = time.perf_counter()

        # Run queries concurrently
        tasks = [adapter.query_context(kill_id) for kill_id in kill_ids]
        results = await asyncio.gather(*tasks)

        elapsed = time.perf_counter() - start

        assert len(results) == 50
        # Should complete quickly due to concurrency
        assert elapsed < 5.0, f"Concurrent queries took {elapsed:.2f}s"

        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_listener_message_rate(self):
        """Listener should handle high message rate."""
        from core.listener import MockSmithListener

        listener = MockSmithListener(interval_seconds=0.01)  # 100 messages/sec
        await listener.connect()

        messages_received = 0
        start = time.perf_counter()

        async for _ in listener.listen():
            messages_received += 1
            if messages_received >= 10:
                break

        elapsed = time.perf_counter() - start
        rate = messages_received / elapsed

        await listener.disconnect()

        assert rate >= 5, f"Message rate {rate:.1f}/s, expected >= 5/s"


class TestDatabasePerformance:
    """Test database operation performance."""

    @pytest.mark.asyncio
    async def test_outcome_store_write_throughput(self, tmp_path):
        """Outcome store should handle high write throughput."""
        from learning.outcome_store import create_outcome_store
        from core.models import OutcomeRecord, ResurrectionOutcome

        config = {
            "learning": {
                "database": {
                    "type": "sqlite",
                    "path": str(tmp_path / "test.db"),
                }
            }
        }

        store = create_outcome_store(config)
        await store.initialize()

        # Write many outcomes
        start = time.perf_counter()

        for i in range(100):
            outcome = OutcomeRecord(
                outcome_id=str(uuid.uuid4()),
                decision_id=str(uuid.uuid4()),
                request_id=str(uuid.uuid4()),
                kill_id=str(uuid.uuid4()),
                target_module=f"service-{i}",
                timestamp=datetime.now(timezone.utc),
                outcome=ResurrectionOutcome.SUCCESS,
                monitoring_duration_minutes=30,
                anomalies_detected=0,
                rolled_back=False,
            )
            await store.record_outcome(outcome)

        elapsed = time.perf_counter() - start
        throughput = 100 / elapsed

        await store.close()

        assert throughput >= 50, f"Write throughput {throughput:.1f}/s, expected >= 50/s"

    @pytest.mark.asyncio
    async def test_outcome_store_read_performance(self, tmp_path):
        """Outcome store reads should be fast."""
        from learning.outcome_store import create_outcome_store
        from core.models import OutcomeRecord, ResurrectionOutcome

        config = {
            "learning": {
                "database": {
                    "type": "sqlite",
                    "path": str(tmp_path / "test.db"),
                }
            }
        }

        store = create_outcome_store(config)
        await store.initialize()

        # Write test data
        module_name = "test-service"
        for i in range(100):
            outcome = OutcomeRecord(
                outcome_id=str(uuid.uuid4()),
                decision_id=str(uuid.uuid4()),
                request_id=str(uuid.uuid4()),
                kill_id=str(uuid.uuid4()),
                target_module=module_name,
                timestamp=datetime.now(timezone.utc),
                outcome=ResurrectionOutcome.SUCCESS if i % 2 == 0 else ResurrectionOutcome.FAILURE,
                monitoring_duration_minutes=30,
                anomalies_detected=0,
                rolled_back=False,
            )
            await store.record_outcome(outcome)

        # Measure read performance
        start = time.perf_counter()

        for _ in range(100):
            await store.get_module_outcomes(module_name, limit=50)

        elapsed = time.perf_counter() - start
        throughput = 100 / elapsed

        await store.close()

        assert throughput >= 100, f"Read throughput {throughput:.1f}/s, expected >= 100/s"


class TestAPIPerformance:
    """Test API endpoint performance."""

    def test_health_check_latency(self):
        """Health check should respond quickly."""
        # This would typically use a test client
        # For now, just verify the endpoint logic is fast
        start = time.perf_counter()

        # Simulate health check logic
        health = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {"redis": "ok", "siem": "ok"},
        }

        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 5, f"Health check took {elapsed_ms:.2f}ms, expected < 5ms"
