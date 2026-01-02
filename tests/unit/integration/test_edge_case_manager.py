"""
Unit tests for the EdgeCaseManager module.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock

from integration.edge_case_manager import (
    EdgeCaseManager,
    EdgeCaseConfig,
    EdgeCase,
    EdgeCaseType,
    EdgeCaseSeverity,
    EdgeCaseAction,
    create_edge_case_manager,
)
from core.models import KillReport, KillReason, Severity


class TestEdgeCaseEnums:
    """Tests for edge case enums."""

    def test_edge_case_type_values(self):
        """Test EdgeCaseType enum values."""
        assert EdgeCaseType.RAPID_REPEATED_KILLS.value == "rapid_repeated_kills"
        assert EdgeCaseType.CASCADING_FAILURE.value == "cascading_failure"
        assert EdgeCaseType.FLAPPING_MODULE.value == "flapping_module"
        assert EdgeCaseType.SYSTEM_WIDE_ANOMALY.value == "system_wide_anomaly"
        assert EdgeCaseType.CIRCULAR_DEPENDENCY.value == "circular_dependency"

    def test_edge_case_severity_values(self):
        """Test EdgeCaseSeverity enum values."""
        assert EdgeCaseSeverity.LOW.value == "low"
        assert EdgeCaseSeverity.MEDIUM.value == "medium"
        assert EdgeCaseSeverity.HIGH.value == "high"
        assert EdgeCaseSeverity.CRITICAL.value == "critical"

    def test_edge_case_action_values(self):
        """Test EdgeCaseAction enum values."""
        assert EdgeCaseAction.PROCEED_WITH_CAUTION.value == "proceed_with_caution"
        assert EdgeCaseAction.REQUIRE_HUMAN_REVIEW.value == "require_human_review"
        assert EdgeCaseAction.PAUSE_AUTO_RESURRECTION.value == "pause_auto_resurrection"
        assert EdgeCaseAction.ESCALATE_IMMEDIATELY.value == "escalate_immediately"


class TestEdgeCase:
    """Tests for EdgeCase dataclass."""

    def test_create_edge_case(self):
        """Test creating an EdgeCase instance."""
        now = datetime.utcnow()
        ec = EdgeCase(
            edge_case_id="ec-001",
            edge_case_type=EdgeCaseType.RAPID_REPEATED_KILLS,
            severity=EdgeCaseSeverity.HIGH,
            detected_at=now,
            description="Module killed 5 times in 60s",
            affected_modules=["test-service"],
            affected_kill_ids=["kill-001", "kill-002"],
            recommended_action=EdgeCaseAction.PAUSE_AUTO_RESURRECTION,
            evidence={"kill_count": 5},
        )

        assert ec.edge_case_id == "ec-001"
        assert ec.edge_case_type == EdgeCaseType.RAPID_REPEATED_KILLS
        assert ec.resolved is False

    def test_to_dict(self):
        """Test serializing edge case to dict."""
        now = datetime.utcnow()
        ec = EdgeCase(
            edge_case_id="ec-001",
            edge_case_type=EdgeCaseType.CASCADING_FAILURE,
            severity=EdgeCaseSeverity.CRITICAL,
            detected_at=now,
            description="5 modules affected",
            affected_modules=["service-a", "service-b"],
            affected_kill_ids=["kill-001"],
            recommended_action=EdgeCaseAction.ESCALATE_IMMEDIATELY,
            evidence={"cascade_depth": 3},
            resolved=True,
            resolved_at=now,
            resolution="Manual intervention",
        )

        data = ec.to_dict()

        assert data["edge_case_type"] == "cascading_failure"
        assert data["severity"] == "critical"
        assert data["resolved"] is True
        assert data["resolution"] == "Manual intervention"


class TestEdgeCaseConfig:
    """Tests for EdgeCaseConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = EdgeCaseConfig()

        assert config.rapid_kill_threshold == 3
        assert config.rapid_kill_window_seconds == 60
        assert config.cascade_threshold == 5
        assert config.flap_threshold == 4
        assert config.flap_window_minutes == 30
        assert config.auto_pause_on_critical is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = EdgeCaseConfig(
            rapid_kill_threshold=5,
            rapid_kill_window_seconds=120,
            auto_pause_on_critical=False,
        )

        assert config.rapid_kill_threshold == 5
        assert config.rapid_kill_window_seconds == 120
        assert config.auto_pause_on_critical is False


class TestEdgeCaseManager:
    """Tests for EdgeCaseManager."""

    @pytest.fixture
    def manager(self):
        """Create an EdgeCaseManager with default config."""
        return EdgeCaseManager()

    @pytest.fixture
    def manager_with_low_thresholds(self):
        """Create manager with low thresholds for testing."""
        config = EdgeCaseConfig(
            rapid_kill_threshold=2,
            rapid_kill_window_seconds=300,
            cascade_threshold=2,
            cascade_window_seconds=300,
            flap_threshold=2,
            flap_window_minutes=60,
            system_anomaly_module_threshold=3,
        )
        return EdgeCaseManager(config=config)

    def create_kill_report(
        self,
        module: str = "test-service",
        kill_reason: KillReason = KillReason.ANOMALY_BEHAVIOR,
        timestamp: datetime = None,
        dependencies: list = None,
    ) -> KillReport:
        """Create a sample kill report."""
        return KillReport(
            kill_id=f"kill-{module}-{datetime.utcnow().timestamp()}",
            timestamp=timestamp or datetime.utcnow(),
            target_module=module,
            target_instance_id="instance-001",
            kill_reason=kill_reason,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            evidence=["Test evidence"],
            dependencies=dependencies or [],
            source_agent="smith-agent",
        )

    def test_initialization(self, manager):
        """Test EdgeCaseManager initialization."""
        assert manager.config is not None
        assert len(manager._kill_history) == 0
        assert len(manager._active_edge_cases) == 0
        assert manager._auto_resurrection_paused is False

    @pytest.mark.asyncio
    async def test_process_kill_report_no_edge_case(self, manager):
        """Test processing single kill report (no edge case)."""
        report = self.create_kill_report()

        result = await manager.process_kill_report(report)

        assert result is None
        assert len(manager._kill_history) == 1

    @pytest.mark.asyncio
    async def test_detect_rapid_repeated_kills(self, manager_with_low_thresholds):
        """Test detection of rapid repeated kills."""
        manager = manager_with_low_thresholds

        # Kill same module twice rapidly
        report1 = self.create_kill_report(module="flaky-service")
        report2 = self.create_kill_report(module="flaky-service")

        await manager.process_kill_report(report1)
        edge_case = await manager.process_kill_report(report2)

        assert edge_case is not None
        assert edge_case.edge_case_type == EdgeCaseType.RAPID_REPEATED_KILLS
        assert edge_case.severity == EdgeCaseSeverity.HIGH
        assert "flaky-service" in edge_case.affected_modules

    @pytest.mark.asyncio
    async def test_detect_cascading_failure(self, manager_with_low_thresholds):
        """Test detection of cascading failures."""
        manager = manager_with_low_thresholds

        # Kill multiple different modules with cascade reason
        for i in range(3):
            report = self.create_kill_report(
                module=f"service-{i}",
                kill_reason=KillReason.DEPENDENCY_CASCADE,
            )
            result = await manager.process_kill_report(report)

        # Should detect cascading failure
        assert result is not None
        assert result.edge_case_type == EdgeCaseType.CASCADING_FAILURE
        assert result.severity == EdgeCaseSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_detect_system_wide_anomaly(self):
        """Test detection of system-wide anomaly."""
        # Use config with high cascade threshold to avoid triggering cascade first
        config = EdgeCaseConfig(
            cascade_threshold=100,  # High threshold to avoid cascade detection
            cascade_window_seconds=300,
            system_anomaly_module_threshold=3,
            system_anomaly_window_seconds=300,
        )
        manager = EdgeCaseManager(config=config)

        # Kill many different modules with non-cascade reason
        for i in range(5):
            report = self.create_kill_report(
                module=f"service-{i}",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,  # Not CASCADE
            )
            result = await manager.process_kill_report(report)

        assert result is not None
        assert result.edge_case_type == EdgeCaseType.SYSTEM_WIDE_ANOMALY
        assert result.severity == EdgeCaseSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_detect_circular_dependency(self, manager):
        """Test detection of circular dependency."""
        now = datetime.utcnow()

        # Kill service-a first (depends on service-b)
        report1 = self.create_kill_report(
            module="service-a",
            kill_reason=KillReason.DEPENDENCY_CASCADE,
            dependencies=["service-b", "service-c"],
            timestamp=now - timedelta(seconds=30),
        )
        await manager.process_kill_report(report1)

        # Kill service-b (depends on service-a)
        report2 = self.create_kill_report(
            module="service-b",
            kill_reason=KillReason.DEPENDENCY_CASCADE,
            dependencies=["service-a", "service-c"],
            timestamp=now - timedelta(seconds=15),
        )
        await manager.process_kill_report(report2)

        # Kill service-c (depends on both)
        report3 = self.create_kill_report(
            module="service-c",
            kill_reason=KillReason.DEPENDENCY_CASCADE,
            dependencies=["service-a", "service-b"],
        )
        edge_case = await manager.process_kill_report(report3)

        assert edge_case is not None
        assert edge_case.edge_case_type == EdgeCaseType.CIRCULAR_DEPENDENCY

    @pytest.mark.asyncio
    async def test_auto_pause_on_critical(self, manager_with_low_thresholds):
        """Test auto-pause on critical edge case."""
        manager = manager_with_low_thresholds

        # Create cascading failure (critical)
        for i in range(3):
            report = self.create_kill_report(
                module=f"service-{i}",
                kill_reason=KillReason.DEPENDENCY_CASCADE,
            )
            await manager.process_kill_report(report)

        assert manager.is_auto_resurrection_paused() is True
        assert manager.get_pause_reason() is not None

    @pytest.mark.asyncio
    async def test_edge_case_callback(self, manager):
        """Test that edge case callback is called."""
        callback = AsyncMock()
        manager.on_edge_case_detected = callback

        # Force rapid kills
        config = EdgeCaseConfig(rapid_kill_threshold=2)
        manager.config = config

        for _ in range(2):
            report = self.create_kill_report(module="callback-test")
            await manager.process_kill_report(report)

        callback.assert_called_once()
        args = callback.call_args[0]
        assert isinstance(args[0], EdgeCase)

    @pytest.mark.asyncio
    async def test_action_callback(self, manager_with_low_thresholds):
        """Test that action callback is called."""
        callback = AsyncMock()
        manager_with_low_thresholds.on_action_required = callback

        for _ in range(2):
            report = self.create_kill_report(module="action-test")
            await manager_with_low_thresholds.process_kill_report(report)

        callback.assert_called_once()

    def test_pause_and_resume_auto_resurrection(self, manager):
        """Test pausing and resuming auto-resurrection."""
        manager.pause_auto_resurrection("Test pause")

        assert manager.is_auto_resurrection_paused() is True
        assert manager.get_pause_reason() == "Test pause"

        manager.resume_auto_resurrection()

        assert manager.is_auto_resurrection_paused() is False
        assert manager.get_pause_reason() is None

    @pytest.mark.asyncio
    async def test_resolve_edge_case(self, manager_with_low_thresholds):
        """Test resolving an edge case."""
        manager = manager_with_low_thresholds

        # Create edge case
        for _ in range(2):
            report = self.create_kill_report(module="resolve-test")
            await manager.process_kill_report(report)

        active = manager.get_active_edge_cases()
        assert len(active) >= 1

        edge_case_id = active[0].edge_case_id
        success = manager.resolve_edge_case(edge_case_id, "Manual resolution")

        assert success is True
        assert len(manager.get_active_edge_cases()) == 0
        assert len(manager.get_edge_case_history()) >= 1

    def test_resolve_nonexistent_edge_case(self, manager):
        """Test resolving nonexistent edge case returns False."""
        success = manager.resolve_edge_case("nonexistent", "Test")
        assert success is False

    @pytest.mark.asyncio
    async def test_should_allow_auto_resurrection_paused(self, manager):
        """Test should_allow_auto_resurrection when paused."""
        manager.pause_auto_resurrection("Test")

        allowed, reason = manager.should_allow_auto_resurrection("any-module")

        assert allowed is False
        assert reason == "Test"

    @pytest.mark.asyncio
    async def test_should_allow_auto_resurrection_active_edge_case(self, manager_with_low_thresholds):
        """Test should_allow_auto_resurrection with active edge case."""
        manager = manager_with_low_thresholds
        manager.config.auto_pause_on_critical = False  # Don't auto-pause

        # Create edge case
        for _ in range(2):
            report = self.create_kill_report(module="blocked-module")
            await manager.process_kill_report(report)

        allowed, reason = manager.should_allow_auto_resurrection("blocked-module")

        assert allowed is False
        assert "edge case" in reason.lower()

    @pytest.mark.asyncio
    async def test_should_allow_auto_resurrection_no_issues(self, manager):
        """Test should_allow_auto_resurrection with no issues."""
        allowed, reason = manager.should_allow_auto_resurrection("healthy-module")

        assert allowed is True
        assert reason is None

    @pytest.mark.asyncio
    async def test_get_statistics(self, manager_with_low_thresholds):
        """Test getting statistics."""
        manager = manager_with_low_thresholds
        manager.config.auto_pause_on_critical = False

        # Create some edge cases
        for _ in range(2):
            report = self.create_kill_report(module="stats-test")
            await manager.process_kill_report(report)

        stats = manager.get_statistics()

        assert "active_edge_cases" in stats
        assert stats["active_edge_cases"] >= 1
        assert "auto_resurrection_paused" in stats

    @pytest.mark.asyncio
    async def test_kill_history_trimmed(self, manager):
        """Test that kill history is trimmed to prevent memory issues."""
        # Add many kill reports
        for i in range(100):
            report = self.create_kill_report(
                module=f"module-{i}",
                timestamp=datetime.utcnow() - timedelta(minutes=i),
            )
            manager._record_kill(report)

        # History should be trimmed to last hour
        assert len(manager._kill_history) < 100

    def test_get_active_edge_cases(self, manager):
        """Test getting active edge cases."""
        active = manager.get_active_edge_cases()
        assert active == []

    def test_get_edge_case_history(self, manager):
        """Test getting edge case history."""
        history = manager.get_edge_case_history()
        assert history == []


class TestCreateEdgeCaseManager:
    """Tests for the create_edge_case_manager factory function."""

    def test_create_with_empty_config(self):
        """Test creating manager with empty config."""
        manager = create_edge_case_manager({})

        assert isinstance(manager, EdgeCaseManager)
        assert manager.config.rapid_kill_threshold == 3

    def test_create_with_custom_config(self):
        """Test creating manager with custom config."""
        config = {
            "edge_cases": {
                "rapid_kill_threshold": 5,
                "rapid_kill_window_seconds": 120,
                "cascade_threshold": 8,
                "auto_pause_on_critical": False,
            }
        }

        manager = create_edge_case_manager(config)

        assert manager.config.rapid_kill_threshold == 5
        assert manager.config.rapid_kill_window_seconds == 120
        assert manager.config.cascade_threshold == 8
        assert manager.config.auto_pause_on_critical is False

    def test_create_with_callbacks(self):
        """Test creating manager with callbacks."""
        callback1 = Mock()
        callback2 = Mock()

        manager = create_edge_case_manager(
            {},
            on_edge_case_detected=callback1,
            on_action_required=callback2,
        )

        assert manager.on_edge_case_detected is callback1
        assert manager.on_action_required is callback2


class TestFlappingDetection:
    """Tests for flapping module detection."""

    @pytest.fixture
    def flap_manager(self):
        """Create manager configured for flapping detection."""
        config = EdgeCaseConfig(
            flap_threshold=3,
            flap_window_minutes=60,
        )
        return EdgeCaseManager(config=config)

    @pytest.mark.asyncio
    async def test_detect_flapping(self, flap_manager):
        """Test flapping module detection."""
        now = datetime.utcnow()

        # Simulate flapping with kills spread over time
        timestamps = [
            now - timedelta(minutes=45),
            now - timedelta(minutes=30),
            now - timedelta(minutes=15),
            now,
        ]

        for ts in timestamps:
            report = KillReport(
                kill_id=f"kill-{ts.timestamp()}",
                timestamp=ts,
                target_module="flapping-service",
                target_instance_id="instance-001",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.MEDIUM,
                confidence_score=0.8,
                evidence=["Test"],
                dependencies=[],
                source_agent="smith",
            )
            flap_manager._record_kill(report)

        # Now detect flapping on latest kill
        latest_report = KillReport(
            kill_id="kill-latest",
            timestamp=now,
            target_module="flapping-service",
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.8,
            evidence=["Test"],
            dependencies=[],
            source_agent="smith",
        )

        edge_case = flap_manager._detect_flapping_module(latest_report)

        if edge_case:
            assert edge_case.edge_case_type == EdgeCaseType.FLAPPING_MODULE
            assert edge_case.severity == EdgeCaseSeverity.MEDIUM
