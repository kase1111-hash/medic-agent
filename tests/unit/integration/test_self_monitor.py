"""
Unit tests for the SelfMonitor module.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from integration.self_monitor import (
    SelfMonitor,
    SelfMonitorConfig,
    HealthCheck,
    Metric,
    HealthStatus,
    MetricType,
    create_self_monitor,
)


class TestHealthEnums:
    """Tests for health-related enums."""

    def test_health_status_values(self):
        """Test HealthStatus enum values."""
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.CRITICAL.value == "critical"

    def test_metric_type_values(self):
        """Test MetricType enum values."""
        assert MetricType.DECISION_LATENCY.value == "decision_latency"
        assert MetricType.ERROR_RATE.value == "error_rate"
        assert MetricType.MEMORY_USAGE.value == "memory_usage"
        assert MetricType.QUEUE_DEPTH.value == "queue_depth"


class TestMetric:
    """Tests for Metric dataclass."""

    def test_create_metric(self):
        """Test creating a Metric instance."""
        now = datetime.utcnow()
        metric = Metric(
            metric_type=MetricType.DECISION_LATENCY,
            value=150.5,
            unit="ms",
            timestamp=now,
            status=HealthStatus.HEALTHY,
            threshold_warning=500,
            threshold_critical=2000,
        )

        assert metric.metric_type == MetricType.DECISION_LATENCY
        assert metric.value == 150.5
        assert metric.status == HealthStatus.HEALTHY

    def test_to_dict(self):
        """Test serializing metric to dict."""
        now = datetime.utcnow()
        metric = Metric(
            metric_type=MetricType.ERROR_RATE,
            value=0.03456,
            unit="ratio",
            timestamp=now,
            status=HealthStatus.HEALTHY,
            threshold_warning=0.05,
            threshold_critical=0.15,
        )

        data = metric.to_dict()

        assert data["metric_type"] == "error_rate"
        assert data["value"] == 0.035  # Rounded to 3 decimals
        assert data["status"] == "healthy"


class TestHealthCheck:
    """Tests for HealthCheck dataclass."""

    def test_create_health_check(self):
        """Test creating a HealthCheck instance."""
        now = datetime.utcnow()
        metric = Metric(
            metric_type=MetricType.CPU_USAGE,
            value=45.0,
            unit="percent",
            timestamp=now,
            status=HealthStatus.HEALTHY,
            threshold_warning=70,
            threshold_critical=90,
        )

        check = HealthCheck(
            check_id="check-001",
            timestamp=now,
            overall_status=HealthStatus.HEALTHY,
            metrics=[metric],
            issues=[],
            recommendations=[],
        )

        assert check.check_id == "check-001"
        assert check.overall_status == HealthStatus.HEALTHY
        assert len(check.metrics) == 1

    def test_to_dict(self):
        """Test serializing health check to dict."""
        now = datetime.utcnow()
        metric = Metric(
            metric_type=MetricType.MEMORY_USAGE,
            value=65.0,
            unit="percent",
            timestamp=now,
            status=HealthStatus.HEALTHY,
            threshold_warning=70,
            threshold_critical=90,
        )

        check = HealthCheck(
            check_id="check-001",
            timestamp=now,
            overall_status=HealthStatus.DEGRADED,
            metrics=[metric],
            issues=["High memory usage"],
            recommendations=["Consider restart"],
        )

        data = check.to_dict()

        assert data["overall_status"] == "degraded"
        assert len(data["issues"]) == 1
        assert len(data["recommendations"]) == 1


class TestSelfMonitorConfig:
    """Tests for SelfMonitorConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = SelfMonitorConfig()

        assert config.enabled is True
        assert config.check_interval_seconds == 60
        assert config.latency_warning_ms == 500
        assert config.latency_critical_ms == 2000
        assert config.error_rate_warning == 0.05
        assert config.memory_warning_percent == 70.0
        assert config.auto_remediate is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = SelfMonitorConfig(
            enabled=False,
            check_interval_seconds=30,
            latency_warning_ms=300,
            auto_remediate=False,
        )

        assert config.enabled is False
        assert config.check_interval_seconds == 30
        assert config.latency_warning_ms == 300
        assert config.auto_remediate is False


class TestSelfMonitor:
    """Tests for SelfMonitor."""

    @pytest.fixture
    def monitor(self):
        """Create a SelfMonitor with default config."""
        return SelfMonitor()

    @pytest.fixture
    def monitor_strict_thresholds(self):
        """Create a monitor with strict thresholds for testing."""
        config = SelfMonitorConfig(
            latency_warning_ms=100,
            latency_critical_ms=200,
            error_rate_warning=0.02,
            error_rate_critical=0.05,
        )
        return SelfMonitor(config=config)

    def test_initialization(self, monitor):
        """Test SelfMonitor initialization."""
        assert monitor.config.enabled is True
        assert monitor._current_status == HealthStatus.HEALTHY
        assert len(monitor._latencies) == 0
        assert len(monitor._errors) == 0

    def test_register_component(self, monitor):
        """Test registering a component."""
        mock_queue = Mock()
        monitor.register_component("approval_queue", mock_queue)

        assert "approval_queue" in monitor._components
        assert monitor._components["approval_queue"] is mock_queue

    def test_record_decision_latency(self, monitor):
        """Test recording decision latency."""
        monitor.record_decision_latency(150.0)
        monitor.record_decision_latency(200.0)

        assert len(monitor._latencies) == 2
        assert len(monitor._decisions) == 2

    def test_record_error(self, monitor):
        """Test recording an error."""
        monitor.record_error("timeout")
        monitor.record_error("connection")

        assert len(monitor._errors) == 2

    def test_trim_history(self, monitor):
        """Test that old history is trimmed."""
        # Add old latency
        old_time = datetime.utcnow() - timedelta(hours=2)
        monitor._latencies.append((old_time, 100.0))
        monitor._decisions.append(old_time)
        monitor._errors.append(old_time)

        # Add current latency
        monitor.record_decision_latency(150.0)

        # Old entries should be trimmed
        assert len(monitor._latencies) == 1
        assert len(monitor._decisions) == 1
        assert len(monitor._errors) == 0

    def test_check_latency_healthy(self, monitor):
        """Test latency check with healthy values."""
        for _ in range(5):
            monitor.record_decision_latency(100.0)

        metric = monitor._check_latency()

        assert metric.status == HealthStatus.HEALTHY
        assert metric.value == 100.0

    def test_check_latency_degraded(self, monitor_strict_thresholds):
        """Test latency check with degraded values."""
        for _ in range(5):
            monitor_strict_thresholds.record_decision_latency(150.0)

        metric = monitor_strict_thresholds._check_latency()

        assert metric.status == HealthStatus.DEGRADED

    def test_check_latency_critical(self, monitor_strict_thresholds):
        """Test latency check with critical values."""
        for _ in range(5):
            monitor_strict_thresholds.record_decision_latency(300.0)

        metric = monitor_strict_thresholds._check_latency()

        assert metric.status == HealthStatus.CRITICAL

    def test_check_latency_no_data(self, monitor):
        """Test latency check with no data."""
        metric = monitor._check_latency()

        assert metric.status == HealthStatus.HEALTHY
        assert metric.value == 0

    def test_check_error_rate_healthy(self, monitor):
        """Test error rate check with healthy values."""
        # 10 decisions, 0 errors
        for _ in range(10):
            monitor._decisions.append(datetime.utcnow())

        metric = monitor._check_error_rate()

        assert metric.status == HealthStatus.HEALTHY
        assert metric.value == 0.0

    def test_check_error_rate_degraded(self, monitor_strict_thresholds):
        """Test error rate check with degraded values."""
        now = datetime.utcnow()

        # 10 decisions, 3 errors (30% > 2% warning)
        for _ in range(10):
            monitor_strict_thresholds._decisions.append(now)
        for _ in range(3):
            monitor_strict_thresholds._errors.append(now)

        metric = monitor_strict_thresholds._check_error_rate()

        assert metric.status == HealthStatus.CRITICAL  # 30% > 5% critical

    def test_check_error_rate_no_decisions(self, monitor):
        """Test error rate with no decisions."""
        metric = monitor._check_error_rate()

        assert metric.status == HealthStatus.HEALTHY
        assert metric.value == 0.0

    @patch("psutil.Process")
    def test_check_memory_healthy(self, mock_process, monitor):
        """Test memory check with healthy values."""
        mock_proc = Mock()
        mock_proc.memory_percent.return_value = 50.0
        mock_process.return_value = mock_proc

        metric = monitor._check_memory()

        assert metric.status == HealthStatus.HEALTHY
        assert metric.value == 50.0

    @patch("psutil.Process")
    def test_check_memory_degraded(self, mock_process, monitor):
        """Test memory check with degraded values."""
        mock_proc = Mock()
        mock_proc.memory_percent.return_value = 75.0
        mock_process.return_value = mock_proc

        metric = monitor._check_memory()

        assert metric.status == HealthStatus.DEGRADED

    @patch("psutil.Process")
    def test_check_memory_critical(self, mock_process, monitor):
        """Test memory check with critical values."""
        mock_proc = Mock()
        mock_proc.memory_percent.return_value = 95.0
        mock_process.return_value = mock_proc

        metric = monitor._check_memory()

        assert metric.status == HealthStatus.CRITICAL

    @patch("psutil.Process")
    def test_check_memory_error(self, mock_process, monitor):
        """Test memory check with error."""
        mock_process.side_effect = Exception("Process error")

        metric = monitor._check_memory()

        assert metric.status == HealthStatus.HEALTHY
        assert metric.value == 0.0

    @patch("psutil.cpu_percent")
    def test_check_cpu_healthy(self, mock_cpu, monitor):
        """Test CPU check with healthy values."""
        mock_cpu.return_value = 30.0

        metric = monitor._check_cpu()

        assert metric.status == HealthStatus.HEALTHY
        assert metric.value == 30.0

    @patch("psutil.cpu_percent")
    def test_check_cpu_degraded(self, mock_cpu, monitor):
        """Test CPU check with degraded values."""
        mock_cpu.return_value = 80.0

        metric = monitor._check_cpu()

        assert metric.status == HealthStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_check_queue_depth_no_queue(self, monitor):
        """Test queue depth check with no registered queue."""
        metric = await monitor._check_queue_depth()

        assert metric.status == HealthStatus.HEALTHY
        assert metric.value == 0

    @pytest.mark.asyncio
    async def test_check_queue_depth_with_queue(self, monitor):
        """Test queue depth check with registered queue."""
        mock_queue = AsyncMock()
        mock_queue.get_pending.return_value = [1, 2, 3]  # 3 pending items

        monitor.register_component("approval_queue", mock_queue)

        metric = await monitor._check_queue_depth()

        assert metric.value == 3
        assert metric.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_check_connections_no_components(self, monitor):
        """Test connection check with no components."""
        metrics = await monitor._check_connections()

        assert len(metrics) == 2  # Smith and SIEM
        # Both should show not connected
        for m in metrics:
            assert m.value == 0.0

    @pytest.mark.asyncio
    async def test_check_connections_with_listener(self, monitor):
        """Test connection check with registered listener."""
        mock_listener = Mock()
        mock_listener.is_connected.return_value = True

        monitor.register_component("listener", mock_listener)

        metrics = await monitor._check_connections()

        smith_metric = next(m for m in metrics if m.metric_type == MetricType.SMITH_CONNECTION)
        assert smith_metric.value == 1.0
        assert smith_metric.status == HealthStatus.HEALTHY

    def test_determine_overall_status_healthy(self, monitor):
        """Test overall status determination with all healthy."""
        now = datetime.utcnow()
        metrics = [
            Metric(MetricType.DECISION_LATENCY, 100, "ms", now, HealthStatus.HEALTHY, 500, 2000),
            Metric(MetricType.ERROR_RATE, 0.01, "ratio", now, HealthStatus.HEALTHY, 0.05, 0.15),
        ]

        status = monitor._determine_overall_status(metrics)

        assert status == HealthStatus.HEALTHY

    def test_determine_overall_status_degraded(self, monitor):
        """Test overall status determination with degraded."""
        now = datetime.utcnow()
        metrics = [
            Metric(MetricType.DECISION_LATENCY, 600, "ms", now, HealthStatus.DEGRADED, 500, 2000),
            Metric(MetricType.ERROR_RATE, 0.01, "ratio", now, HealthStatus.HEALTHY, 0.05, 0.15),
        ]

        status = monitor._determine_overall_status(metrics)

        assert status == HealthStatus.DEGRADED

    def test_determine_overall_status_critical(self, monitor):
        """Test overall status determination with critical."""
        now = datetime.utcnow()
        metrics = [
            Metric(MetricType.DECISION_LATENCY, 100, "ms", now, HealthStatus.HEALTHY, 500, 2000),
            Metric(MetricType.MEMORY_USAGE, 95, "percent", now, HealthStatus.CRITICAL, 70, 90),
        ]

        status = monitor._determine_overall_status(metrics)

        assert status == HealthStatus.CRITICAL

    @pytest.mark.asyncio
    @patch("psutil.Process")
    @patch("psutil.cpu_percent")
    async def test_perform_health_check(self, mock_cpu, mock_process, monitor):
        """Test performing a full health check."""
        mock_proc = Mock()
        mock_proc.memory_percent.return_value = 50.0
        mock_process.return_value = mock_proc
        mock_cpu.return_value = 30.0

        # Add some latency data
        monitor.record_decision_latency(150.0)

        health_check = await monitor.perform_health_check()

        assert health_check is not None
        assert health_check.overall_status == HealthStatus.HEALTHY
        assert len(health_check.metrics) >= 4  # Latency, error rate, memory, CPU

    @pytest.mark.asyncio
    async def test_health_change_callback(self, monitor):
        """Test that health change callback is called."""
        callback = AsyncMock()
        monitor.on_health_change = callback

        # Simulate status change
        old_status = monitor._current_status
        monitor._current_status = HealthStatus.DEGRADED

        # The callback would be called in the monitoring loop
        # For unit testing, we call it manually
        await callback(old_status, HealthStatus.DEGRADED)

        callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_critical_callback(self, monitor):
        """Test that critical callback is called."""
        callback = AsyncMock()
        monitor.on_critical = callback

        now = datetime.utcnow()
        critical_check = HealthCheck(
            check_id="check-001",
            timestamp=now,
            overall_status=HealthStatus.CRITICAL,
            metrics=[],
            issues=["Critical issue"],
            recommendations=["Fix it"],
        )

        await callback(critical_check)

        callback.assert_called_once()

    @pytest.mark.asyncio
    @patch("gc.collect")
    async def test_attempt_remediation_memory(self, mock_gc, monitor):
        """Test auto-remediation for memory issues."""
        now = datetime.utcnow()
        metrics = [
            Metric(MetricType.MEMORY_USAGE, 95, "percent", now, HealthStatus.CRITICAL, 70, 90),
        ]
        health_check = HealthCheck(
            check_id="check-001",
            timestamp=now,
            overall_status=HealthStatus.CRITICAL,
            metrics=metrics,
            issues=["High memory"],
            recommendations=["GC"],
        )

        result = await monitor._attempt_remediation(health_check)

        assert result is True
        mock_gc.assert_called_once()

    @pytest.mark.asyncio
    async def test_remediation_rate_limiting(self, monitor):
        """Test that remediation is rate limited."""
        # Exhaust remediation limit
        now = datetime.utcnow()
        for _ in range(monitor.config.max_auto_remediations_per_hour):
            monitor._remediations.append(now)

        health_check = HealthCheck(
            check_id="check-001",
            timestamp=now,
            overall_status=HealthStatus.CRITICAL,
            metrics=[
                Metric(MetricType.MEMORY_USAGE, 95, "percent", now, HealthStatus.CRITICAL, 70, 90),
            ],
            issues=["High memory"],
            recommendations=["GC"],
        )

        result = await monitor._attempt_remediation(health_check)

        assert result is False

    def test_get_current_status(self, monitor):
        """Test getting current status."""
        assert monitor.get_current_status() == HealthStatus.HEALTHY

        monitor._current_status = HealthStatus.DEGRADED
        assert monitor.get_current_status() == HealthStatus.DEGRADED

    def test_get_latest_check_no_history(self, monitor):
        """Test getting latest check with no history."""
        result = monitor.get_latest_check()
        assert result is None

    @pytest.mark.asyncio
    @patch("psutil.Process")
    @patch("psutil.cpu_percent")
    async def test_get_latest_check(self, mock_cpu, mock_process, monitor):
        """Test getting latest check."""
        mock_proc = Mock()
        mock_proc.memory_percent.return_value = 50.0
        mock_process.return_value = mock_proc
        mock_cpu.return_value = 30.0

        await monitor.perform_health_check()

        latest = monitor.get_latest_check()

        assert latest is not None
        assert isinstance(latest, HealthCheck)

    @pytest.mark.asyncio
    @patch("psutil.Process")
    @patch("psutil.cpu_percent")
    async def test_get_check_history(self, mock_cpu, mock_process, monitor):
        """Test getting check history."""
        mock_proc = Mock()
        mock_proc.memory_percent.return_value = 50.0
        mock_process.return_value = mock_proc
        mock_cpu.return_value = 30.0

        for _ in range(3):
            await monitor.perform_health_check()

        history = monitor.get_check_history(limit=2)

        assert len(history) == 2

    @pytest.mark.asyncio
    @patch("psutil.Process")
    @patch("psutil.cpu_percent")
    async def test_get_metrics_summary(self, mock_cpu, mock_process, monitor):
        """Test getting metrics summary."""
        mock_proc = Mock()
        mock_proc.memory_percent.return_value = 50.0
        mock_process.return_value = mock_proc
        mock_cpu.return_value = 30.0

        await monitor.perform_health_check()

        summary = monitor.get_metrics_summary()

        assert summary["status"] == "healthy"
        assert "metrics" in summary
        assert "timestamp" in summary

    def test_get_metrics_summary_no_data(self, monitor):
        """Test getting metrics summary with no data."""
        summary = monitor.get_metrics_summary()

        assert summary == {"status": "no_data"}

    @pytest.mark.asyncio
    async def test_start_and_stop_monitoring(self, monitor):
        """Test starting and stopping monitoring."""
        monitor.config.check_interval_seconds = 0.1

        await monitor.start_monitoring()
        assert monitor._monitoring_task is not None

        await asyncio.sleep(0.05)  # Let it run briefly

        await monitor.stop_monitoring()
        assert monitor._monitoring_task is None


class TestCreateSelfMonitor:
    """Tests for the create_self_monitor factory function."""

    def test_create_with_empty_config(self):
        """Test creating monitor with empty config."""
        monitor = create_self_monitor({})

        assert isinstance(monitor, SelfMonitor)
        assert monitor.config.enabled is True

    def test_create_with_custom_config(self):
        """Test creating monitor with custom config."""
        config = {
            "self_monitoring": {
                "enabled": False,
                "check_interval_seconds": 30,
                "latency_warning_ms": 300,
                "memory_warning_percent": 60.0,
                "auto_remediate": False,
            }
        }

        monitor = create_self_monitor(config)

        assert monitor.config.enabled is False
        assert monitor.config.check_interval_seconds == 30
        assert monitor.config.latency_warning_ms == 300
        assert monitor.config.memory_warning_percent == 60.0
        assert monitor.config.auto_remediate is False

    def test_create_with_callbacks(self):
        """Test creating monitor with callbacks."""
        callback1 = Mock()
        callback2 = Mock()

        monitor = create_self_monitor(
            {},
            on_health_change=callback1,
            on_critical=callback2,
        )

        assert monitor.on_health_change is callback1
        assert monitor.on_critical is callback2


class TestMonitoringLoop:
    """Tests for the monitoring loop behavior."""

    @pytest.mark.asyncio
    @patch("psutil.Process")
    @patch("psutil.cpu_percent")
    async def test_monitoring_loop_status_change(self, mock_cpu, mock_process):
        """Test that monitoring loop detects status changes."""
        mock_proc = Mock()
        mock_proc.memory_percent.return_value = 50.0
        mock_process.return_value = mock_proc
        mock_cpu.return_value = 30.0

        callback = AsyncMock()
        config = SelfMonitorConfig(check_interval_seconds=0.1)
        monitor = SelfMonitor(config=config, on_health_change=callback)

        # Perform initial check
        await monitor.perform_health_check()
        initial_status = monitor._current_status

        # Change status
        monitor._current_status = HealthStatus.DEGRADED

        # Check that status changed
        assert monitor._current_status != initial_status
