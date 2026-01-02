"""
Medic Agent Self-Monitor

Monitors the agent's own performance, health, and decision quality.
Can detect degradation and trigger automatic remediation.
"""

import asyncio
import os
import psutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import statistics

from core.logger import get_logger

logger = get_logger("integration.self_monitor")


class HealthStatus(Enum):
    """Overall health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"


class MetricType(Enum):
    """Types of metrics being monitored."""
    DECISION_LATENCY = "decision_latency"
    DECISION_ACCURACY = "decision_accuracy"
    QUEUE_DEPTH = "queue_depth"
    ERROR_RATE = "error_rate"
    MEMORY_USAGE = "memory_usage"
    CPU_USAGE = "cpu_usage"
    RESURRECTION_SUCCESS_RATE = "resurrection_success_rate"
    SMITH_CONNECTION = "smith_connection"
    SIEM_CONNECTION = "siem_connection"


@dataclass
class Metric:
    """A monitored metric value."""
    metric_type: MetricType
    value: float
    unit: str
    timestamp: datetime
    status: HealthStatus
    threshold_warning: float
    threshold_critical: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metric_type": self.metric_type.value,
            "value": round(self.value, 3),
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "threshold_warning": self.threshold_warning,
            "threshold_critical": self.threshold_critical,
        }


@dataclass
class HealthCheck:
    """Result of a health check."""
    check_id: str
    timestamp: datetime
    overall_status: HealthStatus
    metrics: List[Metric]
    issues: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "check_id": self.check_id,
            "timestamp": self.timestamp.isoformat(),
            "overall_status": self.overall_status.value,
            "metrics": [m.to_dict() for m in self.metrics],
            "issues": self.issues,
            "recommendations": self.recommendations,
        }


@dataclass
class SelfMonitorConfig:
    """Configuration for self-monitoring."""
    enabled: bool = True
    check_interval_seconds: int = 60
    history_window_minutes: int = 60

    # Latency thresholds (ms)
    latency_warning_ms: float = 500
    latency_critical_ms: float = 2000

    # Error rate thresholds
    error_rate_warning: float = 0.05  # 5%
    error_rate_critical: float = 0.15  # 15%

    # Queue thresholds
    queue_warning: int = 50
    queue_critical: int = 100

    # Resource thresholds
    memory_warning_percent: float = 70.0
    memory_critical_percent: float = 90.0
    cpu_warning_percent: float = 70.0
    cpu_critical_percent: float = 90.0

    # Auto-remediation
    auto_remediate: bool = True
    max_auto_remediations_per_hour: int = 3


class SelfMonitor:
    """
    Monitors the Medic Agent's own health and performance.

    Tracks:
    - Decision latency
    - Decision accuracy (based on outcomes)
    - Queue depths
    - Error rates
    - Resource usage
    - External connection status
    """

    def __init__(
        self,
        config: Optional[SelfMonitorConfig] = None,
        on_health_change: Optional[Callable] = None,
        on_critical: Optional[Callable] = None,
    ):
        self.config = config or SelfMonitorConfig()
        self.on_health_change = on_health_change
        self.on_critical = on_critical

        # Metric history
        self._latencies: List[tuple[datetime, float]] = []
        self._errors: List[datetime] = []
        self._decisions: List[datetime] = []
        self._check_history: List[HealthCheck] = []

        # Current state
        self._current_status = HealthStatus.HEALTHY
        self._last_check: Optional[datetime] = None
        self._monitoring_task: Optional[asyncio.Task] = None

        # Component references
        self._components: Dict[str, Any] = {}

        # Remediation tracking
        self._remediations: List[datetime] = []

        logger.info("SelfMonitor initialized")

    def register_component(self, name: str, component: Any) -> None:
        """Register a component for monitoring."""
        self._components[name] = component
        logger.debug(f"Registered component for monitoring: {name}")

    def record_decision_latency(self, latency_ms: float) -> None:
        """Record a decision latency measurement."""
        now = datetime.utcnow()
        self._latencies.append((now, latency_ms))
        self._decisions.append(now)
        self._trim_history()

    def record_error(self, error_type: str = "general") -> None:
        """Record an error occurrence."""
        self._errors.append(datetime.utcnow())
        self._trim_history()

    def _trim_history(self) -> None:
        """Trim old history data."""
        cutoff = datetime.utcnow() - timedelta(minutes=self.config.history_window_minutes)

        self._latencies = [
            (t, v) for t, v in self._latencies
            if t > cutoff
        ]
        self._errors = [t for t in self._errors if t > cutoff]
        self._decisions = [t for t in self._decisions if t > cutoff]

    async def start_monitoring(self) -> None:
        """Start the background monitoring loop."""
        if self._monitoring_task:
            return

        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Self-monitoring started")

    async def stop_monitoring(self) -> None:
        """Stop the background monitoring loop."""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None
            logger.info("Self-monitoring stopped")

    async def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while True:
            try:
                await asyncio.sleep(self.config.check_interval_seconds)
                health_check = await self.perform_health_check()

                # Handle status changes
                if health_check.overall_status != self._current_status:
                    old_status = self._current_status
                    self._current_status = health_check.overall_status

                    logger.warning(
                        "Health status changed",
                        old_status=old_status.value,
                        new_status=self._current_status.value,
                    )

                    if self.on_health_change:
                        try:
                            result = self.on_health_change(old_status, self._current_status)
                            if asyncio.iscoroutine(result):
                                await result
                        except Exception as e:
                            logger.error(f"Health change callback error: {e}")

                # Handle critical status
                if health_check.overall_status == HealthStatus.CRITICAL:
                    if self.on_critical:
                        try:
                            result = self.on_critical(health_check)
                            if asyncio.iscoroutine(result):
                                await result
                        except Exception as e:
                            logger.error(f"Critical callback error: {e}")

                    # Auto-remediation
                    if self.config.auto_remediate:
                        await self._attempt_remediation(health_check)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}", exc_info=True)

    async def perform_health_check(self) -> HealthCheck:
        """Perform a comprehensive health check."""
        import uuid

        now = datetime.utcnow()
        metrics = []
        issues = []
        recommendations = []

        # Decision latency
        latency_metric = self._check_latency()
        metrics.append(latency_metric)
        if latency_metric.status != HealthStatus.HEALTHY:
            issues.append(f"High decision latency: {latency_metric.value:.0f}ms")
            recommendations.append("Review decision engine performance")

        # Error rate
        error_metric = self._check_error_rate()
        metrics.append(error_metric)
        if error_metric.status != HealthStatus.HEALTHY:
            issues.append(f"Elevated error rate: {error_metric.value:.1%}")
            recommendations.append("Review error logs for patterns")

        # Memory usage
        memory_metric = self._check_memory()
        metrics.append(memory_metric)
        if memory_metric.status != HealthStatus.HEALTHY:
            issues.append(f"High memory usage: {memory_metric.value:.1f}%")
            recommendations.append("Consider garbage collection or restart")

        # CPU usage
        cpu_metric = self._check_cpu()
        metrics.append(cpu_metric)
        if cpu_metric.status != HealthStatus.HEALTHY:
            issues.append(f"High CPU usage: {cpu_metric.value:.1f}%")
            recommendations.append("Review processing bottlenecks")

        # Queue depth (if approval queue is registered)
        if "approval_queue" in self._components:
            queue_metric = await self._check_queue_depth()
            metrics.append(queue_metric)
            if queue_metric.status != HealthStatus.HEALTHY:
                issues.append(f"Queue backlog: {int(queue_metric.value)} items")
                recommendations.append("Process pending approvals")

        # Connection status
        connection_metrics = await self._check_connections()
        metrics.extend(connection_metrics)
        for cm in connection_metrics:
            if cm.status != HealthStatus.HEALTHY:
                issues.append(f"Connection issue: {cm.metric_type.value}")
                recommendations.append(f"Check {cm.metric_type.value} connection")

        # Determine overall status
        overall = self._determine_overall_status(metrics)

        health_check = HealthCheck(
            check_id=str(uuid.uuid4()),
            timestamp=now,
            overall_status=overall,
            metrics=metrics,
            issues=issues,
            recommendations=recommendations,
        )

        self._check_history.append(health_check)
        if len(self._check_history) > 100:
            self._check_history = self._check_history[-100:]

        self._last_check = now

        return health_check

    def _check_latency(self) -> Metric:
        """Check decision latency."""
        now = datetime.utcnow()

        if not self._latencies:
            return Metric(
                metric_type=MetricType.DECISION_LATENCY,
                value=0,
                unit="ms",
                timestamp=now,
                status=HealthStatus.HEALTHY,
                threshold_warning=self.config.latency_warning_ms,
                threshold_critical=self.config.latency_critical_ms,
            )

        avg_latency = statistics.mean(v for _, v in self._latencies)

        if avg_latency >= self.config.latency_critical_ms:
            status = HealthStatus.CRITICAL
        elif avg_latency >= self.config.latency_warning_ms:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        return Metric(
            metric_type=MetricType.DECISION_LATENCY,
            value=avg_latency,
            unit="ms",
            timestamp=now,
            status=status,
            threshold_warning=self.config.latency_warning_ms,
            threshold_critical=self.config.latency_critical_ms,
        )

    def _check_error_rate(self) -> Metric:
        """Check error rate."""
        now = datetime.utcnow()

        total_decisions = len(self._decisions)
        total_errors = len(self._errors)

        if total_decisions == 0:
            error_rate = 0.0
        else:
            error_rate = total_errors / total_decisions

        if error_rate >= self.config.error_rate_critical:
            status = HealthStatus.CRITICAL
        elif error_rate >= self.config.error_rate_warning:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        return Metric(
            metric_type=MetricType.ERROR_RATE,
            value=error_rate,
            unit="ratio",
            timestamp=now,
            status=status,
            threshold_warning=self.config.error_rate_warning,
            threshold_critical=self.config.error_rate_critical,
        )

    def _check_memory(self) -> Metric:
        """Check memory usage."""
        now = datetime.utcnow()

        try:
            process = psutil.Process(os.getpid())
            memory_percent = process.memory_percent()
        except Exception:
            memory_percent = 0.0

        if memory_percent >= self.config.memory_critical_percent:
            status = HealthStatus.CRITICAL
        elif memory_percent >= self.config.memory_warning_percent:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        return Metric(
            metric_type=MetricType.MEMORY_USAGE,
            value=memory_percent,
            unit="percent",
            timestamp=now,
            status=status,
            threshold_warning=self.config.memory_warning_percent,
            threshold_critical=self.config.memory_critical_percent,
        )

    def _check_cpu(self) -> Metric:
        """Check CPU usage."""
        now = datetime.utcnow()

        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
        except Exception:
            cpu_percent = 0.0

        if cpu_percent >= self.config.cpu_critical_percent:
            status = HealthStatus.CRITICAL
        elif cpu_percent >= self.config.cpu_warning_percent:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        return Metric(
            metric_type=MetricType.CPU_USAGE,
            value=cpu_percent,
            unit="percent",
            timestamp=now,
            status=status,
            threshold_warning=self.config.cpu_warning_percent,
            threshold_critical=self.config.cpu_critical_percent,
        )

    async def _check_queue_depth(self) -> Metric:
        """Check approval queue depth."""
        now = datetime.utcnow()

        queue = self._components.get("approval_queue")
        if not queue:
            return Metric(
                metric_type=MetricType.QUEUE_DEPTH,
                value=0,
                unit="items",
                timestamp=now,
                status=HealthStatus.HEALTHY,
                threshold_warning=self.config.queue_warning,
                threshold_critical=self.config.queue_critical,
            )

        try:
            pending = len(await queue.get_pending())
        except Exception:
            pending = 0

        if pending >= self.config.queue_critical:
            status = HealthStatus.CRITICAL
        elif pending >= self.config.queue_warning:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        return Metric(
            metric_type=MetricType.QUEUE_DEPTH,
            value=pending,
            unit="items",
            timestamp=now,
            status=status,
            threshold_warning=self.config.queue_warning,
            threshold_critical=self.config.queue_critical,
        )

    async def _check_connections(self) -> List[Metric]:
        """Check external connection status."""
        metrics = []
        now = datetime.utcnow()

        # Smith connection
        listener = self._components.get("listener")
        smith_connected = False
        if listener and hasattr(listener, "is_connected"):
            try:
                smith_connected = listener.is_connected()
            except Exception:
                pass

        metrics.append(Metric(
            metric_type=MetricType.SMITH_CONNECTION,
            value=1.0 if smith_connected else 0.0,
            unit="boolean",
            timestamp=now,
            status=HealthStatus.HEALTHY if smith_connected else HealthStatus.CRITICAL,
            threshold_warning=1.0,
            threshold_critical=0.0,
        ))

        # SIEM connection
        siem = self._components.get("siem_adapter")
        siem_connected = False
        if siem and hasattr(siem, "is_healthy"):
            try:
                siem_connected = await siem.is_healthy()
            except Exception:
                pass

        metrics.append(Metric(
            metric_type=MetricType.SIEM_CONNECTION,
            value=1.0 if siem_connected else 0.0,
            unit="boolean",
            timestamp=now,
            status=HealthStatus.HEALTHY if siem_connected else HealthStatus.DEGRADED,
            threshold_warning=1.0,
            threshold_critical=0.0,
        ))

        return metrics

    def _determine_overall_status(self, metrics: List[Metric]) -> HealthStatus:
        """Determine overall health from individual metrics."""
        statuses = [m.status for m in metrics]

        if HealthStatus.CRITICAL in statuses:
            return HealthStatus.CRITICAL
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY

    async def _attempt_remediation(self, health_check: HealthCheck) -> bool:
        """Attempt automatic remediation."""
        # Check rate limiting
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        self._remediations = [t for t in self._remediations if t > hour_ago]

        if len(self._remediations) >= self.config.max_auto_remediations_per_hour:
            logger.warning("Remediation rate limit reached")
            return False

        remediated = False

        for metric in health_check.metrics:
            if metric.status == HealthStatus.CRITICAL:
                if metric.metric_type == MetricType.MEMORY_USAGE:
                    # Try garbage collection
                    import gc
                    gc.collect()
                    logger.info("Triggered garbage collection for memory pressure")
                    remediated = True

                elif metric.metric_type == MetricType.QUEUE_DEPTH:
                    # Log warning about queue
                    logger.warning("Queue depth critical - manual intervention may be needed")

        if remediated:
            self._remediations.append(now)

        return remediated

    def get_current_status(self) -> HealthStatus:
        """Get current health status."""
        return self._current_status

    def get_latest_check(self) -> Optional[HealthCheck]:
        """Get the latest health check result."""
        if self._check_history:
            return self._check_history[-1]
        return None

    def get_check_history(self, limit: int = 50) -> List[HealthCheck]:
        """Get health check history."""
        return list(reversed(self._check_history[-limit:]))

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get a summary of current metrics."""
        latest = self.get_latest_check()
        if not latest:
            return {"status": "no_data"}

        return {
            "status": latest.overall_status.value,
            "timestamp": latest.timestamp.isoformat(),
            "metrics": {m.metric_type.value: m.value for m in latest.metrics},
            "issue_count": len(latest.issues),
        }


def create_self_monitor(
    config: Dict[str, Any],
    on_health_change: Optional[Callable] = None,
    on_critical: Optional[Callable] = None,
) -> SelfMonitor:
    """Factory function to create self-monitor."""
    monitor_config = config.get("self_monitoring", {})

    return SelfMonitor(
        config=SelfMonitorConfig(
            enabled=monitor_config.get("enabled", True),
            check_interval_seconds=monitor_config.get("check_interval_seconds", 60),
            history_window_minutes=monitor_config.get("history_window_minutes", 60),
            latency_warning_ms=monitor_config.get("latency_warning_ms", 500),
            latency_critical_ms=monitor_config.get("latency_critical_ms", 2000),
            error_rate_warning=monitor_config.get("error_rate_warning", 0.05),
            error_rate_critical=monitor_config.get("error_rate_critical", 0.15),
            queue_warning=monitor_config.get("queue_warning", 50),
            queue_critical=monitor_config.get("queue_critical", 100),
            memory_warning_percent=monitor_config.get("memory_warning_percent", 70.0),
            memory_critical_percent=monitor_config.get("memory_critical_percent", 90.0),
            auto_remediate=monitor_config.get("auto_remediate", True),
        ),
        on_health_change=on_health_change,
        on_critical=on_critical,
    )
