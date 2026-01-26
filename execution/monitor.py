"""
Medic Agent Post-Resurrection Monitor

Observes resurrected modules for anomalies and determines
when rollback is necessary.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import uuid

from core.models import ResurrectionRequest, ResurrectionStatus
from core.logger import get_logger, LogContext

logger = get_logger("execution.monitor")


class HealthStatus(Enum):
    """Health status of a monitored module."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class AnomalyType(Enum):
    """Types of anomalies detected during monitoring."""
    CPU_SPIKE = "cpu_spike"
    MEMORY_SPIKE = "memory_spike"
    ERROR_RATE = "error_rate"
    LATENCY_SPIKE = "latency_spike"
    HEALTH_CHECK_FAIL = "health_check_fail"
    CRASH_LOOP = "crash_loop"
    NETWORK_ANOMALY = "network_anomaly"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


@dataclass
class Anomaly:
    """Detected anomaly during monitoring."""
    anomaly_id: str
    anomaly_type: AnomalyType
    detected_at: datetime
    severity: float  # 0.0-1.0
    description: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type.value,
            "detected_at": self.detected_at.isoformat(),
            "severity": self.severity,
            "description": self.description,
            "metrics": self.metrics,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


@dataclass
class MonitoringSession:
    """Active monitoring session for a resurrected module."""
    monitor_id: str
    request_id: str
    target_module: str
    target_instance_id: str
    started_at: datetime
    duration_minutes: int
    ends_at: datetime

    # Health tracking
    health_status: HealthStatus = HealthStatus.UNKNOWN
    last_health_check: Optional[datetime] = None
    consecutive_failures: int = 0
    total_health_checks: int = 0
    passed_health_checks: int = 0

    # Anomaly tracking
    anomalies: List[Anomaly] = field(default_factory=list)

    # Metrics
    metrics_history: List[Dict[str, Any]] = field(default_factory=list)

    # State
    active: bool = True
    outcome: Optional[str] = None  # stable, unstable, rollback_triggered

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "monitor_id": self.monitor_id,
            "request_id": self.request_id,
            "target_module": self.target_module,
            "target_instance_id": self.target_instance_id,
            "started_at": self.started_at.isoformat(),
            "duration_minutes": self.duration_minutes,
            "ends_at": self.ends_at.isoformat(),
            "health_status": self.health_status.value,
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None,
            "total_health_checks": self.total_health_checks,
            "passed_health_checks": self.passed_health_checks,
            "health_rate": self.passed_health_checks / max(1, self.total_health_checks),
            "anomaly_count": len(self.anomalies),
            "active": self.active,
            "outcome": self.outcome,
        }

    def get_health_rate(self) -> float:
        """Calculate health check pass rate."""
        if self.total_health_checks == 0:
            return 0.0
        return self.passed_health_checks / self.total_health_checks


class ResurrectionMonitor(ABC):
    """
    Abstract interface for post-resurrection monitoring.

    Monitors resurrected modules for stability and triggers
    rollback when necessary.
    """

    @abstractmethod
    async def start_monitoring(
        self,
        request: ResurrectionRequest,
        duration_minutes: int,
    ) -> str:
        """Start monitoring a resurrected module. Returns monitor_id."""
        pass

    @abstractmethod
    async def stop_monitoring(self, monitor_id: str) -> Dict[str, Any]:
        """Stop monitoring and return collected metrics."""
        pass

    @abstractmethod
    async def check_health(self, target_module: str, instance_id: str) -> HealthStatus:
        """Perform health check on module."""
        pass

    @abstractmethod
    async def get_anomalies(self, monitor_id: str) -> List[Anomaly]:
        """Get detected anomalies during monitoring."""
        pass

    @abstractmethod
    def should_rollback(self, monitor_id: str) -> tuple[bool, str]:
        """Evaluate if rollback is needed. Returns (should_rollback, reason)."""
        pass


class ModuleMonitor(ResurrectionMonitor):
    """
    Default implementation of post-resurrection monitoring.

    Performs periodic health checks and anomaly detection.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        health_checker: Optional[Callable] = None,
        metrics_collector: Optional[Callable] = None,
    ):
        self.config = config or {}

        # Monitoring settings
        self.health_check_interval = self.config.get("health_check_interval", 30)
        self.anomaly_threshold = self.config.get("anomaly_threshold", 0.7)
        self.max_consecutive_failures = self.config.get("max_consecutive_failures", 3)

        # Metric thresholds
        self.cpu_threshold = self.config.get("cpu_threshold", 90.0)
        self.memory_threshold = self.config.get("memory_threshold", 90.0)
        self.error_rate_threshold = self.config.get("error_rate_threshold", 0.1)

        # External integrations
        self._health_checker = health_checker or self._default_health_checker
        self._metrics_collector = metrics_collector or self._default_metrics_collector

        # Active sessions
        self._sessions: Dict[str, MonitoringSession] = {}
        self._monitoring_tasks: Dict[str, asyncio.Task] = {}

        # Rollback callback
        self._rollback_callback: Optional[Callable] = None

    def set_rollback_callback(self, callback: Callable) -> None:
        """Set callback to trigger rollback."""
        self._rollback_callback = callback

    async def start_monitoring(
        self,
        request: ResurrectionRequest,
        duration_minutes: int,
    ) -> str:
        """Start monitoring a resurrected module."""
        monitor_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        session = MonitoringSession(
            monitor_id=monitor_id,
            request_id=request.request_id,
            target_module=request.target_module,
            target_instance_id=request.target_instance_id,
            started_at=now,
            duration_minutes=duration_minutes,
            ends_at=now + timedelta(minutes=duration_minutes),
        )

        self._sessions[monitor_id] = session

        # Start monitoring task
        task = asyncio.create_task(
            self._monitoring_loop(monitor_id)
        )
        self._monitoring_tasks[monitor_id] = task

        logger.info(
            "Started monitoring session",
            monitor_id=monitor_id,
            target_module=request.target_module,
            duration_minutes=duration_minutes,
        )

        return monitor_id

    async def stop_monitoring(self, monitor_id: str) -> Dict[str, Any]:
        """Stop monitoring and return results."""
        session = self._sessions.get(monitor_id)
        if not session:
            return {"error": "Session not found"}

        # Cancel monitoring task
        task = self._monitoring_tasks.get(monitor_id)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            del self._monitoring_tasks[monitor_id]

        # Mark session as inactive
        session.active = False

        # Determine outcome
        if not session.outcome:
            health_rate = session.get_health_rate()
            if health_rate >= 0.9:
                session.outcome = "stable"
            elif health_rate >= 0.7:
                session.outcome = "degraded"
            else:
                session.outcome = "unstable"

        result = session.to_dict()
        result["anomalies"] = [a.to_dict() for a in session.anomalies]

        logger.info(
            "Stopped monitoring session",
            monitor_id=monitor_id,
            outcome=session.outcome,
            health_rate=session.get_health_rate(),
        )

        return result

    async def check_health(
        self,
        target_module: str,
        instance_id: str,
    ) -> HealthStatus:
        """Perform a single health check."""
        try:
            result = await self._health_checker(target_module, instance_id)

            if isinstance(result, dict):
                if result.get("healthy", False):
                    return HealthStatus.HEALTHY
                elif result.get("degraded", False):
                    return HealthStatus.DEGRADED
                else:
                    return HealthStatus.UNHEALTHY

            return HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return HealthStatus.UNKNOWN

    async def get_anomalies(self, monitor_id: str) -> List[Anomaly]:
        """Get anomalies for a monitoring session."""
        session = self._sessions.get(monitor_id)
        if not session:
            return []
        return session.anomalies

    def should_rollback(self, monitor_id: str) -> tuple[bool, str]:
        """Evaluate if rollback is needed."""
        session = self._sessions.get(monitor_id)
        if not session:
            return False, "Session not found"

        # Check consecutive failures
        if session.consecutive_failures >= self.max_consecutive_failures:
            return True, f"Consecutive health check failures: {session.consecutive_failures}"

        # Check for critical anomalies
        critical_anomalies = [
            a for a in session.anomalies
            if a.severity >= 0.9 and not a.resolved
        ]
        if critical_anomalies:
            return True, f"Critical anomaly detected: {critical_anomalies[0].description}"

        # Check overall health rate
        if session.total_health_checks >= 5:
            health_rate = session.get_health_rate()
            if health_rate < 0.5:
                return True, f"Health rate too low: {health_rate:.0%}"

        # Check for crash loop
        crash_anomalies = [
            a for a in session.anomalies
            if a.anomaly_type == AnomalyType.CRASH_LOOP
        ]
        if crash_anomalies:
            return True, "Crash loop detected"

        return False, ""

    async def _monitoring_loop(self, monitor_id: str) -> None:
        """Main monitoring loop for a session."""
        session = self._sessions.get(monitor_id)
        if not session:
            return

        with LogContext(
            monitor_id=monitor_id,
            target_module=session.target_module,
        ):
            logger.debug("Monitoring loop started")

            try:
                while session.active and datetime.now(timezone.utc) < session.ends_at:
                    # Perform health check
                    status = await self.check_health(
                        session.target_module,
                        session.target_instance_id,
                    )

                    # Update session
                    session.last_health_check = datetime.now(timezone.utc)
                    session.total_health_checks += 1
                    session.health_status = status

                    if status == HealthStatus.HEALTHY:
                        session.passed_health_checks += 1
                        session.consecutive_failures = 0
                    else:
                        session.consecutive_failures += 1

                        # Record anomaly if unhealthy
                        if status == HealthStatus.UNHEALTHY:
                            anomaly = Anomaly(
                                anomaly_id=str(uuid.uuid4()),
                                anomaly_type=AnomalyType.HEALTH_CHECK_FAIL,
                                detected_at=datetime.now(timezone.utc),
                                severity=0.5 + (0.1 * session.consecutive_failures),
                                description=f"Health check failed ({session.consecutive_failures} consecutive)",
                            )
                            session.anomalies.append(anomaly)

                    # Collect metrics
                    await self._collect_metrics(session)

                    # Check for anomalies in metrics
                    await self._detect_anomalies(session)

                    # Check if rollback needed
                    should_rollback, reason = self.should_rollback(monitor_id)
                    if should_rollback:
                        logger.warning(
                            "Rollback triggered",
                            reason=reason,
                        )
                        session.outcome = "rollback_triggered"

                        if self._rollback_callback:
                            await self._rollback_callback(
                                session.request_id,
                                reason,
                            )
                        break

                    # Wait for next check
                    await asyncio.sleep(self.health_check_interval)

                # Monitoring period completed
                if session.active and not session.outcome:
                    session.outcome = "stable" if session.get_health_rate() >= 0.9 else "unstable"
                    logger.info(
                        "Monitoring period completed",
                        outcome=session.outcome,
                    )

            except asyncio.CancelledError:
                logger.debug("Monitoring loop cancelled")
                raise

            except Exception as e:
                logger.error(f"Monitoring error: {e}", exc_info=True)
                session.outcome = "error"

            finally:
                session.active = False

    async def _collect_metrics(self, session: MonitoringSession) -> None:
        """Collect metrics for a session."""
        try:
            metrics = await self._metrics_collector(
                session.target_module,
                session.target_instance_id,
            )

            if metrics:
                metrics["collected_at"] = datetime.now(timezone.utc).isoformat()
                session.metrics_history.append(metrics)

                # Keep only last 100 data points
                if len(session.metrics_history) > 100:
                    session.metrics_history = session.metrics_history[-100:]

        except Exception as e:
            logger.warning(f"Failed to collect metrics: {e}")

    async def _detect_anomalies(self, session: MonitoringSession) -> None:
        """Detect anomalies in collected metrics."""
        if not session.metrics_history:
            return

        latest = session.metrics_history[-1]

        # Check CPU
        cpu = latest.get("cpu_percent", 0)
        if cpu > self.cpu_threshold:
            anomaly = Anomaly(
                anomaly_id=str(uuid.uuid4()),
                anomaly_type=AnomalyType.CPU_SPIKE,
                detected_at=datetime.now(timezone.utc),
                severity=min(1.0, cpu / 100),
                description=f"CPU usage at {cpu:.1f}%",
                metrics={"cpu_percent": cpu},
            )
            session.anomalies.append(anomaly)

        # Check memory
        memory = latest.get("memory_percent", 0)
        if memory > self.memory_threshold:
            anomaly = Anomaly(
                anomaly_id=str(uuid.uuid4()),
                anomaly_type=AnomalyType.MEMORY_SPIKE,
                detected_at=datetime.now(timezone.utc),
                severity=min(1.0, memory / 100),
                description=f"Memory usage at {memory:.1f}%",
                metrics={"memory_percent": memory},
            )
            session.anomalies.append(anomaly)

        # Check error rate
        error_rate = latest.get("error_rate", 0)
        if error_rate > self.error_rate_threshold:
            anomaly = Anomaly(
                anomaly_id=str(uuid.uuid4()),
                anomaly_type=AnomalyType.ERROR_RATE,
                detected_at=datetime.now(timezone.utc),
                severity=min(1.0, error_rate * 2),
                description=f"Error rate at {error_rate:.1%}",
                metrics={"error_rate": error_rate},
            )
            session.anomalies.append(anomaly)

    async def _default_health_checker(
        self,
        module: str,
        instance_id: str,
    ) -> Dict[str, Any]:
        """Default health checker (mock implementation)."""
        import random

        # Simulate health check
        await asyncio.sleep(0.1)

        # 90% healthy for testing
        if random.random() > 0.1:
            return {"healthy": True, "response_time_ms": random.randint(10, 100)}
        else:
            return {"healthy": False, "error": "Connection refused"}

    async def _default_metrics_collector(
        self,
        module: str,
        instance_id: str,
    ) -> Dict[str, Any]:
        """Default metrics collector (mock implementation)."""
        import random

        return {
            "cpu_percent": random.uniform(10, 70),
            "memory_percent": random.uniform(20, 60),
            "request_rate": random.randint(10, 1000),
            "error_rate": random.uniform(0, 0.05),
            "response_time_p99_ms": random.randint(50, 500),
        }

    def get_session(self, monitor_id: str) -> Optional[MonitoringSession]:
        """Get a monitoring session by ID."""
        return self._sessions.get(monitor_id)

    def get_active_sessions(self) -> List[MonitoringSession]:
        """Get all active monitoring sessions."""
        return [s for s in self._sessions.values() if s.active]

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        active = [s for s in self._sessions.values() if s.active]
        completed = [s for s in self._sessions.values() if not s.active]

        outcomes = {}
        for s in completed:
            outcome = s.outcome or "unknown"
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

        return {
            "total_sessions": len(self._sessions),
            "active_sessions": len(active),
            "completed_sessions": len(completed),
            "outcomes": outcomes,
        }


def create_monitor(config: Dict[str, Any]) -> ResurrectionMonitor:
    """Factory function to create a monitor."""
    monitor_config = config.get("resurrection", {})
    return ModuleMonitor(monitor_config)
