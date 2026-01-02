"""
Medic Agent Metrics

Prometheus metrics for monitoring and observability.
Provides counters, gauges, and histograms for key operations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import time
import threading
from functools import wraps

from core.logger import get_logger

logger = get_logger("core.metrics")

# Try to import prometheus_client
try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Info,
        generate_latest,
        CONTENT_TYPE_LATEST,
        start_http_server,
        CollectorRegistry,
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus_client not installed. Metrics will be collected internally only.")


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass
class MetricValue:
    """Internal metric value storage."""
    name: str
    metric_type: MetricType
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


class InternalMetricsStore:
    """
    Internal metrics storage for when Prometheus is not available.

    Provides basic metrics collection without external dependencies.
    """

    def __init__(self):
        self._counters: Dict[str, float] = {}
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def inc_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter."""
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + value

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge value."""
        key = self._make_key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Observe a histogram value."""
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = []
            self._histograms[key].append(value)
            # Keep only last 1000 observations
            if len(self._histograms[key]) > 1000:
                self._histograms[key] = self._histograms[key][-1000:]

    def get_all(self) -> Dict[str, Any]:
        """Get all metrics."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    k: {
                        "count": len(v),
                        "sum": sum(v) if v else 0,
                        "avg": sum(v) / len(v) if v else 0,
                        "min": min(v) if v else 0,
                        "max": max(v) if v else 0,
                    }
                    for k, v in self._histograms.items()
                },
            }

    def _make_key(self, name: str, labels: Optional[Dict[str, str]] = None) -> str:
        """Create a unique key for metric with labels."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"


class MedicMetrics:
    """
    Medic Agent metrics collection and export.

    Uses Prometheus client if available, falls back to internal storage.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._internal_store = InternalMetricsStore()
        self._registry = None
        self._server_started = False

        if PROMETHEUS_AVAILABLE:
            self._registry = CollectorRegistry()
            self._setup_prometheus_metrics()
        else:
            logger.info("Using internal metrics storage")

    def _setup_prometheus_metrics(self) -> None:
        """Set up Prometheus metric objects."""
        labels = self.config.get("labels", {})
        base_labels = list(labels.keys())

        # Kill report metrics
        self.kill_reports_received = Counter(
            "medic_kill_reports_received_total",
            "Total number of kill reports received",
            labelnames=base_labels + ["severity"],
            registry=self._registry,
        )

        self.kill_reports_processed = Counter(
            "medic_kill_reports_processed_total",
            "Total number of kill reports processed",
            labelnames=base_labels + ["outcome"],
            registry=self._registry,
        )

        # Decision metrics
        self.decisions_made = Counter(
            "medic_decisions_made_total",
            "Total number of resurrection decisions",
            labelnames=base_labels + ["outcome", "risk_level"],
            registry=self._registry,
        )

        self.decision_latency = Histogram(
            "medic_decision_latency_seconds",
            "Time to make resurrection decision",
            labelnames=base_labels,
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
            registry=self._registry,
        )

        # SIEM metrics
        self.siem_queries = Counter(
            "medic_siem_queries_total",
            "Total number of SIEM queries",
            labelnames=base_labels + ["status"],
            registry=self._registry,
        )

        self.siem_latency = Histogram(
            "medic_siem_latency_seconds",
            "SIEM query latency",
            labelnames=base_labels,
            buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
            registry=self._registry,
        )

        # Resurrection metrics
        self.resurrections_attempted = Counter(
            "medic_resurrections_attempted_total",
            "Total resurrection attempts",
            labelnames=base_labels + ["mode"],
            registry=self._registry,
        )

        self.resurrections_succeeded = Counter(
            "medic_resurrections_succeeded_total",
            "Successful resurrections",
            labelnames=base_labels,
            registry=self._registry,
        )

        self.resurrections_failed = Counter(
            "medic_resurrections_failed_total",
            "Failed resurrections",
            labelnames=base_labels + ["reason"],
            registry=self._registry,
        )

        self.resurrections_in_progress = Gauge(
            "medic_resurrections_in_progress",
            "Current number of resurrections in progress",
            labelnames=base_labels,
            registry=self._registry,
        )

        self.resurrection_duration = Histogram(
            "medic_resurrection_duration_seconds",
            "Resurrection workflow duration",
            labelnames=base_labels + ["result"],
            buckets=(1, 5, 10, 30, 60, 120, 300, 600),
            registry=self._registry,
        )

        # Queue metrics
        self.queue_depth = Gauge(
            "medic_approval_queue_depth",
            "Current approval queue depth",
            labelnames=base_labels,
            registry=self._registry,
        )

        self.queue_wait_time = Histogram(
            "medic_queue_wait_time_seconds",
            "Time items spend in approval queue",
            labelnames=base_labels,
            buckets=(60, 300, 900, 1800, 3600, 7200, 14400),
            registry=self._registry,
        )

        # Rollback metrics
        self.rollbacks_triggered = Counter(
            "medic_rollbacks_triggered_total",
            "Total rollbacks triggered",
            labelnames=base_labels + ["reason"],
            registry=self._registry,
        )

        # Error metrics
        self.errors = Counter(
            "medic_errors_total",
            "Total errors by category",
            labelnames=base_labels + ["category", "error_type"],
            registry=self._registry,
        )

        # Health metrics
        self.health_status = Gauge(
            "medic_health_status",
            "Agent health status (1=healthy, 0=unhealthy)",
            labelnames=base_labels,
            registry=self._registry,
        )

        # Learning metrics
        self.outcomes_recorded = Counter(
            "medic_outcomes_recorded_total",
            "Total outcomes recorded for learning",
            labelnames=base_labels + ["outcome_type"],
            registry=self._registry,
        )

        self.threshold_adjustments = Counter(
            "medic_threshold_adjustments_total",
            "Total threshold adjustments made",
            labelnames=base_labels + ["adjustment_type"],
            registry=self._registry,
        )

        # Smith negotiation metrics
        self.negotiations_initiated = Counter(
            "medic_negotiations_initiated_total",
            "Total Smith negotiations initiated",
            labelnames=base_labels + ["type"],
            registry=self._registry,
        )

        self.vetoes_issued = Counter(
            "medic_vetoes_issued_total",
            "Total vetoes issued",
            labelnames=base_labels + ["decision"],
            registry=self._registry,
        )

        # Agent info
        self.agent_info = Info(
            "medic_agent",
            "Medic Agent information",
            registry=self._registry,
        )

        logger.info("Prometheus metrics initialized")

    def _get_base_labels(self) -> Dict[str, str]:
        """Get base labels from config."""
        return self.config.get("labels", {})

    # Kill report metrics

    def record_kill_report_received(self, severity: str) -> None:
        """Record receiving a kill report."""
        labels = {**self._get_base_labels(), "severity": severity}
        if PROMETHEUS_AVAILABLE:
            self.kill_reports_received.labels(**labels).inc()
        self._internal_store.inc_counter("kill_reports_received", labels=labels)

    def record_kill_report_processed(self, outcome: str) -> None:
        """Record processing a kill report."""
        labels = {**self._get_base_labels(), "outcome": outcome}
        if PROMETHEUS_AVAILABLE:
            self.kill_reports_processed.labels(**labels).inc()
        self._internal_store.inc_counter("kill_reports_processed", labels=labels)

    # Decision metrics

    def record_decision(self, outcome: str, risk_level: str, latency_seconds: float) -> None:
        """Record a resurrection decision."""
        base_labels = self._get_base_labels()
        decision_labels = {**base_labels, "outcome": outcome, "risk_level": risk_level}

        if PROMETHEUS_AVAILABLE:
            self.decisions_made.labels(**decision_labels).inc()
            self.decision_latency.labels(**base_labels).observe(latency_seconds)

        self._internal_store.inc_counter("decisions_made", labels=decision_labels)
        self._internal_store.observe_histogram("decision_latency", latency_seconds, labels=base_labels)

    # SIEM metrics

    def record_siem_query(self, status: str, latency_seconds: float) -> None:
        """Record a SIEM query."""
        base_labels = self._get_base_labels()
        query_labels = {**base_labels, "status": status}

        if PROMETHEUS_AVAILABLE:
            self.siem_queries.labels(**query_labels).inc()
            self.siem_latency.labels(**base_labels).observe(latency_seconds)

        self._internal_store.inc_counter("siem_queries", labels=query_labels)
        self._internal_store.observe_histogram("siem_latency", latency_seconds, labels=base_labels)

    # Resurrection metrics

    def record_resurrection_attempt(self, mode: str) -> None:
        """Record a resurrection attempt."""
        labels = {**self._get_base_labels(), "mode": mode}
        if PROMETHEUS_AVAILABLE:
            self.resurrections_attempted.labels(**labels).inc()
        self._internal_store.inc_counter("resurrections_attempted", labels=labels)

    def record_resurrection_success(self, duration_seconds: float) -> None:
        """Record a successful resurrection."""
        base_labels = self._get_base_labels()
        if PROMETHEUS_AVAILABLE:
            self.resurrections_succeeded.labels(**base_labels).inc()
            self.resurrection_duration.labels(**base_labels, result="success").observe(duration_seconds)
        self._internal_store.inc_counter("resurrections_succeeded", labels=base_labels)

    def record_resurrection_failure(self, reason: str, duration_seconds: float) -> None:
        """Record a failed resurrection."""
        base_labels = self._get_base_labels()
        failure_labels = {**base_labels, "reason": reason}
        if PROMETHEUS_AVAILABLE:
            self.resurrections_failed.labels(**failure_labels).inc()
            self.resurrection_duration.labels(**base_labels, result="failure").observe(duration_seconds)
        self._internal_store.inc_counter("resurrections_failed", labels=failure_labels)

    def set_resurrections_in_progress(self, count: int) -> None:
        """Set the number of resurrections in progress."""
        base_labels = self._get_base_labels()
        if PROMETHEUS_AVAILABLE:
            self.resurrections_in_progress.labels(**base_labels).set(count)
        self._internal_store.set_gauge("resurrections_in_progress", count, labels=base_labels)

    # Queue metrics

    def set_queue_depth(self, depth: int) -> None:
        """Set current queue depth."""
        base_labels = self._get_base_labels()
        if PROMETHEUS_AVAILABLE:
            self.queue_depth.labels(**base_labels).set(depth)
        self._internal_store.set_gauge("queue_depth", depth, labels=base_labels)

    def record_queue_wait_time(self, seconds: float) -> None:
        """Record time spent in queue."""
        base_labels = self._get_base_labels()
        if PROMETHEUS_AVAILABLE:
            self.queue_wait_time.labels(**base_labels).observe(seconds)
        self._internal_store.observe_histogram("queue_wait_time", seconds, labels=base_labels)

    # Rollback metrics

    def record_rollback(self, reason: str) -> None:
        """Record a rollback."""
        labels = {**self._get_base_labels(), "reason": reason}
        if PROMETHEUS_AVAILABLE:
            self.rollbacks_triggered.labels(**labels).inc()
        self._internal_store.inc_counter("rollbacks_triggered", labels=labels)

    # Error metrics

    def record_error(self, category: str, error_type: str) -> None:
        """Record an error."""
        labels = {**self._get_base_labels(), "category": category, "error_type": error_type}
        if PROMETHEUS_AVAILABLE:
            self.errors.labels(**labels).inc()
        self._internal_store.inc_counter("errors", labels=labels)

    # Health metrics

    def set_health_status(self, healthy: bool) -> None:
        """Set agent health status."""
        base_labels = self._get_base_labels()
        if PROMETHEUS_AVAILABLE:
            self.health_status.labels(**base_labels).set(1 if healthy else 0)
        self._internal_store.set_gauge("health_status", 1 if healthy else 0, labels=base_labels)

    # Learning metrics

    def record_outcome(self, outcome_type: str) -> None:
        """Record an outcome for learning."""
        labels = {**self._get_base_labels(), "outcome_type": outcome_type}
        if PROMETHEUS_AVAILABLE:
            self.outcomes_recorded.labels(**labels).inc()
        self._internal_store.inc_counter("outcomes_recorded", labels=labels)

    def record_threshold_adjustment(self, adjustment_type: str) -> None:
        """Record a threshold adjustment."""
        labels = {**self._get_base_labels(), "adjustment_type": adjustment_type}
        if PROMETHEUS_AVAILABLE:
            self.threshold_adjustments.labels(**labels).inc()
        self._internal_store.inc_counter("threshold_adjustments", labels=labels)

    # Smith metrics

    def record_negotiation(self, negotiation_type: str) -> None:
        """Record a Smith negotiation."""
        labels = {**self._get_base_labels(), "type": negotiation_type}
        if PROMETHEUS_AVAILABLE:
            self.negotiations_initiated.labels(**labels).inc()
        self._internal_store.inc_counter("negotiations_initiated", labels=labels)

    def record_veto(self, decision: str) -> None:
        """Record a veto decision."""
        labels = {**self._get_base_labels(), "decision": decision}
        if PROMETHEUS_AVAILABLE:
            self.vetoes_issued.labels(**labels).inc()
        self._internal_store.inc_counter("vetoes_issued", labels=labels)

    # Agent info

    def set_agent_info(self, version: str, mode: str, phase: str) -> None:
        """Set agent information."""
        if PROMETHEUS_AVAILABLE:
            self.agent_info.info({
                "version": version,
                "mode": mode,
                "phase": phase,
            })

    # Utility methods

    def get_metrics(self) -> bytes:
        """Get Prometheus-formatted metrics."""
        if PROMETHEUS_AVAILABLE:
            return generate_latest(self._registry)
        return b""

    def get_internal_metrics(self) -> Dict[str, Any]:
        """Get internal metrics as dictionary."""
        return self._internal_store.get_all()

    def start_server(self, port: int = 9090) -> None:
        """Start Prometheus HTTP server."""
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Cannot start metrics server: prometheus_client not available")
            return

        if self._server_started:
            logger.warning("Metrics server already started")
            return

        start_http_server(port, registry=self._registry)
        self._server_started = True
        logger.info(f"Metrics server started on port {port}")


# Decorators for automatic instrumentation

def timed(metric_name: str):
    """Decorator to time function execution."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.time()
            try:
                return await func(*args, **kwargs)
            finally:
                duration = time.time() - start
                if _global_metrics:
                    _global_metrics._internal_store.observe_histogram(metric_name, duration)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                duration = time.time() - start
                if _global_metrics:
                    _global_metrics._internal_store.observe_histogram(metric_name, duration)

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def counted(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator to count function calls."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            if _global_metrics:
                _global_metrics._internal_store.inc_counter(metric_name, labels=labels)
            return await func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            if _global_metrics:
                _global_metrics._internal_store.inc_counter(metric_name, labels=labels)
            return func(*args, **kwargs)

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


# Global metrics instance
_global_metrics: Optional[MedicMetrics] = None


def get_metrics() -> Optional[MedicMetrics]:
    """Get the global metrics instance."""
    return _global_metrics


def create_metrics(config: Optional[Dict[str, Any]] = None) -> MedicMetrics:
    """Create and set the global metrics instance."""
    global _global_metrics
    _global_metrics = MedicMetrics(config)
    return _global_metrics
