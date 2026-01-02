"""
Medic Agent Integration Module

Smith protocol bindings, edge case handling, and self-monitoring.
Introduced in Phase 3-5.
"""

from integration.edge_case_manager import (
    EdgeCaseManager,
    EdgeCase,
    EdgeCaseType,
    EdgeCaseSeverity,
    EdgeCaseAction,
    EdgeCaseConfig,
    create_edge_case_manager,
)
from integration.smith_negotiator import (
    SmithNegotiator,
    Negotiation,
    NegotiationType,
    NegotiationState,
    NegotiationOutcome,
    NegotiationMessage,
    SmithConnection,
    create_smith_negotiator,
)
from integration.veto_protocol import (
    VetoProtocol,
    VetoRequest,
    VetoResponse,
    VetoDecision,
    VetoReason,
    VetoConfig,
    VetoStatistics,
    create_veto_protocol,
)
from integration.self_monitor import (
    SelfMonitor,
    HealthCheck,
    HealthStatus,
    Metric,
    MetricType,
    SelfMonitorConfig,
    create_self_monitor,
)
from integration.cluster_manager import (
    ClusterManager,
    ClusterInfo,
    ClusterRole,
    ClusterState,
    ClusterStore,
    InMemoryClusterStore,
    SyncEvent,
    SyncScope,
    get_cluster_manager,
    init_cluster_manager,
    publish_cluster_event,
)

__all__ = [
    # Edge Case Manager
    "EdgeCaseManager",
    "EdgeCase",
    "EdgeCaseType",
    "EdgeCaseSeverity",
    "EdgeCaseAction",
    "EdgeCaseConfig",
    "create_edge_case_manager",
    # Smith Negotiator
    "SmithNegotiator",
    "Negotiation",
    "NegotiationType",
    "NegotiationState",
    "NegotiationOutcome",
    "NegotiationMessage",
    "SmithConnection",
    "create_smith_negotiator",
    # Veto Protocol
    "VetoProtocol",
    "VetoRequest",
    "VetoResponse",
    "VetoDecision",
    "VetoReason",
    "VetoConfig",
    "VetoStatistics",
    "create_veto_protocol",
    # Self Monitor
    "SelfMonitor",
    "HealthCheck",
    "HealthStatus",
    "Metric",
    "MetricType",
    "SelfMonitorConfig",
    "create_self_monitor",
    # Cluster Manager
    "ClusterManager",
    "ClusterInfo",
    "ClusterRole",
    "ClusterState",
    "ClusterStore",
    "InMemoryClusterStore",
    "SyncEvent",
    "SyncScope",
    "get_cluster_manager",
    "init_cluster_manager",
    "publish_cluster_event",
]
