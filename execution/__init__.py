"""
Medic Agent Execution Module

Resurrection, monitoring, and rollback management.
Introduced in Phase 2.
"""

from execution.recommendation import (
    RecommendationEngine,
    ResurrectionProposal,
    RecommendationType,
    UrgencyLevel,
    create_recommendation_engine,
)
from execution.resurrector import (
    Resurrector,
    ModuleResurrector,
    ResurrectionResult,
    ResurrectionMethod,
    create_resurrector,
)
from execution.monitor import (
    ResurrectionMonitor,
    ModuleMonitor,
    MonitoringSession,
    Anomaly,
    AnomalyType,
    HealthStatus,
    create_monitor,
)
from execution.auto_resurrect import (
    AutoResurrectionManager,
    AutoResurrectionConfig,
    AutoResurrectionResult,
    ResurrectionAttempt,
    create_auto_resurrector,
)

__all__ = [
    # Recommendation
    "RecommendationEngine",
    "ResurrectionProposal",
    "RecommendationType",
    "UrgencyLevel",
    "create_recommendation_engine",
    # Resurrector
    "Resurrector",
    "ModuleResurrector",
    "ResurrectionResult",
    "ResurrectionMethod",
    "create_resurrector",
    # Monitor
    "ResurrectionMonitor",
    "ModuleMonitor",
    "MonitoringSession",
    "Anomaly",
    "AnomalyType",
    "HealthStatus",
    "create_monitor",
    # Auto-Resurrection
    "AutoResurrectionManager",
    "AutoResurrectionConfig",
    "AutoResurrectionResult",
    "ResurrectionAttempt",
    "create_auto_resurrector",
]
