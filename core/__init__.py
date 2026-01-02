"""
Medic Agent Core Module

Core logic for message listening, SIEM querying, and decision evaluation.
"""

from core.models import (
    KillReason,
    Severity,
    KillReport,
    ThreatIndicator,
    SIEMContextResponse,
    DecisionOutcome,
    RiskLevel,
    ResurrectionDecision,
)
from core.logger import get_logger, configure_logging
from core.listener import KillReportListener, SmithEventListener
from core.siem_interface import SIEMAdapter, RESTSIEMAdapter
from core.decision import DecisionEngine, ObserverDecisionEngine
from core.risk import (
    RiskAssessor,
    AdvancedRiskAssessor,
    RiskAssessment,
    RiskFactor,
    RiskThresholds,
    RiskWeights,
    create_risk_assessor,
)
from core.event_bus import (
    EventBus,
    Event,
    EventType,
    get_event_bus,
    create_event_bus,
    on_event,
)
from core.errors import (
    MedicError,
    ErrorCategory,
    SmithConnectionError,
    SIEMQueryError,
    DecisionError,
    ResurrectionError,
    ValidationError,
    ConfigurationError,
    RetryPolicy,
    CircuitBreaker,
    CircuitState,
    with_retry,
    create_siem_retry_policy,
    create_smith_retry_policy,
    create_siem_circuit_breaker,
    create_smith_circuit_breaker,
)
from core.metrics import (
    MedicMetrics,
    MetricType,
    create_metrics,
    get_metrics,
)

__all__ = [
    # Models
    "KillReason",
    "Severity",
    "KillReport",
    "ThreatIndicator",
    "SIEMContextResponse",
    "DecisionOutcome",
    "RiskLevel",
    "ResurrectionDecision",
    # Logger
    "get_logger",
    "configure_logging",
    # Listener
    "KillReportListener",
    "SmithEventListener",
    # SIEM
    "SIEMAdapter",
    "RESTSIEMAdapter",
    # Decision
    "DecisionEngine",
    "ObserverDecisionEngine",
    # Risk
    "RiskAssessor",
    "AdvancedRiskAssessor",
    "RiskAssessment",
    "RiskFactor",
    "RiskThresholds",
    "RiskWeights",
    "create_risk_assessor",
    # Event Bus
    "EventBus",
    "Event",
    "EventType",
    "get_event_bus",
    "create_event_bus",
    "on_event",
]
