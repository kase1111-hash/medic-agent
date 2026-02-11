"""
Medic Agent Core Module

Core logic for message listening, risk assessment, and decision evaluation.
"""

from core.models import (
    KillReason,
    Severity,
    KillReport,
    SIEMResult,
    DecisionOutcome,
    RiskLevel,
    ResurrectionDecision,
    ResurrectionRequest,
    ResurrectionStatus,
    OutcomeResult,
)
from core.logger import get_logger, configure_logging
from core.listener import KillReportListener, SmithEventListener
from core.decision import (
    DecisionEngine,
    ObserverDecisionEngine,
    LiveDecisionEngine,
    DecisionConfig,
    create_decision_engine,
)
from core.risk import (
    RiskAssessor,
    AdvancedRiskAssessor,
    RiskAssessment,
    RiskFactor,
    RiskThresholds,
    RiskWeights,
    create_risk_assessor,
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
)

__all__ = [
    # Models
    "KillReason",
    "Severity",
    "KillReport",
    "SIEMResult",
    "DecisionOutcome",
    "RiskLevel",
    "ResurrectionDecision",
    "ResurrectionRequest",
    "ResurrectionStatus",
    "OutcomeResult",
    # Logger
    "get_logger",
    "configure_logging",
    # Listener
    "KillReportListener",
    "SmithEventListener",
    # Decision
    "DecisionEngine",
    "ObserverDecisionEngine",
    "LiveDecisionEngine",
    "DecisionConfig",
    "create_decision_engine",
    # Risk
    "RiskAssessor",
    "AdvancedRiskAssessor",
    "RiskAssessment",
    "RiskFactor",
    "RiskThresholds",
    "RiskWeights",
    "create_risk_assessor",
    # Errors
    "MedicError",
    "ErrorCategory",
    "SmithConnectionError",
    "SIEMQueryError",
    "DecisionError",
    "ResurrectionError",
    "ValidationError",
    "ConfigurationError",
    "RetryPolicy",
    "CircuitBreaker",
    "CircuitState",
    "with_retry",
]
