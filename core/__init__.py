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
]
