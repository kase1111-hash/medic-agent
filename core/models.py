"""
Medic Agent Data Models

Core data structures for kill reports, SIEM responses, and resurrection decisions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import uuid


class KillReason(Enum):
    """Categorized reasons for a kill event from Smith."""
    THREAT_DETECTED = "threat_detected"
    ANOMALY_BEHAVIOR = "anomaly_behavior"
    POLICY_VIOLATION = "policy_violation"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DEPENDENCY_CASCADE = "dependency_cascade"
    MANUAL_OVERRIDE = "manual_override"


class Severity(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DecisionOutcome(Enum):
    """Possible outcomes of a resurrection decision."""
    APPROVE_AUTO = "approve_auto"           # Auto-resurrect (low risk)
    APPROVE_MANUAL = "approve_manual"       # Approved by human
    PENDING_REVIEW = "pending_review"       # Awaiting human review
    DENY = "deny"                           # Do not resurrect
    DEFER = "defer"                         # Need more information


class RiskLevel(Enum):
    """Risk level categories with associated score ranges."""
    MINIMAL = "minimal"       # Score 0.0-0.2
    LOW = "low"               # Score 0.2-0.4
    MEDIUM = "medium"         # Score 0.4-0.6
    HIGH = "high"             # Score 0.6-0.8
    CRITICAL = "critical"     # Score 0.8-1.0

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """Determine risk level from a numeric score."""
        if score < 0.2:
            return cls.MINIMAL
        elif score < 0.4:
            return cls.LOW
        elif score < 0.6:
            return cls.MEDIUM
        elif score < 0.8:
            return cls.HIGH
        else:
            return cls.CRITICAL


class ResurrectionStatus(Enum):
    """Status of a resurrection request workflow."""
    PENDING = "pending"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


class OutcomeResult(Enum):
    """Final outcome of a resurrection attempt."""
    SUCCESS = "success"               # Resurrection successful, stable
    PARTIAL_SUCCESS = "partial"       # Some issues but acceptable
    FAILURE = "failure"               # Resurrection failed
    RE_KILLED = "re_killed"           # Smith killed it again
    ROLLBACK = "rollback"             # Had to rollback


@dataclass
class KillReport:
    """
    Inbound message from Smith's kill notification feed.

    Represents a single kill event with all associated context
    needed for resurrection evaluation.
    """
    kill_id: str
    timestamp: datetime
    target_module: str
    target_instance_id: str
    kill_reason: KillReason
    severity: Severity
    confidence_score: float  # 0.0-1.0
    evidence: List[str]
    dependencies: List[str]
    source_agent: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate kill report data."""
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError(f"confidence_score must be between 0.0 and 1.0, got {self.confidence_score}")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KillReport":
        """Create a KillReport from a dictionary (e.g., parsed JSON)."""
        return cls(
            kill_id=data["kill_id"],
            timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")),
            target_module=data["target_module"],
            target_instance_id=data["target_instance_id"],
            kill_reason=KillReason(data["kill_reason"]),
            severity=Severity(data["severity"]),
            confidence_score=float(data["confidence_score"]),
            evidence=data.get("evidence", []),
            dependencies=data.get("dependencies", []),
            source_agent=data["source_agent"],
            metadata=data.get("metadata", {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "kill_id": self.kill_id,
            "timestamp": self.timestamp.isoformat(),
            "target_module": self.target_module,
            "target_instance_id": self.target_instance_id,
            "kill_reason": self.kill_reason.value,
            "severity": self.severity.value,
            "confidence_score": self.confidence_score,
            "evidence": self.evidence,
            "dependencies": self.dependencies,
            "source_agent": self.source_agent,
            "metadata": self.metadata,
        }


@dataclass
class ThreatIndicator:
    """Individual threat indicator from SIEM."""
    indicator_type: str  # IP, hash, domain, behavior, etc.
    value: str
    threat_score: float  # 0.0-1.0 normalized score
    source: str          # Intel source name
    last_seen: datetime
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatIndicator":
        """Create from dictionary."""
        return cls(
            indicator_type=data["indicator_type"],
            value=data["value"],
            threat_score=float(data["threat_score"]),
            source=data["source"],
            last_seen=datetime.fromisoformat(data["last_seen"].replace("Z", "+00:00")),
            tags=data.get("tags", []),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "indicator_type": self.indicator_type,
            "value": self.value,
            "threat_score": self.threat_score,
            "source": self.source,
            "last_seen": self.last_seen.isoformat(),
            "tags": self.tags,
        }


@dataclass
class SIEMContextResponse:
    """
    Enriched context from SIEM query.

    Contains threat indicators, historical data, and risk assessment
    for a specific kill event.
    """
    query_id: str
    kill_id: str
    timestamp: datetime
    threat_indicators: List[ThreatIndicator]
    historical_behavior: Dict[str, Any]
    false_positive_history: int  # Prior FP count for this module
    network_context: Dict[str, Any]
    user_context: Optional[Dict[str, Any]]
    risk_score: float  # 0.0-1.0
    recommendation: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SIEMContextResponse":
        """Create from dictionary."""
        return cls(
            query_id=data["query_id"],
            kill_id=data["kill_id"],
            timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")),
            threat_indicators=[
                ThreatIndicator.from_dict(ti) for ti in data.get("threat_indicators", [])
            ],
            historical_behavior=data.get("historical_behavior", {}),
            false_positive_history=int(data.get("false_positive_history", 0)),
            network_context=data.get("network_context", {}),
            user_context=data.get("user_context"),
            risk_score=float(data.get("risk_score", 0.5)),
            recommendation=data.get("recommendation", "unknown"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "query_id": self.query_id,
            "kill_id": self.kill_id,
            "timestamp": self.timestamp.isoformat(),
            "threat_indicators": [ti.to_dict() for ti in self.threat_indicators],
            "historical_behavior": self.historical_behavior,
            "false_positive_history": self.false_positive_history,
            "network_context": self.network_context,
            "user_context": self.user_context,
            "risk_score": self.risk_score,
            "recommendation": self.recommendation,
        }


@dataclass
class ResurrectionDecision:
    """
    Decision output from the decision engine.

    Contains the recommendation on whether to resurrect a killed module,
    along with supporting reasoning and risk assessment.
    """
    decision_id: str
    kill_id: str
    timestamp: datetime
    outcome: DecisionOutcome
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    reasoning: List[str]
    recommended_action: str
    requires_human_review: bool
    auto_approve_eligible: bool
    constraints: List[str] = field(default_factory=list)
    timeout_minutes: int = 60

    @classmethod
    def create(
        cls,
        kill_id: str,
        outcome: DecisionOutcome,
        risk_score: float,
        confidence: float,
        reasoning: List[str],
        recommended_action: str,
        constraints: Optional[List[str]] = None,
    ) -> "ResurrectionDecision":
        """Factory method to create a new decision."""
        risk_level = RiskLevel.from_score(risk_score)
        requires_human = outcome == DecisionOutcome.PENDING_REVIEW
        auto_eligible = (
            risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW)
            and confidence >= 0.8
        )

        return cls(
            decision_id=str(uuid.uuid4()),
            kill_id=kill_id,
            timestamp=datetime.utcnow(),
            outcome=outcome,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            reasoning=reasoning,
            recommended_action=recommended_action,
            requires_human_review=requires_human,
            auto_approve_eligible=auto_eligible,
            constraints=constraints or [],
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "decision_id": self.decision_id,
            "kill_id": self.kill_id,
            "timestamp": self.timestamp.isoformat(),
            "outcome": self.outcome.value,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "recommended_action": self.recommended_action,
            "requires_human_review": self.requires_human_review,
            "auto_approve_eligible": self.auto_approve_eligible,
            "constraints": self.constraints,
            "timeout_minutes": self.timeout_minutes,
        }


@dataclass
class ResurrectionRequest:
    """
    Execution request for resurrection workflow.

    Tracks the state of a resurrection attempt from approval through completion.
    """
    request_id: str
    decision_id: str
    kill_id: str
    target_module: str
    target_instance_id: str
    status: ResurrectionStatus
    created_at: datetime
    approved_at: Optional[datetime] = None
    approved_by: Optional[str] = None  # "auto" or user identifier
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    rollback_reason: Optional[str] = None
    monitoring_duration_minutes: int = 30
    health_checks: List[str] = field(default_factory=list)

    @classmethod
    def from_decision(
        cls,
        decision: ResurrectionDecision,
        kill_report: KillReport,
    ) -> "ResurrectionRequest":
        """Create a resurrection request from a decision."""
        return cls(
            request_id=str(uuid.uuid4()),
            decision_id=decision.decision_id,
            kill_id=decision.kill_id,
            target_module=kill_report.target_module,
            target_instance_id=kill_report.target_instance_id,
            status=ResurrectionStatus.PENDING,
            created_at=datetime.utcnow(),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "kill_id": self.kill_id,
            "target_module": self.target_module,
            "target_instance_id": self.target_instance_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "rollback_reason": self.rollback_reason,
            "monitoring_duration_minutes": self.monitoring_duration_minutes,
            "health_checks": self.health_checks,
        }


@dataclass
class OutcomeRecord:
    """
    Learning system outcome for analysis.

    Records the final result of a resurrection attempt for pattern
    analysis and threshold adjustment.
    """
    outcome_id: str
    request_id: str
    decision_id: str
    kill_id: str
    result: OutcomeResult
    recorded_at: datetime
    time_to_stable: Optional[int] = None  # Seconds until stable (if success)
    post_resurrection_metrics: Dict[str, Any] = field(default_factory=dict)
    smith_feedback: Optional[str] = None
    human_feedback: Optional[str] = None
    lessons_learned: List[str] = field(default_factory=list)
    should_adjust_threshold: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "outcome_id": self.outcome_id,
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "kill_id": self.kill_id,
            "result": self.result.value,
            "recorded_at": self.recorded_at.isoformat(),
            "time_to_stable": self.time_to_stable,
            "post_resurrection_metrics": self.post_resurrection_metrics,
            "smith_feedback": self.smith_feedback,
            "human_feedback": self.human_feedback,
            "lessons_learned": self.lessons_learned,
            "should_adjust_threshold": self.should_adjust_threshold,
        }
