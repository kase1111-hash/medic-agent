"""
Medic Agent Data Models

Core data structures for kill reports and resurrection decisions.

Security: All user-provided input is validated to prevent injection attacks,
path traversal, and resource exhaustion.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
import uuid

from core.validation import (
    validate_module_name,
    validate_instance_id,
    validate_metadata,
    validate_evidence_list,
    validate_dependency_list,
    validate_confidence_score,
)


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
    APPROVE_AUTO = "approve_auto"
    APPROVE_MANUAL = "approve_manual"
    PENDING_REVIEW = "pending_review"
    DENY = "deny"
    DEFER = "defer"


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
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial"
    FAILURE = "failure"
    RE_KILLED = "re_killed"
    ROLLBACK = "rollback"


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
        """Validate kill report data for security and correctness."""
        self.target_module = validate_module_name(self.target_module, "target_module")
        self.target_instance_id = validate_instance_id(self.target_instance_id, "target_instance_id")
        self.confidence_score = validate_confidence_score(self.confidence_score, "confidence_score")
        self.evidence = validate_evidence_list(self.evidence, "evidence")
        self.dependencies = validate_dependency_list(self.dependencies, "dependencies")
        self.metadata = validate_metadata(self.metadata, "metadata")

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
class SIEMResult:
    """
    Minimal SIEM enrichment result.

    Placeholder for Phase 1 (no SIEM). Will be expanded in Phase 3
    when a real SIEM integration is wired in.
    """
    risk_score: float = 0.5
    false_positive_history: int = 0
    recommendation: str = "unknown"


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
            timestamp=datetime.now(timezone.utc),
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
            created_at=datetime.now(timezone.utc),
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
