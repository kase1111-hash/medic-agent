"""
Medic Agent Veto Protocol

Implements the pre-kill veto system that allows Medic to prevent
Smith from killing a module if there's strong evidence it's a false positive.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import uuid

from core.models import KillReason, Severity
from core.logger import get_logger

logger = get_logger("integration.veto_protocol")


class VetoDecision(Enum):
    """Possible veto decisions."""
    APPROVE_KILL = "approve_kill"        # Allow Smith to proceed
    VETO = "veto"                        # Block the kill
    DELAY = "delay"                      # Request delay for more analysis
    CONDITIONAL = "conditional"           # Approve with conditions


class VetoReason(Enum):
    """Reasons for vetoing a kill."""
    HIGH_FALSE_POSITIVE_HISTORY = "high_fp_history"
    RECENT_SUCCESSFUL_RESURRECTION = "recent_resurrection"
    LOW_RISK_ASSESSMENT = "low_risk"
    CONTRADICTORY_SIEM_DATA = "contradictory_siem"
    CRITICAL_DEPENDENCY = "critical_dependency"
    ACTIVE_INVESTIGATION = "active_investigation"
    HUMAN_OVERRIDE = "human_override"


@dataclass
class VetoRequest:
    """A pre-kill veto request from Smith."""
    request_id: str
    module: str
    instance_id: str
    kill_reason: KillReason
    severity: Severity
    smith_confidence: float
    evidence: List[str]
    dependencies: List[str]
    received_at: datetime
    deadline: datetime  # When we need to respond by

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "module": self.module,
            "instance_id": self.instance_id,
            "kill_reason": self.kill_reason.value,
            "severity": self.severity.value,
            "smith_confidence": self.smith_confidence,
            "evidence": self.evidence,
            "dependencies": self.dependencies,
            "received_at": self.received_at.isoformat(),
            "deadline": self.deadline.isoformat(),
        }


@dataclass
class VetoResponse:
    """Response to a veto request."""
    request_id: str
    decision: VetoDecision
    veto_reasons: List[VetoReason]
    medic_confidence: float
    explanation: str
    conditions: Optional[Dict[str, Any]] = None
    delay_seconds: Optional[int] = None
    responded_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "decision": self.decision.value,
            "veto_reasons": [r.value for r in self.veto_reasons],
            "medic_confidence": round(self.medic_confidence, 3),
            "explanation": self.explanation,
            "conditions": self.conditions,
            "delay_seconds": self.delay_seconds,
            "responded_at": self.responded_at.isoformat(),
        }


@dataclass
class VetoConfig:
    """Configuration for the veto protocol."""
    enabled: bool = True
    default_timeout_seconds: int = 30
    max_vetos_per_hour: int = 10
    veto_cooldown_seconds: int = 300
    min_fp_history_for_veto: int = 3
    max_risk_for_veto: float = 0.3
    require_human_approval_for_veto: bool = False


@dataclass
class VetoStatistics:
    """Statistics about veto usage."""
    total_requests: int
    approved_kills: int
    vetoed_kills: int
    delayed_kills: int
    veto_rate: float
    avg_response_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "approved_kills": self.approved_kills,
            "vetoed_kills": self.vetoed_kills,
            "delayed_kills": self.delayed_kills,
            "veto_rate": round(self.veto_rate, 3),
            "avg_response_time_ms": round(self.avg_response_time_ms, 1),
        }


class VetoProtocol:
    """
    Implements the pre-kill veto protocol.

    When Smith is about to kill a module, it can consult Medic first.
    Medic can:
    - Approve the kill (let it proceed)
    - Veto the kill (block it)
    - Request delay (need more time to analyze)
    """

    def __init__(
        self,
        config: Optional[VetoConfig] = None,
        decision_engine: Optional[Any] = None,
        outcome_store: Optional[Any] = None,
        on_veto_decision: Optional[Callable] = None,
    ):
        self.config = config or VetoConfig()
        self.decision_engine = decision_engine
        self.outcome_store = outcome_store
        self.on_veto_decision = on_veto_decision

        # Request tracking
        self._pending_requests: Dict[str, VetoRequest] = {}
        self._request_history: List[tuple[VetoRequest, VetoResponse]] = []

        # Rate limiting
        self._vetos_this_hour: List[datetime] = []
        self._last_veto_by_module: Dict[str, datetime] = {}

        # Response times for statistics
        self._response_times: List[float] = []

        logger.info("VetoProtocol initialized", enabled=self.config.enabled)

    async def handle_veto_request(
        self,
        request: VetoRequest,
    ) -> VetoResponse:
        """
        Handle a pre-kill veto request from Smith.

        Args:
            request: The veto request

        Returns:
            VetoResponse with the decision
        """
        if not self.config.enabled:
            return self._approve_kill(request, "Veto protocol disabled")

        start_time = datetime.utcnow()
        self._pending_requests[request.request_id] = request

        logger.info(
            "Veto request received",
            request_id=request.request_id,
            module=request.module,
            kill_reason=request.kill_reason.value,
        )

        try:
            # Check if we can veto (rate limiting)
            can_veto, limit_reason = self._check_rate_limits(request.module)

            # Gather evidence for decision
            assessment = await self._assess_veto_request(request)

            # Make decision
            response = self._make_decision(request, assessment, can_veto, limit_reason)

            # Record response time
            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._response_times.append(response_time)
            if len(self._response_times) > 1000:
                self._response_times = self._response_times[-1000:]

            # Store in history
            self._request_history.append((request, response))
            if len(self._request_history) > 500:
                self._request_history = self._request_history[-500:]

            # Update rate limiting if vetoed
            if response.decision == VetoDecision.VETO:
                self._vetos_this_hour.append(datetime.utcnow())
                self._last_veto_by_module[request.module] = datetime.utcnow()

            # Trigger callback
            if self.on_veto_decision:
                try:
                    result = self.on_veto_decision(request, response)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as e:
                    logger.error(f"Veto callback error: {e}")

            logger.info(
                "Veto decision made",
                request_id=request.request_id,
                decision=response.decision.value,
                response_time_ms=response_time,
            )

            return response

        finally:
            del self._pending_requests[request.request_id]

    async def _assess_veto_request(
        self,
        request: VetoRequest,
    ) -> Dict[str, Any]:
        """Assess whether to veto a kill request."""
        assessment = {
            "veto_reasons": [],
            "confidence": 0.5,
            "risk_score": 0.5,
            "should_veto": False,
        }

        # Check false positive history
        if self.outcome_store:
            try:
                outcomes = self.outcome_store.get_outcomes_by_module(
                    request.module, limit=20
                )
                fp_count = sum(
                    1 for o in outcomes
                    if o.outcome_type.value == "false_positive"
                )

                if fp_count >= self.config.min_fp_history_for_veto:
                    assessment["veto_reasons"].append(
                        VetoReason.HIGH_FALSE_POSITIVE_HISTORY
                    )
                    assessment["fp_count"] = fp_count

                # Check for recent successful resurrection
                recent_success = [
                    o for o in outcomes
                    if (datetime.utcnow() - o.timestamp).total_seconds() < 3600
                    and o.outcome_type.value == "success"
                ]
                if recent_success:
                    assessment["veto_reasons"].append(
                        VetoReason.RECENT_SUCCESSFUL_RESURRECTION
                    )

            except Exception as e:
                logger.warning(f"Error checking outcome history: {e}")

        # Use decision engine for risk assessment
        if self.decision_engine:
            try:
                # This would need a mock SIEM response
                # For now, use Smith's confidence inverted
                risk_score = 1 - request.smith_confidence

                if risk_score < self.config.max_risk_for_veto:
                    assessment["veto_reasons"].append(VetoReason.LOW_RISK_ASSESSMENT)
                    assessment["risk_score"] = risk_score

            except Exception as e:
                logger.warning(f"Error with decision engine: {e}")

        # Check for critical dependencies
        if len(request.dependencies) > 5:
            # Many dependents = risky to kill, might veto
            assessment["veto_reasons"].append(VetoReason.CRITICAL_DEPENDENCY)

        # Calculate overall veto confidence
        if assessment["veto_reasons"]:
            assessment["should_veto"] = True
            assessment["confidence"] = min(
                0.9,
                0.5 + len(assessment["veto_reasons"]) * 0.15
            )

        return assessment

    def _check_rate_limits(self, module: str) -> tuple[bool, Optional[str]]:
        """Check if we can issue a veto."""
        now = datetime.utcnow()

        # Clean old vetos
        hour_ago = now - timedelta(hours=1)
        self._vetos_this_hour = [
            t for t in self._vetos_this_hour
            if t > hour_ago
        ]

        # Check global rate limit
        if len(self._vetos_this_hour) >= self.config.max_vetos_per_hour:
            return False, f"Hourly veto limit reached ({self.config.max_vetos_per_hour})"

        # Check per-module cooldown
        if module in self._last_veto_by_module:
            elapsed = (now - self._last_veto_by_module[module]).total_seconds()
            if elapsed < self.config.veto_cooldown_seconds:
                remaining = self.config.veto_cooldown_seconds - elapsed
                return False, f"Module in cooldown ({remaining:.0f}s remaining)"

        return True, None

    def _make_decision(
        self,
        request: VetoRequest,
        assessment: Dict[str, Any],
        can_veto: bool,
        limit_reason: Optional[str],
    ) -> VetoResponse:
        """Make the final veto decision."""
        veto_reasons = assessment.get("veto_reasons", [])
        confidence = assessment.get("confidence", 0.5)

        # If we can't veto due to rate limiting, approve with note
        if not can_veto and assessment.get("should_veto"):
            return VetoResponse(
                request_id=request.request_id,
                decision=VetoDecision.APPROVE_KILL,
                veto_reasons=veto_reasons,
                medic_confidence=confidence,
                explanation=f"Would veto but {limit_reason}",
                conditions={"would_have_vetoed": True, "reason": limit_reason},
            )

        # Strong veto case
        if assessment.get("should_veto") and len(veto_reasons) >= 2:
            return VetoResponse(
                request_id=request.request_id,
                decision=VetoDecision.VETO,
                veto_reasons=veto_reasons,
                medic_confidence=confidence,
                explanation=f"Multiple veto reasons: {[r.value for r in veto_reasons]}",
            )

        # Marginal case - request delay
        if assessment.get("should_veto") and len(veto_reasons) == 1:
            return VetoResponse(
                request_id=request.request_id,
                decision=VetoDecision.DELAY,
                veto_reasons=veto_reasons,
                medic_confidence=confidence,
                explanation="Need more time to analyze",
                delay_seconds=30,
            )

        # High Smith confidence - approve
        if request.smith_confidence > 0.9:
            return VetoResponse(
                request_id=request.request_id,
                decision=VetoDecision.APPROVE_KILL,
                veto_reasons=[],
                medic_confidence=1 - request.smith_confidence,
                explanation="High Smith confidence, no objection",
            )

        # Default: approve with conditions
        return VetoResponse(
            request_id=request.request_id,
            decision=VetoDecision.CONDITIONAL,
            veto_reasons=[],
            medic_confidence=0.6,
            explanation="Approve with monitoring request",
            conditions={"monitor_after_kill": True, "alert_on_reoccurrence": True},
        )

    def _approve_kill(self, request: VetoRequest, reason: str) -> VetoResponse:
        """Create an approval response."""
        return VetoResponse(
            request_id=request.request_id,
            decision=VetoDecision.APPROVE_KILL,
            veto_reasons=[],
            medic_confidence=0.5,
            explanation=reason,
        )

    def get_pending_requests(self) -> List[VetoRequest]:
        """Get all pending veto requests."""
        return list(self._pending_requests.values())

    def get_statistics(self) -> VetoStatistics:
        """Get veto statistics."""
        total = len(self._request_history)

        if total == 0:
            return VetoStatistics(
                total_requests=0,
                approved_kills=0,
                vetoed_kills=0,
                delayed_kills=0,
                veto_rate=0.0,
                avg_response_time_ms=0.0,
            )

        approved = sum(
            1 for _, r in self._request_history
            if r.decision == VetoDecision.APPROVE_KILL
        )
        vetoed = sum(
            1 for _, r in self._request_history
            if r.decision == VetoDecision.VETO
        )
        delayed = sum(
            1 for _, r in self._request_history
            if r.decision == VetoDecision.DELAY
        )

        avg_response = (
            sum(self._response_times) / len(self._response_times)
            if self._response_times else 0.0
        )

        return VetoStatistics(
            total_requests=total,
            approved_kills=approved,
            vetoed_kills=vetoed,
            delayed_kills=delayed,
            veto_rate=vetoed / total if total > 0 else 0.0,
            avg_response_time_ms=avg_response,
        )

    def get_history(
        self,
        limit: int = 50,
        decision: Optional[VetoDecision] = None,
    ) -> List[tuple[VetoRequest, VetoResponse]]:
        """Get veto history with optional filtering."""
        history = self._request_history

        if decision:
            history = [(req, resp) for req, resp in history if resp.decision == decision]

        return list(reversed(history[-limit:]))


def create_veto_protocol(
    config: Dict[str, Any],
    decision_engine: Optional[Any] = None,
    outcome_store: Optional[Any] = None,
    on_veto_decision: Optional[Callable] = None,
) -> VetoProtocol:
    """Factory function to create veto protocol."""
    smith_config = config.get("smith", {})
    veto_config = smith_config.get("veto_protocol", {})

    return VetoProtocol(
        config=VetoConfig(
            enabled=veto_config.get("enabled", False),
            default_timeout_seconds=veto_config.get("timeout_seconds", 30),
            max_vetos_per_hour=veto_config.get("max_vetos_per_hour", 10),
            veto_cooldown_seconds=veto_config.get("cooldown_seconds", 300),
            min_fp_history_for_veto=veto_config.get("min_fp_for_veto", 3),
            max_risk_for_veto=veto_config.get("max_risk_for_veto", 0.3),
            require_human_approval_for_veto=veto_config.get("require_human", False),
        ),
        decision_engine=decision_engine,
        outcome_store=outcome_store,
        on_veto_decision=on_veto_decision,
    )
