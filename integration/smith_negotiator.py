"""
Medic Agent Smith Negotiator

Bi-directional communication with Smith for collaborative decision-making,
including pre-kill consultation and resurrection coordination.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import json
import uuid

from core.models import KillReport, KillReason, Severity
from core.logger import get_logger

logger = get_logger("integration.smith_negotiator")


class NegotiationState(Enum):
    """State of a negotiation with Smith."""
    INITIATED = "initiated"
    AWAITING_RESPONSE = "awaiting_response"
    IN_DISCUSSION = "in_discussion"
    AGREED = "agreed"
    DISAGREED = "disagreed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class NegotiationType(Enum):
    """Types of negotiations with Smith."""
    PRE_KILL_CONSULTATION = "pre_kill_consultation"
    POST_KILL_APPEAL = "post_kill_appeal"
    RESURRECTION_CLEARANCE = "resurrection_clearance"
    THRESHOLD_DISCUSSION = "threshold_discussion"
    MODULE_STATUS_QUERY = "module_status_query"
    BULK_RESURRECTION_REQUEST = "bulk_resurrection_request"


class NegotiationOutcome(Enum):
    """Outcome of a negotiation."""
    APPROVED = "approved"
    DENIED = "denied"
    CONDITIONAL = "conditional"
    DEFERRED = "deferred"
    NO_RESPONSE = "no_response"


@dataclass
class NegotiationMessage:
    """A message in a negotiation."""
    message_id: str
    sender: str  # "medic" or "smith"
    timestamp: datetime
    message_type: str
    content: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "message_id": self.message_id,
            "sender": self.sender,
            "timestamp": self.timestamp.isoformat(),
            "message_type": self.message_type,
            "content": self.content,
        }


@dataclass
class Negotiation:
    """A negotiation session with Smith."""
    negotiation_id: str
    negotiation_type: NegotiationType
    state: NegotiationState
    initiated_at: datetime
    initiated_by: str  # "medic" or "smith"
    subject: Dict[str, Any]  # What we're negotiating about
    messages: List[NegotiationMessage] = field(default_factory=list)
    outcome: Optional[NegotiationOutcome] = None
    outcome_details: Optional[Dict[str, Any]] = None
    completed_at: Optional[datetime] = None
    timeout_seconds: int = 30

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "negotiation_id": self.negotiation_id,
            "negotiation_type": self.negotiation_type.value,
            "state": self.state.value,
            "initiated_at": self.initiated_at.isoformat(),
            "initiated_by": self.initiated_by,
            "subject": self.subject,
            "messages": [m.to_dict() for m in self.messages],
            "outcome": self.outcome.value if self.outcome else None,
            "outcome_details": self.outcome_details,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


@dataclass
class SmithConnection:
    """Configuration for Smith connection."""
    endpoint: str = "redis://localhost:6379"
    request_topic: str = "medic.to_smith"
    response_topic: str = "smith.to_medic"
    timeout_seconds: int = 30
    retry_attempts: int = 3
    enabled: bool = True


class SmithNegotiator:
    """
    Handles bi-directional negotiation with Smith.

    Enables:
    - Pre-kill consultation (Smith asks Medic before killing)
    - Post-kill appeal (Medic contests a kill decision)
    - Resurrection clearance (Medic requests Smith's blessing)
    - Threshold discussions (Agree on risk thresholds)
    """

    def __init__(
        self,
        connection: Optional[SmithConnection] = None,
        message_sender: Optional[Callable] = None,
    ):
        self.connection = connection or SmithConnection()
        self.message_sender = message_sender

        # Active negotiations
        self._negotiations: Dict[str, Negotiation] = {}
        self._negotiation_history: List[Negotiation] = []

        # Pending response handlers
        self._response_handlers: Dict[str, asyncio.Future] = {}

        # Statistics
        self._stats = {
            "total_negotiations": 0,
            "successful": 0,
            "failed": 0,
            "timeouts": 0,
        }

        logger.info(
            "SmithNegotiator initialized",
            endpoint=self.connection.endpoint,
            enabled=self.connection.enabled,
        )

    async def request_pre_kill_consultation(
        self,
        module: str,
        kill_reason: KillReason,
        smith_confidence: float,
        medic_assessment: Dict[str, Any],
    ) -> Negotiation:
        """
        Initiate a pre-kill consultation when Smith is about to kill.

        Args:
            module: Module Smith wants to kill
            kill_reason: Reason for the kill
            smith_confidence: Smith's confidence in the kill
            medic_assessment: Medic's assessment of the situation

        Returns:
            Negotiation result
        """
        negotiation = await self._initiate_negotiation(
            negotiation_type=NegotiationType.PRE_KILL_CONSULTATION,
            subject={
                "module": module,
                "kill_reason": kill_reason.value,
                "smith_confidence": smith_confidence,
                "medic_assessment": medic_assessment,
            },
            message_content={
                "action": "consult",
                "module": module,
                "medic_risk_score": medic_assessment.get("risk_score"),
                "medic_recommendation": medic_assessment.get("recommendation"),
                "false_positive_history": medic_assessment.get("fp_history", 0),
            },
        )

        return negotiation

    async def appeal_kill_decision(
        self,
        kill_report: KillReport,
        appeal_reason: str,
        evidence: Dict[str, Any],
    ) -> Negotiation:
        """
        Appeal a kill decision that Medic believes was incorrect.

        Args:
            kill_report: The kill report to appeal
            appeal_reason: Reason for the appeal
            evidence: Supporting evidence

        Returns:
            Negotiation result
        """
        negotiation = await self._initiate_negotiation(
            negotiation_type=NegotiationType.POST_KILL_APPEAL,
            subject={
                "kill_id": kill_report.kill_id,
                "module": kill_report.target_module,
                "appeal_reason": appeal_reason,
            },
            message_content={
                "action": "appeal",
                "kill_id": kill_report.kill_id,
                "module": kill_report.target_module,
                "appeal_reason": appeal_reason,
                "evidence": evidence,
                "request": "reconsider_kill",
            },
        )

        return negotiation

    async def request_resurrection_clearance(
        self,
        module: str,
        kill_id: str,
        resurrection_reason: str,
        risk_assessment: Dict[str, Any],
    ) -> Negotiation:
        """
        Request Smith's clearance before resurrecting a module.

        Args:
            module: Module to resurrect
            kill_id: Original kill ID
            resurrection_reason: Reason for resurrection
            risk_assessment: Medic's risk assessment

        Returns:
            Negotiation result
        """
        negotiation = await self._initiate_negotiation(
            negotiation_type=NegotiationType.RESURRECTION_CLEARANCE,
            subject={
                "module": module,
                "kill_id": kill_id,
                "reason": resurrection_reason,
            },
            message_content={
                "action": "request_clearance",
                "module": module,
                "kill_id": kill_id,
                "reason": resurrection_reason,
                "risk_score": risk_assessment.get("risk_score"),
                "confidence": risk_assessment.get("confidence"),
                "request": "approve_resurrection",
            },
        )

        return negotiation

    async def query_module_status(
        self,
        module: str,
    ) -> Dict[str, Any]:
        """
        Query Smith about a module's current status.

        Args:
            module: Module to query

        Returns:
            Status information from Smith
        """
        negotiation = await self._initiate_negotiation(
            negotiation_type=NegotiationType.MODULE_STATUS_QUERY,
            subject={"module": module},
            message_content={
                "action": "query_status",
                "module": module,
            },
        )

        if negotiation.outcome == NegotiationOutcome.APPROVED:
            return negotiation.outcome_details or {}

        return {"status": "unknown", "error": "No response from Smith"}

    async def negotiate_thresholds(
        self,
        proposed_thresholds: Dict[str, float],
        justification: str,
    ) -> Negotiation:
        """
        Propose threshold changes to Smith.

        Args:
            proposed_thresholds: Proposed threshold values
            justification: Why we're proposing these changes

        Returns:
            Negotiation result
        """
        negotiation = await self._initiate_negotiation(
            negotiation_type=NegotiationType.THRESHOLD_DISCUSSION,
            subject={
                "proposed_thresholds": proposed_thresholds,
                "justification": justification,
            },
            message_content={
                "action": "propose_thresholds",
                "proposed": proposed_thresholds,
                "justification": justification,
                "based_on": "historical_outcomes",
            },
        )

        return negotiation

    async def _initiate_negotiation(
        self,
        negotiation_type: NegotiationType,
        subject: Dict[str, Any],
        message_content: Dict[str, Any],
    ) -> Negotiation:
        """Initiate a new negotiation."""
        negotiation_id = str(uuid.uuid4())

        negotiation = Negotiation(
            negotiation_id=negotiation_id,
            negotiation_type=negotiation_type,
            state=NegotiationState.INITIATED,
            initiated_at=datetime.utcnow(),
            initiated_by="medic",
            subject=subject,
            timeout_seconds=self.connection.timeout_seconds,
        )

        # Create initial message
        message = NegotiationMessage(
            message_id=str(uuid.uuid4()),
            sender="medic",
            timestamp=datetime.utcnow(),
            message_type=negotiation_type.value,
            content=message_content,
        )
        negotiation.messages.append(message)

        self._negotiations[negotiation_id] = negotiation
        self._stats["total_negotiations"] += 1

        logger.info(
            "Negotiation initiated",
            negotiation_id=negotiation_id,
            type=negotiation_type.value,
        )

        # Send to Smith
        if self.connection.enabled:
            try:
                response = await self._send_and_wait(negotiation, message)
                self._process_response(negotiation, response)
            except asyncio.TimeoutError:
                negotiation.state = NegotiationState.TIMEOUT
                negotiation.outcome = NegotiationOutcome.NO_RESPONSE
                self._stats["timeouts"] += 1
                logger.warning(
                    "Negotiation timeout",
                    negotiation_id=negotiation_id,
                )
        else:
            # Mock response for testing
            negotiation.state = NegotiationState.AGREED
            negotiation.outcome = NegotiationOutcome.APPROVED
            negotiation.outcome_details = {"mock": True}

        negotiation.completed_at = datetime.utcnow()
        self._negotiation_history.append(negotiation)

        if negotiation.outcome in (NegotiationOutcome.APPROVED, NegotiationOutcome.CONDITIONAL):
            self._stats["successful"] += 1
        else:
            self._stats["failed"] += 1

        return negotiation

    async def _send_and_wait(
        self,
        negotiation: Negotiation,
        message: NegotiationMessage,
    ) -> Dict[str, Any]:
        """Send message to Smith and wait for response."""
        negotiation.state = NegotiationState.AWAITING_RESPONSE

        if self.message_sender:
            # Use provided sender
            try:
                response = await asyncio.wait_for(
                    self.message_sender(
                        topic=self.connection.request_topic,
                        message={
                            "negotiation_id": negotiation.negotiation_id,
                            **message.to_dict(),
                        },
                    ),
                    timeout=self.connection.timeout_seconds,
                )
                return response
            except asyncio.TimeoutError:
                raise

        # Default: simulate response
        await asyncio.sleep(0.1)  # Simulate network latency
        return {
            "status": "approved",
            "negotiation_id": negotiation.negotiation_id,
            "smith_response": "acknowledged",
        }

    def _process_response(
        self,
        negotiation: Negotiation,
        response: Dict[str, Any],
    ) -> None:
        """Process Smith's response."""
        # Add response as message
        message = NegotiationMessage(
            message_id=str(uuid.uuid4()),
            sender="smith",
            timestamp=datetime.utcnow(),
            message_type="response",
            content=response,
        )
        negotiation.messages.append(message)

        # Determine outcome
        status = response.get("status", "").lower()

        if status in ("approved", "ok", "agree", "cleared"):
            negotiation.state = NegotiationState.AGREED
            negotiation.outcome = NegotiationOutcome.APPROVED
        elif status in ("conditional", "partial"):
            negotiation.state = NegotiationState.AGREED
            negotiation.outcome = NegotiationOutcome.CONDITIONAL
        elif status in ("denied", "rejected", "disagree"):
            negotiation.state = NegotiationState.DISAGREED
            negotiation.outcome = NegotiationOutcome.DENIED
        elif status in ("defer", "pending"):
            negotiation.state = NegotiationState.IN_DISCUSSION
            negotiation.outcome = NegotiationOutcome.DEFERRED
        else:
            negotiation.state = NegotiationState.DISAGREED
            negotiation.outcome = NegotiationOutcome.NO_RESPONSE

        negotiation.outcome_details = response

        logger.info(
            "Negotiation response received",
            negotiation_id=negotiation.negotiation_id,
            outcome=negotiation.outcome.value,
        )

    async def handle_incoming_message(
        self,
        message: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Handle an incoming message from Smith.

        Args:
            message: The incoming message

        Returns:
            Response to send back
        """
        message_type = message.get("type", "")
        negotiation_id = message.get("negotiation_id")

        logger.debug(
            "Incoming message from Smith",
            message_type=message_type,
            negotiation_id=negotiation_id,
        )

        if message_type == "pre_kill_notification":
            # Smith is asking about a module before killing it
            return await self._handle_pre_kill_notification(message)

        elif message_type == "negotiation_response":
            # Response to our negotiation
            if negotiation_id and negotiation_id in self._negotiations:
                negotiation = self._negotiations[negotiation_id]
                self._process_response(negotiation, message)
            return None

        elif message_type == "threshold_proposal":
            # Smith proposing threshold changes
            return await self._handle_threshold_proposal(message)

        return None

    async def _handle_pre_kill_notification(
        self,
        message: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Handle Smith's pre-kill notification."""
        module = message.get("module")
        kill_reason = message.get("kill_reason")
        confidence = message.get("confidence", 0.5)

        # This would integrate with the decision engine
        # For now, provide a simple response

        response = {
            "type": "pre_kill_response",
            "module": module,
            "medic_position": "no_objection" if confidence > 0.8 else "request_review",
            "reason": "High Smith confidence" if confidence > 0.8 else "Recommend verification",
        }

        return response

    async def _handle_threshold_proposal(
        self,
        message: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Handle Smith's threshold proposal."""
        proposed = message.get("proposed_thresholds", {})

        # Would integrate with threshold adapter
        response = {
            "type": "threshold_response",
            "status": "acknowledged",
            "medic_response": "will_review",
            "proposed_thresholds": proposed,
        }

        return response

    def get_negotiation(self, negotiation_id: str) -> Optional[Negotiation]:
        """Get a negotiation by ID."""
        return self._negotiations.get(negotiation_id)

    def get_active_negotiations(self) -> List[Negotiation]:
        """Get all active negotiations."""
        return [
            n for n in self._negotiations.values()
            if n.state in (
                NegotiationState.INITIATED,
                NegotiationState.AWAITING_RESPONSE,
                NegotiationState.IN_DISCUSSION,
            )
        ]

    def get_history(self, limit: int = 50) -> List[Negotiation]:
        """Get negotiation history."""
        return list(reversed(self._negotiation_history[-limit:]))

    def get_statistics(self) -> Dict[str, Any]:
        """Get negotiation statistics."""
        return {
            **self._stats,
            "active_negotiations": len(self.get_active_negotiations()),
            "success_rate": (
                self._stats["successful"] / self._stats["total_negotiations"]
                if self._stats["total_negotiations"] > 0 else 0.0
            ),
        }


def create_smith_negotiator(
    config: Dict[str, Any],
    message_sender: Optional[Callable] = None,
) -> SmithNegotiator:
    """Factory function to create Smith negotiator."""
    smith_config = config.get("smith", {})
    negotiation_config = smith_config.get("negotiation", {})

    connection = SmithConnection(
        endpoint=smith_config.get("event_bus", {}).get("host", "localhost"),
        request_topic=negotiation_config.get("request_topic", "medic.to_smith"),
        response_topic=negotiation_config.get("response_topic", "smith.to_medic"),
        timeout_seconds=negotiation_config.get("timeout_seconds", 30),
        enabled=negotiation_config.get("enabled", True),
    )

    return SmithNegotiator(
        connection=connection,
        message_sender=message_sender,
    )
