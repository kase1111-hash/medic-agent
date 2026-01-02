"""
Medic Agent Approval Queue

Manages the queue of resurrection proposals awaiting human review.
Provides persistence and notification capabilities.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import threading

from execution.recommendation import ResurrectionProposal, RecommendationType
from core.models import (
    ResurrectionDecision,
    ResurrectionRequest,
    ResurrectionStatus,
    DecisionOutcome,
)
from core.logger import get_logger

logger = get_logger("interfaces.approval_queue")


class QueueItemStatus(Enum):
    """Status of an item in the approval queue."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass
class QueueItem:
    """An item in the approval queue."""
    item_id: str
    proposal: ResurrectionProposal
    status: QueueItemStatus
    created_at: datetime
    expires_at: datetime
    priority: int = 0  # Higher = more urgent

    # Review tracking
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None

    # Notifications
    notifications_sent: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "item_id": self.item_id,
            "proposal_id": self.proposal.proposal_id,
            "kill_id": self.proposal.kill_report.kill_id,
            "target_module": self.proposal.kill_report.target_module,
            "recommendation": self.proposal.recommendation.value,
            "urgency": self.proposal.urgency.value,
            "risk_level": self.proposal.decision.risk_level.value,
            "risk_score": self.proposal.decision.risk_score,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "priority": self.priority,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_notes": self.review_notes,
            "summary": self.proposal.summary,
        }

    def is_expired(self) -> bool:
        """Check if the item has expired."""
        return datetime.utcnow() > self.expires_at


class ApprovalQueue(ABC):
    """
    Abstract interface for approval queue management.

    Manages the queue of resurrection proposals awaiting
    human review and approval.
    """

    @abstractmethod
    async def enqueue(self, proposal: ResurrectionProposal) -> str:
        """Add proposal to approval queue. Returns queue_item_id."""
        pass

    @abstractmethod
    async def dequeue(self, item_id: str) -> Optional[QueueItem]:
        """Remove and return item from queue."""
        pass

    @abstractmethod
    async def approve(
        self,
        item_id: str,
        approver: str,
        notes: Optional[str] = None,
    ) -> ResurrectionRequest:
        """Approve a queued proposal."""
        pass

    @abstractmethod
    async def deny(
        self,
        item_id: str,
        denier: str,
        reason: str,
    ) -> None:
        """Deny a queued proposal."""
        pass

    @abstractmethod
    async def list_pending(self, limit: int = 50) -> List[QueueItem]:
        """List pending items in queue."""
        pass

    @abstractmethod
    async def get_item(self, item_id: str) -> Optional[QueueItem]:
        """Get a specific queue item."""
        pass

    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        pass


class InMemoryApprovalQueue(ApprovalQueue):
    """
    In-memory implementation of the approval queue.

    Suitable for development and single-instance deployments.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        persistence_path: Optional[str] = None,
    ):
        self.config = config or {}
        self.persistence_path = Path(persistence_path) if persistence_path else None

        # Queue settings
        self.max_pending = self.config.get("max_pending", 100)
        self.default_timeout_hours = self.config.get("timeout_hours", 24)

        # In-memory storage
        self._queue: Dict[str, QueueItem] = {}
        self._lock = threading.Lock()

        # Event callbacks
        self._on_enqueue: List[Callable] = []
        self._on_approve: List[Callable] = []
        self._on_deny: List[Callable] = []
        self._on_expire: List[Callable] = []

        # Load persisted state if available
        if self.persistence_path:
            self._load_state()

        logger.info("Approval queue initialized")

    async def enqueue(self, proposal: ResurrectionProposal) -> str:
        """Add a proposal to the queue."""
        with self._lock:
            # Check capacity
            pending_count = sum(
                1 for item in self._queue.values()
                if item.status == QueueItemStatus.PENDING
            )
            if pending_count >= self.max_pending:
                raise ValueError(f"Queue at capacity ({self.max_pending})")

            # Calculate priority based on urgency
            from execution.recommendation import UrgencyLevel
            priority_map = {
                UrgencyLevel.CRITICAL: 100,
                UrgencyLevel.HIGH: 75,
                UrgencyLevel.MEDIUM: 50,
                UrgencyLevel.LOW: 25,
            }
            priority = priority_map.get(proposal.urgency, 50)

            # Create queue item
            item = QueueItem(
                item_id=proposal.proposal_id,
                proposal=proposal,
                status=QueueItemStatus.PENDING,
                created_at=datetime.utcnow(),
                expires_at=proposal.expires_at,
                priority=priority,
            )

            self._queue[item.item_id] = item
            self._persist_state()

        logger.info(
            "Proposal enqueued",
            item_id=item.item_id,
            target_module=proposal.kill_report.target_module,
            priority=priority,
        )

        # Trigger callbacks
        for callback in self._on_enqueue:
            try:
                await callback(item)
            except Exception as e:
                logger.error(f"Enqueue callback failed: {e}")

        return item.item_id

    async def dequeue(self, item_id: str) -> Optional[QueueItem]:
        """Remove and return an item from the queue."""
        with self._lock:
            item = self._queue.pop(item_id, None)
            if item:
                self._persist_state()
        return item

    async def approve(
        self,
        item_id: str,
        approver: str,
        notes: Optional[str] = None,
    ) -> ResurrectionRequest:
        """Approve a queued proposal."""
        with self._lock:
            item = self._queue.get(item_id)
            if not item:
                raise ValueError(f"Item not found: {item_id}")

            if item.status != QueueItemStatus.PENDING:
                raise ValueError(f"Item not pending: {item.status.value}")

            if item.is_expired():
                item.status = QueueItemStatus.EXPIRED
                self._persist_state()
                raise ValueError("Item has expired")

            # Update item
            item.status = QueueItemStatus.APPROVED
            item.reviewed_by = approver
            item.reviewed_at = datetime.utcnow()
            item.review_notes = notes

            # Update proposal
            item.proposal.status = "approved"
            item.proposal.reviewed_by = approver
            item.proposal.reviewed_at = item.reviewed_at
            item.proposal.review_notes = notes

            self._persist_state()

        logger.info(
            "Proposal approved",
            item_id=item_id,
            approver=approver,
            target_module=item.proposal.kill_report.target_module,
        )

        # Create resurrection request
        request = ResurrectionRequest.from_decision(
            item.proposal.decision,
            item.proposal.kill_report,
        )
        request.status = ResurrectionStatus.APPROVED
        request.approved_at = item.reviewed_at
        request.approved_by = approver

        # Trigger callbacks
        for callback in self._on_approve:
            try:
                await callback(item, request)
            except Exception as e:
                logger.error(f"Approve callback failed: {e}")

        return request

    async def deny(
        self,
        item_id: str,
        denier: str,
        reason: str,
    ) -> None:
        """Deny a queued proposal."""
        with self._lock:
            item = self._queue.get(item_id)
            if not item:
                raise ValueError(f"Item not found: {item_id}")

            if item.status != QueueItemStatus.PENDING:
                raise ValueError(f"Item not pending: {item.status.value}")

            # Update item
            item.status = QueueItemStatus.DENIED
            item.reviewed_by = denier
            item.reviewed_at = datetime.utcnow()
            item.review_notes = reason

            # Update proposal
            item.proposal.status = "denied"
            item.proposal.reviewed_by = denier
            item.proposal.reviewed_at = item.reviewed_at
            item.proposal.review_notes = reason

            self._persist_state()

        logger.info(
            "Proposal denied",
            item_id=item_id,
            denier=denier,
            reason=reason,
        )

        # Trigger callbacks
        for callback in self._on_deny:
            try:
                await callback(item, reason)
            except Exception as e:
                logger.error(f"Deny callback failed: {e}")

    async def list_pending(self, limit: int = 50) -> List[QueueItem]:
        """List pending items sorted by priority and age."""
        with self._lock:
            # Check for expired items
            await self._check_expirations()

            pending = [
                item for item in self._queue.values()
                if item.status == QueueItemStatus.PENDING
            ]

        # Sort by priority (desc) then by creation time (asc)
        pending.sort(key=lambda x: (-x.priority, x.created_at))

        return pending[:limit]

    async def get_item(self, item_id: str) -> Optional[QueueItem]:
        """Get a specific queue item."""
        return self._queue.get(item_id)

    async def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        with self._lock:
            total = len(self._queue)
            by_status = {}
            by_urgency = {}

            for item in self._queue.values():
                # Count by status
                status = item.status.value
                by_status[status] = by_status.get(status, 0) + 1

                # Count by urgency (pending only)
                if item.status == QueueItemStatus.PENDING:
                    urgency = item.proposal.urgency.value
                    by_urgency[urgency] = by_urgency.get(urgency, 0) + 1

            pending = by_status.get("pending", 0)

        return {
            "total_items": total,
            "pending_items": pending,
            "capacity": self.max_pending,
            "utilization": pending / self.max_pending if self.max_pending > 0 else 0,
            "by_status": by_status,
            "by_urgency": by_urgency,
        }

    async def _check_expirations(self) -> None:
        """Check and expire old items."""
        now = datetime.utcnow()
        expired = []

        for item_id, item in self._queue.items():
            if item.status == QueueItemStatus.PENDING and item.is_expired():
                item.status = QueueItemStatus.EXPIRED
                expired.append(item)

        if expired:
            self._persist_state()
            logger.info(f"Expired {len(expired)} queue items")

            for item in expired:
                for callback in self._on_expire:
                    try:
                        await callback(item)
                    except Exception as e:
                        logger.error(f"Expire callback failed: {e}")

    def _persist_state(self) -> None:
        """Persist queue state to disk."""
        if not self.persistence_path:
            return

        try:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)

            # Serialize queue items (without full proposal objects)
            state = {
                "items": [item.to_dict() for item in self._queue.values()],
                "saved_at": datetime.utcnow().isoformat(),
            }

            with open(self.persistence_path, "w") as f:
                json.dump(state, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to persist queue state: {e}")

    def _load_state(self) -> None:
        """Load queue state from disk."""
        if not self.persistence_path or not self.persistence_path.exists():
            return

        try:
            with open(self.persistence_path, "r") as f:
                state = json.load(f)

            # Note: Full proposal reconstruction would require additional data
            # For now, just log that we found persisted state
            logger.info(
                f"Found persisted queue state with {len(state.get('items', []))} items"
            )

        except Exception as e:
            logger.error(f"Failed to load queue state: {e}")

    def on_enqueue(self, callback: Callable) -> None:
        """Register callback for enqueue events."""
        self._on_enqueue.append(callback)

    def on_approve(self, callback: Callable) -> None:
        """Register callback for approve events."""
        self._on_approve.append(callback)

    def on_deny(self, callback: Callable) -> None:
        """Register callback for deny events."""
        self._on_deny.append(callback)

    def on_expire(self, callback: Callable) -> None:
        """Register callback for expiration events."""
        self._on_expire.append(callback)


def create_approval_queue(config: Dict[str, Any]) -> ApprovalQueue:
    """Factory function to create an approval queue."""
    queue_config = config.get("interfaces", {}).get("approval_queue", {})
    persistence_path = config.get("data_dir", "data") + "/approval_queue.json"

    return InMemoryApprovalQueue(
        config=queue_config,
        persistence_path=persistence_path,
    )
