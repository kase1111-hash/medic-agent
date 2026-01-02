"""
Medic Agent Internal Event Bus

Provides pub/sub event handling for internal component communication.
Supports both sync and async event handlers.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import uuid
import weakref

from core.logger import get_logger

logger = get_logger("core.event_bus")


class EventType(Enum):
    """Standard event types in the Medic Agent system."""
    # Kill report events
    KILL_RECEIVED = "kill.received"
    KILL_PROCESSED = "kill.processed"

    # Decision events
    DECISION_MADE = "decision.made"
    DECISION_LOGGED = "decision.logged"

    # Approval events
    PROPOSAL_CREATED = "proposal.created"
    PROPOSAL_QUEUED = "proposal.queued"
    PROPOSAL_APPROVED = "proposal.approved"
    PROPOSAL_DENIED = "proposal.denied"
    PROPOSAL_EXPIRED = "proposal.expired"

    # Resurrection events
    RESURRECTION_STARTED = "resurrection.started"
    RESURRECTION_COMPLETED = "resurrection.completed"
    RESURRECTION_FAILED = "resurrection.failed"
    RESURRECTION_ROLLBACK = "resurrection.rollback"

    # Monitoring events
    MONITORING_STARTED = "monitoring.started"
    MONITORING_STOPPED = "monitoring.stopped"
    ANOMALY_DETECTED = "monitoring.anomaly"
    HEALTH_CHECK_FAILED = "monitoring.health_failed"

    # System events
    AGENT_STARTED = "agent.started"
    AGENT_STOPPED = "agent.stopped"
    CONFIG_CHANGED = "config.changed"
    ERROR_OCCURRED = "error.occurred"


@dataclass
class Event:
    """An event in the system."""
    event_id: str
    event_type: EventType
    timestamp: datetime
    source: str
    payload: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "payload": self.payload,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def create(
        cls,
        event_type: EventType,
        source: str,
        payload: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> "Event":
        """Create a new event."""
        return cls(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.utcnow(),
            source=source,
            payload=payload or {},
            correlation_id=correlation_id,
        )


class EventHandler:
    """Wrapper for event handlers with metadata."""

    def __init__(
        self,
        handler: Callable,
        handler_id: str,
        event_types: Set[EventType],
        is_async: bool = False,
        priority: int = 0,
    ):
        self.handler = handler
        self.handler_id = handler_id
        self.event_types = event_types
        self.is_async = is_async
        self.priority = priority
        self.call_count = 0
        self.last_called: Optional[datetime] = None
        self.errors: List[str] = []


class EventBus:
    """
    Internal event bus for component communication.

    Supports:
    - Multiple subscribers per event type
    - Async and sync handlers
    - Priority ordering
    - Wildcard subscriptions
    - Event history
    """

    def __init__(
        self,
        history_size: int = 1000,
        error_handler: Optional[Callable] = None,
    ):
        self._handlers: Dict[EventType, List[EventHandler]] = {}
        self._wildcard_handlers: List[EventHandler] = []
        self._history: List[Event] = []
        self._history_size = history_size
        self._error_handler = error_handler
        self._lock = asyncio.Lock()

        logger.info("EventBus initialized")

    def subscribe(
        self,
        event_types: EventType | List[EventType],
        handler: Callable,
        priority: int = 0,
    ) -> str:
        """
        Subscribe to one or more event types.

        Args:
            event_types: Single event type or list of types
            handler: Callback function (sync or async)
            priority: Handler priority (higher = called first)

        Returns:
            Handler ID for unsubscription
        """
        if isinstance(event_types, EventType):
            event_types = [event_types]

        handler_id = str(uuid.uuid4())
        is_async = asyncio.iscoroutinefunction(handler)

        event_handler = EventHandler(
            handler=handler,
            handler_id=handler_id,
            event_types=set(event_types),
            is_async=is_async,
            priority=priority,
        )

        for event_type in event_types:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(event_handler)
            # Sort by priority (descending)
            self._handlers[event_type].sort(key=lambda h: -h.priority)

        logger.debug(
            f"Handler subscribed",
            handler_id=handler_id,
            event_types=[et.value for et in event_types],
        )

        return handler_id

    def subscribe_all(self, handler: Callable, priority: int = 0) -> str:
        """Subscribe to all event types."""
        handler_id = str(uuid.uuid4())
        is_async = asyncio.iscoroutinefunction(handler)

        event_handler = EventHandler(
            handler=handler,
            handler_id=handler_id,
            event_types=set(),  # Empty = all
            is_async=is_async,
            priority=priority,
        )

        self._wildcard_handlers.append(event_handler)
        self._wildcard_handlers.sort(key=lambda h: -h.priority)

        logger.debug(f"Wildcard handler subscribed", handler_id=handler_id)

        return handler_id

    def unsubscribe(self, handler_id: str) -> bool:
        """Unsubscribe a handler by ID."""
        found = False

        # Check regular handlers
        for event_type, handlers in self._handlers.items():
            for handler in handlers[:]:
                if handler.handler_id == handler_id:
                    handlers.remove(handler)
                    found = True

        # Check wildcard handlers
        for handler in self._wildcard_handlers[:]:
            if handler.handler_id == handler_id:
                self._wildcard_handlers.remove(handler)
                found = True

        if found:
            logger.debug(f"Handler unsubscribed", handler_id=handler_id)

        return found

    async def emit(self, event: Event) -> None:
        """
        Emit an event to all subscribers.

        Args:
            event: The event to emit
        """
        async with self._lock:
            # Add to history
            self._history.append(event)
            if len(self._history) > self._history_size:
                self._history = self._history[-self._history_size:]

        logger.debug(
            "Emitting event",
            event_type=event.event_type.value,
            event_id=event.event_id,
        )

        # Collect handlers
        handlers = list(self._handlers.get(event.event_type, []))
        handlers.extend(self._wildcard_handlers)
        handlers.sort(key=lambda h: -h.priority)

        # Call handlers
        for handler in handlers:
            try:
                handler.call_count += 1
                handler.last_called = datetime.utcnow()

                if handler.is_async:
                    await handler.handler(event)
                else:
                    handler.handler(event)

            except Exception as e:
                error_msg = f"Handler {handler.handler_id} error: {e}"
                handler.errors.append(error_msg)
                logger.error(error_msg, exc_info=True)

                if self._error_handler:
                    try:
                        self._error_handler(event, e)
                    except Exception:
                        pass

    def emit_sync(self, event: Event) -> None:
        """Emit event synchronously (for non-async contexts)."""
        asyncio.create_task(self.emit(event))

    async def emit_event(
        self,
        event_type: EventType,
        source: str,
        payload: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> Event:
        """Convenience method to create and emit an event."""
        event = Event.create(
            event_type=event_type,
            source=source,
            payload=payload,
            correlation_id=correlation_id,
        )
        await self.emit(event)
        return event

    def get_history(
        self,
        event_type: Optional[EventType] = None,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[Event]:
        """Get event history with optional filtering."""
        events = self._history

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        if since:
            events = [e for e in events if e.timestamp > since]

        return list(reversed(events[-limit:]))

    def get_handler_stats(self) -> Dict[str, Any]:
        """Get statistics for all handlers."""
        all_handlers = []

        for event_type, handlers in self._handlers.items():
            for handler in handlers:
                all_handlers.append({
                    "handler_id": handler.handler_id,
                    "event_types": [et.value for et in handler.event_types],
                    "priority": handler.priority,
                    "call_count": handler.call_count,
                    "last_called": handler.last_called.isoformat() if handler.last_called else None,
                    "error_count": len(handler.errors),
                    "is_async": handler.is_async,
                })

        for handler in self._wildcard_handlers:
            all_handlers.append({
                "handler_id": handler.handler_id,
                "event_types": ["*"],
                "priority": handler.priority,
                "call_count": handler.call_count,
                "last_called": handler.last_called.isoformat() if handler.last_called else None,
                "error_count": len(handler.errors),
                "is_async": handler.is_async,
            })

        return {
            "total_handlers": len(all_handlers),
            "handlers": all_handlers,
            "history_size": len(self._history),
        }

    def clear_history(self) -> None:
        """Clear event history."""
        self._history.clear()


# Global event bus instance
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def create_event_bus(
    history_size: int = 1000,
    error_handler: Optional[Callable] = None,
) -> EventBus:
    """Create a new event bus instance."""
    global _event_bus
    _event_bus = EventBus(
        history_size=history_size,
        error_handler=error_handler,
    )
    return _event_bus


# Convenience decorators
def on_event(*event_types: EventType, priority: int = 0):
    """Decorator to subscribe a function to events."""
    def decorator(func: Callable) -> Callable:
        bus = get_event_bus()
        bus.subscribe(list(event_types), func, priority)
        return func
    return decorator


def on_all_events(priority: int = 0):
    """Decorator to subscribe to all events."""
    def decorator(func: Callable) -> Callable:
        bus = get_event_bus()
        bus.subscribe_all(func, priority)
        return func
    return decorator
