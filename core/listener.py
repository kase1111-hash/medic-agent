"""
Medic Agent Kill Report Listener

Subscribes to Smith kill feed and processes incoming kill notifications.
Supports multiple transport backends (Redis, RabbitMQ, etc.).
"""

import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import AsyncIterator, Callable, Dict, List, Optional, Any
import uuid

from core.models import KillReport
from core.logger import get_logger, set_trace_context, LogContext

logger = get_logger("core.listener")


class KillReportListener(ABC):
    """
    Abstract interface for listening to Smith kill notifications.

    Implementations should handle connection management, message parsing,
    and acknowledgment for different transport backends.
    """

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to Smith event bus."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully disconnect from event bus."""
        pass

    @abstractmethod
    async def listen(self) -> AsyncIterator[KillReport]:
        """Yield incoming kill reports as async iterator."""
        pass

    @abstractmethod
    def register_handler(self, handler: Callable[[KillReport], Any]) -> None:
        """Register a callback handler for incoming reports."""
        pass

    @abstractmethod
    async def acknowledge(self, kill_id: str) -> bool:
        """Acknowledge processing of a kill report."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the connection is healthy."""
        pass


class SmithEventListener(KillReportListener):
    """
    Redis Streams-based implementation of Smith kill notification listener.

    Connects to Smith's event bus and processes KILL_REPORT messages.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        topic: str = "smith.events.kill_notifications",
        consumer_group: str = "medic-agent",
        consumer_name: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.topic = topic
        self.consumer_group = consumer_group
        self.consumer_name = consumer_name or f"medic-{uuid.uuid4().hex[:8]}"

        self._redis: Optional[Any] = None
        self._connected = False
        self._handlers: List[Callable[[KillReport], Any]] = []
        self._pending_acks: Dict[str, str] = {}  # kill_id -> message_id

    async def connect(self) -> None:
        """Establish connection to Redis Streams."""
        try:
            import redis.asyncio as redis
        except ImportError:
            logger.warning("redis package not installed, using mock mode")
            self._connected = True
            return

        try:
            self._redis = redis.Redis(host=self.host, port=self.port, decode_responses=True)
            await self._redis.ping()

            # Create consumer group if it doesn't exist
            try:
                await self._redis.xgroup_create(
                    self.topic, self.consumer_group, id="0", mkstream=True
                )
                logger.info(
                    f"Created consumer group '{self.consumer_group}' for topic '{self.topic}'"
                )
            except redis.ResponseError as e:
                if "BUSYGROUP" not in str(e):
                    raise

            self._connected = True
            logger.info(
                "Connected to Smith event bus",
                host=self.host,
                port=self.port,
                topic=self.topic,
            )

        except Exception as e:
            logger.error(f"Failed to connect to Smith event bus: {e}")
            raise

    async def disconnect(self) -> None:
        """Gracefully disconnect from Redis."""
        if self._redis:
            await self._redis.close()
            self._redis = None
        self._connected = False
        logger.info("Disconnected from Smith event bus")

    async def listen(self) -> AsyncIterator[KillReport]:
        """
        Yield incoming kill reports from Smith.

        This is an infinite async generator that continuously reads
        from the event stream. Use it with `async for`:

            async for kill_report in listener.listen():
                process(kill_report)
        """
        if not self._connected:
            await self.connect()

        logger.info("Starting to listen for kill reports")

        while self._connected:
            try:
                kill_report = await self._read_next_message()
                if kill_report:
                    yield kill_report
                else:
                    # No message available, brief sleep before retry
                    await asyncio.sleep(0.1)

            except asyncio.CancelledError:
                logger.info("Listen loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error reading from event bus: {e}")
                await asyncio.sleep(1.0)  # Backoff on error

    async def _read_next_message(self) -> Optional[KillReport]:
        """Read and parse the next message from the stream."""
        if not self._redis:
            # Mock mode - return None (no messages)
            return None

        try:
            # Read from consumer group
            messages = await self._redis.xreadgroup(
                self.consumer_group,
                self.consumer_name,
                {self.topic: ">"},
                count=1,
                block=1000,  # 1 second timeout
            )

            if not messages:
                return None

            for stream_name, stream_messages in messages:
                for message_id, message_data in stream_messages:
                    # Set trace context for this message
                    set_trace_context()

                    try:
                        kill_report = self._parse_message(message_data)
                        self._pending_acks[kill_report.kill_id] = message_id

                        logger.info(
                            "Received kill report",
                            kill_id=kill_report.kill_id,
                            target_module=kill_report.target_module,
                            severity=kill_report.severity.value,
                        )

                        return kill_report

                    except Exception as e:
                        logger.error(
                            f"Failed to parse kill report: {e}",
                            message_id=message_id,
                        )
                        # Acknowledge bad messages to prevent reprocessing
                        await self._redis.xack(
                            self.topic, self.consumer_group, message_id
                        )

        except Exception as e:
            logger.error(f"Error reading stream: {e}")

        return None

    def _parse_message(self, message_data: Dict[str, str]) -> KillReport:
        """Parse raw message data into a KillReport."""
        # Message format: {"version": "1.0", "message_type": "KILL_REPORT", "payload": {...}}
        if "payload" in message_data:
            # Full message format
            payload = json.loads(message_data["payload"])
        elif "data" in message_data:
            # Alternative format
            payload = json.loads(message_data["data"])
        else:
            # Direct payload
            payload = {k: v for k, v in message_data.items()}
            # Parse any JSON strings
            for key in ["evidence", "dependencies", "metadata"]:
                if key in payload and isinstance(payload[key], str):
                    payload[key] = json.loads(payload[key])

        return KillReport.from_dict(payload)

    def register_handler(self, handler: Callable[[KillReport], Any]) -> None:
        """Register a callback handler for incoming kill reports."""
        self._handlers.append(handler)
        logger.debug(f"Registered handler: {handler.__name__}")

    async def acknowledge(self, kill_id: str) -> bool:
        """
        Acknowledge successful processing of a kill report.

        This removes the message from the pending list in Redis.
        """
        message_id = self._pending_acks.pop(kill_id, None)
        if not message_id:
            logger.warning(f"No pending ack found for kill_id: {kill_id}")
            return False

        if self._redis:
            try:
                await self._redis.xack(self.topic, self.consumer_group, message_id)
                logger.debug(f"Acknowledged kill report", kill_id=kill_id)
                return True
            except Exception as e:
                logger.error(f"Failed to acknowledge message: {e}", kill_id=kill_id)
                return False

        return True  # Mock mode

    async def health_check(self) -> bool:
        """Check if the connection to Smith event bus is healthy."""
        if not self._redis:
            return self._connected  # Mock mode

        try:
            await self._redis.ping()
            return True
        except Exception:
            return False


class MockSmithListener(KillReportListener):
    """
    Mock listener for testing and development.

    Generates synthetic kill reports at configurable intervals.
    """

    def __init__(
        self,
        interval_seconds: float = 5.0,
        modules: Optional[List[str]] = None,
    ):
        self.interval_seconds = interval_seconds
        self.modules = modules or ["auth-service", "api-gateway", "data-processor"]
        self._connected = False
        self._handlers: List[Callable[[KillReport], Any]] = []
        self._acked: set = set()

    async def connect(self) -> None:
        """Mock connection."""
        self._connected = True
        logger.info("Mock Smith listener connected")

    async def disconnect(self) -> None:
        """Mock disconnection."""
        self._connected = False
        logger.info("Mock Smith listener disconnected")

    async def listen(self) -> AsyncIterator[KillReport]:
        """Generate mock kill reports at regular intervals."""
        import random
        from core.models import KillReason, Severity

        logger.info("Mock listener starting to generate kill reports")

        while self._connected:
            await asyncio.sleep(self.interval_seconds)

            if not self._connected:
                break

            set_trace_context()

            kill_report = KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                target_module=random.choice(self.modules),
                target_instance_id=f"instance-{random.randint(1, 100):03d}",
                kill_reason=random.choice(list(KillReason)),
                severity=random.choice(list(Severity)),
                confidence_score=random.uniform(0.4, 0.95),
                evidence=[f"evidence-{i}" for i in range(random.randint(1, 3))],
                dependencies=[],
                source_agent="smith-mock",
                metadata={"mock": True},
            )

            logger.info(
                "Generated mock kill report",
                kill_id=kill_report.kill_id,
                target_module=kill_report.target_module,
            )

            yield kill_report

    def register_handler(self, handler: Callable[[KillReport], Any]) -> None:
        """Register handler."""
        self._handlers.append(handler)

    async def acknowledge(self, kill_id: str) -> bool:
        """Mock acknowledgment."""
        self._acked.add(kill_id)
        return True

    async def health_check(self) -> bool:
        """Mock health check."""
        return self._connected


def create_listener(config: Dict[str, Any]) -> KillReportListener:
    """
    Factory function to create the appropriate listener based on config.

    Args:
        config: Configuration dictionary with smith connection settings

    Returns:
        Configured KillReportListener instance
    """
    event_bus_config = config.get("smith", {}).get("event_bus", {})
    bus_type = event_bus_config.get("type", "redis")

    if bus_type == "mock":
        return MockSmithListener(
            interval_seconds=event_bus_config.get("interval_seconds", 5.0),
            modules=event_bus_config.get("modules"),
        )

    # Default to Redis-based listener
    return SmithEventListener(
        host=event_bus_config.get("host", "localhost"),
        port=event_bus_config.get("port", 6379),
        topic=event_bus_config.get("topic", "smith.events.kill_notifications"),
        consumer_group=event_bus_config.get("consumer_group", "medic-agent"),
    )
