"""
Medic Agent Error Handling

Custom exception hierarchy and error handling utilities.
Based on error patterns defined in the technical specification.
"""

from enum import Enum
from typing import Any, Callable, List, Optional, TypeVar
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
import asyncio
import random

from core.logger import get_logger

logger = get_logger("core.errors")

T = TypeVar('T')


class ErrorCategory(Enum):
    """Categories of errors for classification and handling."""
    CONNECTION = "connection"       # Network/connectivity issues
    TIMEOUT = "timeout"             # Operation timeout
    VALIDATION = "validation"       # Data validation failures
    AUTHORIZATION = "authorization" # Permission/auth issues
    RATE_LIMIT = "rate_limit"       # Rate limiting hit
    INTERNAL = "internal"           # Internal processing errors
    EXTERNAL = "external"           # External service errors
    CONFIGURATION = "configuration" # Config/setup issues


class MedicError(Exception):
    """
    Base exception for Medic Agent.

    All custom exceptions inherit from this class.
    """

    def __init__(
        self,
        message: str,
        category: ErrorCategory,
        recoverable: bool = True,
        context: Optional[dict] = None,
    ):
        self.message = message
        self.category = category
        self.recoverable = recoverable
        self.context = context or {}
        self.timestamp = datetime.now(timezone.utc)
        super().__init__(self.message)

    def to_dict(self) -> dict:
        """Convert to dictionary for logging/serialization."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "category": self.category.value,
            "recoverable": self.recoverable,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
        }


class SmithConnectionError(MedicError):
    """Failed to connect to Smith event bus."""

    def __init__(self, message: str, host: Optional[str] = None, port: Optional[int] = None):
        self.host = host
        self.port = port
        context = {}
        if host:
            context["host"] = host
        if port:
            context["port"] = port
        super().__init__(message, ErrorCategory.CONNECTION, recoverable=True, context=context)


class SIEMQueryError(MedicError):
    """SIEM query failed."""

    def __init__(
        self,
        message: str,
        query_id: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        self.query_id = query_id
        self.status_code = status_code
        context = {}
        if query_id:
            context["query_id"] = query_id
        if status_code:
            context["status_code"] = status_code
        super().__init__(message, ErrorCategory.EXTERNAL, recoverable=True, context=context)


class SIEMTimeoutError(MedicError):
    """SIEM query timed out."""

    def __init__(self, message: str, query_id: Optional[str] = None, timeout_seconds: Optional[float] = None):
        self.query_id = query_id
        self.timeout_seconds = timeout_seconds
        context = {}
        if query_id:
            context["query_id"] = query_id
        if timeout_seconds:
            context["timeout_seconds"] = timeout_seconds
        super().__init__(message, ErrorCategory.TIMEOUT, recoverable=True, context=context)


class DecisionError(MedicError):
    """Decision engine failure."""

    def __init__(self, message: str, kill_id: str, reason: Optional[str] = None):
        self.kill_id = kill_id
        self.reason = reason
        context = {"kill_id": kill_id}
        if reason:
            context["reason"] = reason
        super().__init__(message, ErrorCategory.INTERNAL, recoverable=False, context=context)


class ResurrectionError(MedicError):
    """Resurrection workflow failure."""

    def __init__(
        self,
        message: str,
        request_id: str,
        should_rollback: bool = False,
        target_module: Optional[str] = None,
    ):
        self.request_id = request_id
        self.should_rollback = should_rollback
        self.target_module = target_module
        context = {"request_id": request_id, "should_rollback": should_rollback}
        if target_module:
            context["target_module"] = target_module
        super().__init__(message, ErrorCategory.INTERNAL, recoverable=True, context=context)


class RollbackError(MedicError):
    """Rollback operation failure."""

    def __init__(self, message: str, request_id: str, reason: Optional[str] = None):
        self.request_id = request_id
        self.reason = reason
        context = {"request_id": request_id}
        if reason:
            context["reason"] = reason
        super().__init__(message, ErrorCategory.INTERNAL, recoverable=False, context=context)


class ValidationError(MedicError):
    """Data validation failure.

    Can be raised with just a message, or with field and value for more context.
    """

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Any = None,
    ):
        self.field = field
        self.value = value
        context: Dict[str, Any] = {}
        if field is not None:
            context["field"] = field
        if value is not None:
            context["value"] = str(value)[:100]
        super().__init__(message, ErrorCategory.VALIDATION, recoverable=False, context=context)


class ConfigurationError(MedicError):
    """Configuration/setup issue."""

    def __init__(self, message: str, config_key: Optional[str] = None):
        self.config_key = config_key
        context = {}
        if config_key:
            context["config_key"] = config_key
        super().__init__(message, ErrorCategory.CONFIGURATION, recoverable=False, context=context)


class RateLimitError(MedicError):
    """Rate limit exceeded."""

    def __init__(
        self,
        message: str,
        limit: Optional[int] = None,
        retry_after_seconds: Optional[int] = None,
    ):
        self.limit = limit
        self.retry_after_seconds = retry_after_seconds
        context = {}
        if limit:
            context["limit"] = limit
        if retry_after_seconds:
            context["retry_after_seconds"] = retry_after_seconds
        super().__init__(message, ErrorCategory.RATE_LIMIT, recoverable=True, context=context)


class AuthorizationError(MedicError):
    """Permission/authorization failure."""

    def __init__(self, message: str, required_permission: Optional[str] = None):
        self.required_permission = required_permission
        context = {}
        if required_permission:
            context["required_permission"] = required_permission
        super().__init__(message, ErrorCategory.AUTHORIZATION, recoverable=False, context=context)


class MonitoringError(MedicError):
    """Post-resurrection monitoring failure."""

    def __init__(
        self,
        message: str,
        monitor_id: str,
        target_module: Optional[str] = None,
    ):
        self.monitor_id = monitor_id
        self.target_module = target_module
        context = {"monitor_id": monitor_id}
        if target_module:
            context["target_module"] = target_module
        super().__init__(message, ErrorCategory.INTERNAL, recoverable=True, context=context)


class QueueError(MedicError):
    """Approval queue operation failure."""

    def __init__(self, message: str, item_id: Optional[str] = None):
        self.item_id = item_id
        context = {}
        if item_id:
            context["item_id"] = item_id
        super().__init__(message, ErrorCategory.INTERNAL, recoverable=True, context=context)


# Retry Policy and Utilities

@dataclass
class RetryPolicy:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    exponential_base: float = 2.0
    jitter: bool = True
    retryable_categories: List[ErrorCategory] = field(default_factory=list)

    def __post_init__(self):
        if not self.retryable_categories:
            self.retryable_categories = [
                ErrorCategory.CONNECTION,
                ErrorCategory.TIMEOUT,
                ErrorCategory.RATE_LIMIT,
            ]

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for a given attempt number."""
        delay = self.initial_delay_seconds * (self.exponential_base ** attempt)
        delay = min(delay, self.max_delay_seconds)

        if self.jitter:
            delay = delay * (0.5 + random.random())

        return delay

    def should_retry(self, error: Exception) -> bool:
        """Check if an error should be retried."""
        if isinstance(error, MedicError):
            return error.recoverable and error.category in self.retryable_categories
        return False


async def with_retry(
    operation: Callable[[], T],
    policy: RetryPolicy,
    on_retry: Optional[Callable[[Exception, int], None]] = None,
) -> T:
    """
    Execute an async operation with retry policy.

    Args:
        operation: Async callable to execute
        policy: Retry policy configuration
        on_retry: Optional callback for retry events

    Returns:
        Result of the operation

    Raises:
        Last exception if all retries exhausted
    """
    last_error: Optional[Exception] = None

    for attempt in range(policy.max_attempts):
        try:
            return await operation()
        except Exception as e:
            last_error = e

            if not policy.should_retry(e) or attempt == policy.max_attempts - 1:
                raise

            delay = policy.get_delay(attempt)

            logger.warning(
                f"Retry attempt {attempt + 1}/{policy.max_attempts}",
                error=str(e),
                delay_seconds=round(delay, 2),
            )

            if on_retry:
                on_retry(e, attempt + 1)

            await asyncio.sleep(delay)

    raise last_error


def with_retry_sync(
    operation: Callable[[], T],
    policy: RetryPolicy,
    on_retry: Optional[Callable[[Exception, int], None]] = None,
) -> T:
    """
    Execute a synchronous operation with retry policy.

    Args:
        operation: Callable to execute
        policy: Retry policy configuration
        on_retry: Optional callback for retry events

    Returns:
        Result of the operation

    Raises:
        Last exception if all retries exhausted
    """
    import time

    last_error: Optional[Exception] = None

    for attempt in range(policy.max_attempts):
        try:
            return operation()
        except Exception as e:
            last_error = e

            if not policy.should_retry(e) or attempt == policy.max_attempts - 1:
                raise

            delay = policy.get_delay(attempt)

            logger.warning(
                f"Retry attempt {attempt + 1}/{policy.max_attempts}",
                error=str(e),
                delay_seconds=round(delay, 2),
            )

            if on_retry:
                on_retry(e, attempt + 1)

            time.sleep(delay)

    raise last_error


# Circuit Breaker Pattern

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"            # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreaker:
    """
    Circuit breaker for external service calls.

    Prevents cascading failures by temporarily blocking
    requests to failing services.
    """
    name: str
    failure_threshold: int = 5
    recovery_timeout_seconds: int = 60
    half_open_max_calls: int = 3

    state: CircuitState = field(default=CircuitState.CLOSED)
    failure_count: int = field(default=0)
    success_count: int = field(default=0)
    last_failure_time: Optional[datetime] = field(default=None)
    half_open_calls: int = field(default=0)

    def can_execute(self) -> bool:
        """Check if request can proceed."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self.last_failure_time:
                elapsed = (datetime.now(timezone.utc) - self.last_failure_time).total_seconds()
                if elapsed >= self.recovery_timeout_seconds:
                    self._transition_to_half_open()
                    return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            return self.half_open_calls < self.half_open_max_calls

        return False

    def record_success(self) -> None:
        """Record successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.half_open_max_calls:
                self._transition_to_closed()
        else:
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.now(timezone.utc)

        if self.state == CircuitState.HALF_OPEN:
            self._transition_to_open()
        elif self.failure_count >= self.failure_threshold:
            self._transition_to_open()

    def _transition_to_open(self) -> None:
        """Transition to open state."""
        logger.warning(
            f"Circuit breaker '{self.name}' opened",
            failure_count=self.failure_count,
        )
        self.state = CircuitState.OPEN

    def _transition_to_half_open(self) -> None:
        """Transition to half-open state."""
        logger.info("Circuit breaker '%s' half-open", self.name)
        self.state = CircuitState.HALF_OPEN
        self.half_open_calls = 0
        self.success_count = 0

    def _transition_to_closed(self) -> None:
        """Transition to closed state."""
        logger.info("Circuit breaker '%s' closed", self.name)
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.half_open_calls = 0

    def get_state(self) -> dict:
        """Get current circuit breaker state."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "last_failure": self.last_failure_time.isoformat() if self.last_failure_time else None,
        }


class CircuitBreakerOpen(MedicError):
    """Circuit breaker is open, request rejected."""

    def __init__(self, circuit_name: str):
        self.circuit_name = circuit_name
        super().__init__(
            f"Circuit breaker '{circuit_name}' is open",
            ErrorCategory.EXTERNAL,
            recoverable=True,
            context={"circuit_name": circuit_name},
        )


async def with_circuit_breaker(
    operation: Callable[[], T],
    circuit: CircuitBreaker,
) -> T:
    """
    Execute an async operation with circuit breaker protection.

    Args:
        operation: Async callable to execute
        circuit: Circuit breaker instance

    Returns:
        Result of the operation

    Raises:
        CircuitBreakerOpen: If circuit is open
        Original exception: If operation fails
    """
    if not circuit.can_execute():
        raise CircuitBreakerOpen(circuit.name)

    if circuit.state == CircuitState.HALF_OPEN:
        circuit.half_open_calls += 1

    try:
        result = await operation()
        circuit.record_success()
        return result
    except Exception as e:
        circuit.record_failure()
        raise


# Factory functions for common configurations

def create_siem_retry_policy() -> RetryPolicy:
    """Create retry policy optimized for SIEM queries."""
    return RetryPolicy(
        max_attempts=3,
        initial_delay_seconds=2.0,
        max_delay_seconds=30.0,
        exponential_base=2.0,
        jitter=True,
        retryable_categories=[
            ErrorCategory.CONNECTION,
            ErrorCategory.TIMEOUT,
            ErrorCategory.RATE_LIMIT,
            ErrorCategory.EXTERNAL,
        ],
    )


def create_smith_retry_policy() -> RetryPolicy:
    """Create retry policy optimized for Smith connection."""
    return RetryPolicy(
        max_attempts=5,
        initial_delay_seconds=1.0,
        max_delay_seconds=60.0,
        exponential_base=2.0,
        jitter=True,
        retryable_categories=[
            ErrorCategory.CONNECTION,
            ErrorCategory.TIMEOUT,
        ],
    )


def create_siem_circuit_breaker() -> CircuitBreaker:
    """Create circuit breaker for SIEM service."""
    return CircuitBreaker(
        name="siem",
        failure_threshold=5,
        recovery_timeout_seconds=60,
        half_open_max_calls=3,
    )


def create_smith_circuit_breaker() -> CircuitBreaker:
    """Create circuit breaker for Smith connection."""
    return CircuitBreaker(
        name="smith",
        failure_threshold=10,
        recovery_timeout_seconds=30,
        half_open_max_calls=5,
    )
