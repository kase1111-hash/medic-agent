"""
Medic Agent Structured Logging

Provides JSON-structured logging with correlation IDs and context fields
for consistent, queryable log output.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import uuid
from contextvars import ContextVar

# Context variables for request tracing
_trace_id: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)
_span_id: ContextVar[Optional[str]] = ContextVar("span_id", default=None)
_context_fields: ContextVar[Dict[str, Any]] = ContextVar("context_fields", default={})


def set_trace_context(trace_id: Optional[str] = None, span_id: Optional[str] = None) -> None:
    """Set trace context for correlation."""
    _trace_id.set(trace_id or str(uuid.uuid4()))
    _span_id.set(span_id or str(uuid.uuid4())[:8])


def get_trace_id() -> Optional[str]:
    """Get current trace ID."""
    return _trace_id.get()


def get_span_id() -> Optional[str]:
    """Get current span ID."""
    return _span_id.get()


def set_context_field(key: str, value: Any) -> None:
    """Set a context field that will be included in all subsequent logs."""
    current = _context_fields.get().copy()
    current[key] = value
    _context_fields.set(current)


def clear_context_fields() -> None:
    """Clear all context fields."""
    _context_fields.set({})


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs as JSON objects.

    Each log entry includes:
    - timestamp: ISO-8601 formatted time
    - level: Log level name
    - logger: Logger name
    - message: Log message
    - context: Additional context fields
    - trace_id/span_id: Correlation IDs
    - exception: Exception info if present
    """

    def __init__(self, include_extra_fields: bool = True):
        super().__init__()
        self.include_extra_fields = include_extra_fields
        self._structured_fields = {
            "kill_id", "decision_id", "request_id", "query_id",
            "target_module", "source_agent", "outcome", "risk_level"
        }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add trace context
        trace_id = get_trace_id()
        span_id = get_span_id()
        if trace_id:
            log_entry["trace_id"] = trace_id
        if span_id:
            log_entry["span_id"] = span_id

        # Add context fields from ContextVar
        context = _context_fields.get()
        if context:
            log_entry["context"] = context.copy()
        else:
            log_entry["context"] = {}

        # Extract structured fields from record
        if self.include_extra_fields:
            for field in self._structured_fields:
                if hasattr(record, field):
                    log_entry["context"][field] = getattr(record, field)

        # Add any extra kwargs passed to the log call
        if hasattr(record, "extra_data") and record.extra_data:
            log_entry["context"].update(record.extra_data)

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add source location for debug level
        if record.levelno <= logging.DEBUG:
            log_entry["source"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        return json.dumps(log_entry, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable text formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as colored text."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname

        if self.use_colors:
            color = self.COLORS.get(level, "")
            level_str = f"{color}{level:8}{self.RESET}"
        else:
            level_str = f"{level:8}"

        # Build message parts
        parts = [f"[{timestamp}] {level_str} {record.name}: {record.getMessage()}"]

        # Add trace context if present
        trace_id = get_trace_id()
        if trace_id:
            parts.append(f"  trace_id={trace_id[:8]}")

        # Add structured fields
        for field in ["kill_id", "decision_id", "request_id"]:
            if hasattr(record, field):
                parts.append(f"  {field}={getattr(record, field)}")

        # Add exception if present
        if record.exc_info:
            parts.append("\n" + self.formatException(record.exc_info))

        return "".join(parts)


class MedicLogger(logging.Logger):
    """
    Extended logger with support for structured context fields.

    Usage:
        logger = get_logger("medic.core")
        logger.info("Processing kill report", kill_id="abc123", target_module="auth")
    """

    def _log(
        self,
        level: int,
        msg: object,
        args: tuple,
        exc_info: Any = None,
        extra: Optional[Dict[str, Any]] = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        **kwargs: Any,
    ) -> None:
        """Override _log to support kwargs as structured fields."""
        if extra is None:
            extra = {}

        # Store extra kwargs as structured data
        if kwargs:
            extra["extra_data"] = kwargs
            # Also set as attributes for field extraction
            for key, value in kwargs.items():
                extra[key] = value

        super()._log(level, msg, args, exc_info, extra, stack_info, stacklevel + 1)


# Set our custom logger class
logging.setLoggerClass(MedicLogger)


def configure_logging(
    level: str = "INFO",
    format_type: str = "json",
    log_file: Optional[str] = None,
    rotation: str = "daily",
    retention_days: int = 30,
) -> None:
    """
    Configure the logging system.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: Output format ("json" or "text")
        log_file: Optional file path for file logging
        rotation: Log rotation strategy (currently not implemented)
        retention_days: Days to retain log files (currently not implemented)
    """
    root_logger = logging.getLogger("medic")
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    if format_type == "json":
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(TextFormatter())
    root_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(JSONFormatter())  # Always JSON for files
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> MedicLogger:
    """
    Get a logger instance with the given name.

    Args:
        name: Logger name (e.g., "medic.core.decision")

    Returns:
        MedicLogger instance
    """
    if not name.startswith("medic"):
        name = f"medic.{name}"
    return logging.getLogger(name)  # type: ignore


# Convenience function for creating trace-aware log context
class LogContext:
    """
    Context manager for setting log context fields.

    Usage:
        with LogContext(kill_id="abc123", target_module="auth"):
            logger.info("Processing started")
            # ... do work ...
            logger.info("Processing completed")
    """

    def __init__(self, **fields: Any):
        self.fields = fields
        self._old_fields: Dict[str, Any] = {}

    def __enter__(self) -> "LogContext":
        self._old_fields = _context_fields.get().copy()
        current = _context_fields.get().copy()
        current.update(self.fields)
        _context_fields.set(current)
        return self

    def __exit__(self, *args: Any) -> None:
        _context_fields.set(self._old_fields)


# Default configuration - can be overridden by configure_logging()
configure_logging(level="INFO", format_type="text")
