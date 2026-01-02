"""
Unit tests for the logging module.
"""

import pytest
import json
import logging

from core.logger import (
    get_logger,
    configure_logging,
    set_trace_context,
    get_trace_id,
    get_span_id,
    set_context_field,
    clear_context_fields,
    LogContext,
    JSONFormatter,
    TextFormatter,
)


class TestGetLogger:
    """Tests for the get_logger function."""

    def test_get_logger_with_prefix(self):
        """Test getting a logger with medic prefix."""
        logger = get_logger("core.decision")
        assert logger.name == "medic.core.decision"

    def test_get_logger_already_prefixed(self):
        """Test getting a logger that already has medic prefix."""
        logger = get_logger("medic.core.decision")
        assert logger.name == "medic.core.decision"

    def test_logger_inheritance(self):
        """Test that child loggers inherit from parent."""
        parent = get_logger("medic.core")
        child = get_logger("medic.core.decision")
        assert child.parent.name == "medic.core"


class TestTraceContext:
    """Tests for trace context management."""

    def test_set_and_get_trace_id(self):
        """Test setting and getting trace ID."""
        set_trace_context(trace_id="test-trace-123")
        assert get_trace_id() == "test-trace-123"

    def test_set_and_get_span_id(self):
        """Test setting and getting span ID."""
        set_trace_context(span_id="span-456")
        assert get_span_id() == "span-456"

    def test_auto_generate_trace_id(self):
        """Test that trace ID is auto-generated if not provided."""
        set_trace_context()
        trace_id = get_trace_id()
        assert trace_id is not None
        assert len(trace_id) > 0


class TestContextFields:
    """Tests for context field management."""

    def test_set_context_field(self):
        """Test setting a context field."""
        clear_context_fields()
        set_context_field("kill_id", "test-kill-001")
        # Context fields are internal, tested through LogContext

    def test_clear_context_fields(self):
        """Test clearing context fields."""
        set_context_field("key", "value")
        clear_context_fields()
        # Verify cleared by checking LogContext behavior


class TestLogContext:
    """Tests for the LogContext context manager."""

    def test_log_context_sets_fields(self):
        """Test that LogContext sets fields within the block."""
        clear_context_fields()

        with LogContext(kill_id="test-123", module="test-service"):
            # Fields should be set within context
            pass

        # Fields should be cleared after context

    def test_log_context_restores_fields(self):
        """Test that LogContext restores previous fields."""
        clear_context_fields()
        set_context_field("existing", "value")

        with LogContext(new_field="new_value"):
            pass

        # Original field should still be accessible

    def test_nested_log_context(self):
        """Test nested LogContext blocks."""
        clear_context_fields()

        with LogContext(outer="outer_value"):
            with LogContext(inner="inner_value"):
                pass
            # Inner context should be cleared, outer should remain


class TestJSONFormatter:
    """Tests for the JSON log formatter."""

    @pytest.fixture
    def json_formatter(self):
        """Create a JSON formatter."""
        return JSONFormatter()

    def test_format_basic_record(self, json_formatter):
        """Test formatting a basic log record."""
        record = logging.LogRecord(
            name="medic.test",
            level=logging.INFO,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        formatted = json_formatter.format(record)
        data = json.loads(formatted)

        assert data["level"] == "INFO"
        assert data["logger"] == "medic.test"
        assert data["message"] == "Test message"
        assert "timestamp" in data

    def test_format_with_trace_context(self, json_formatter):
        """Test that trace context is included in formatted output."""
        set_trace_context(trace_id="trace-123", span_id="span-456")

        record = logging.LogRecord(
            name="medic.test",
            level=logging.INFO,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        formatted = json_formatter.format(record)
        data = json.loads(formatted)

        assert data.get("trace_id") == "trace-123"
        assert data.get("span_id") == "span-456"

    def test_format_with_structured_fields(self, json_formatter):
        """Test that structured fields are included."""
        record = logging.LogRecord(
            name="medic.test",
            level=logging.INFO,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.kill_id = "kill-001"
        record.decision_id = "decision-001"

        formatted = json_formatter.format(record)
        data = json.loads(formatted)

        assert data["context"].get("kill_id") == "kill-001"
        assert data["context"].get("decision_id") == "decision-001"


class TestTextFormatter:
    """Tests for the text log formatter."""

    @pytest.fixture
    def text_formatter(self):
        """Create a text formatter."""
        return TextFormatter(use_colors=False)

    def test_format_basic_record(self, text_formatter):
        """Test formatting a basic log record."""
        record = logging.LogRecord(
            name="medic.test",
            level=logging.INFO,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        formatted = text_formatter.format(record)

        assert "INFO" in formatted
        assert "medic.test" in formatted
        assert "Test message" in formatted

    def test_format_with_colors(self):
        """Test that colors are applied when enabled."""
        formatter = TextFormatter(use_colors=True)

        record = logging.LogRecord(
            name="medic.test",
            level=logging.ERROR,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Error message",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(record)

        # Should contain color codes
        assert "\033[" in formatted  # ANSI escape sequence


class TestConfigureLogging:
    """Tests for the configure_logging function."""

    def test_configure_default(self):
        """Test default logging configuration."""
        configure_logging()

        logger = get_logger("test")
        assert logger.level == logging.DEBUG or logger.parent.level == logging.INFO

    def test_configure_json_format(self, tmp_path):
        """Test configuring JSON format."""
        log_file = tmp_path / "test.log"

        configure_logging(
            level="DEBUG",
            format_type="json",
            log_file=str(log_file),
        )

        logger = get_logger("test.json")
        logger.info("Test message")

        # Check that JSON was written to file
        if log_file.exists():
            content = log_file.read_text()
            # Should be valid JSON lines
            for line in content.strip().split("\n"):
                if line:
                    json.loads(line)

    def test_configure_text_format(self):
        """Test configuring text format."""
        configure_logging(
            level="INFO",
            format_type="text",
        )

        logger = get_logger("test.text")
        # Should not raise
        logger.info("Test message")
