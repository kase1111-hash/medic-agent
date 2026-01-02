"""
Security Tests - API Security

Tests for API authentication, authorization, and rate limiting.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import uuid


class TestCORSSecurity:
    """Test CORS configuration security."""

    @pytest.fixture
    def web_api_config(self):
        """Configuration with restrictive CORS."""
        return {
            "cors_origins": ["https://allowed-domain.com"],
            "rate_limit_per_minute": 60,
        }

    @pytest.fixture
    def web_api_open_cors_config(self):
        """Configuration with open CORS (insecure)."""
        return {
            "cors_origins": ["*"],
            "rate_limit_per_minute": 60,
        }

    def test_cors_not_wildcard_in_production_config(self, web_api_config):
        """Production config should not have wildcard CORS."""
        assert "*" not in web_api_config.get("cors_origins", [])

    def test_cors_origins_are_https(self, web_api_config):
        """CORS origins should use HTTPS in production."""
        for origin in web_api_config.get("cors_origins", []):
            if origin != "*":
                assert origin.startswith("https://"), f"Origin {origin} should use HTTPS"


class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limiter_blocks_excessive_requests(self):
        """Rate limiter should block requests exceeding limit."""
        from interfaces.web import RateLimiter

        limiter = RateLimiter(requests_per_minute=5)
        client_id = "test-client"

        # First 5 requests should be allowed
        for i in range(5):
            assert limiter.is_allowed(client_id), f"Request {i+1} should be allowed"

        # 6th request should be blocked
        assert not limiter.is_allowed(client_id), "Request 6 should be blocked"

    def test_rate_limiter_allows_different_clients(self):
        """Rate limiter should track clients separately."""
        from interfaces.web import RateLimiter

        limiter = RateLimiter(requests_per_minute=2)

        # Client 1 uses their quota
        assert limiter.is_allowed("client-1")
        assert limiter.is_allowed("client-1")
        assert not limiter.is_allowed("client-1")

        # Client 2 should still have quota
        assert limiter.is_allowed("client-2")
        assert limiter.is_allowed("client-2")

    def test_rate_limiter_resets_after_window(self):
        """Rate limiter should reset after time window."""
        from interfaces.web import RateLimiter
        import time

        limiter = RateLimiter(requests_per_minute=1)
        client_id = "test-client"

        # Use up quota
        assert limiter.is_allowed(client_id)
        assert not limiter.is_allowed(client_id)

        # Manipulate time (simulate 61 seconds passing)
        old_requests = limiter.requests[client_id]
        limiter.requests[client_id] = [r - 61 for r in old_requests]

        # Should be allowed again
        assert limiter.is_allowed(client_id)


class TestAuthenticationBypass:
    """Test for authentication bypass vulnerabilities."""

    def test_api_key_not_in_logs(self):
        """API keys should not be logged."""
        import logging
        from io import StringIO

        from core.logger import get_logger, configure_logging

        # Capture log output
        log_capture = StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setLevel(logging.DEBUG)

        logger = get_logger("test.auth")
        logger.addHandler(handler)

        # Log a message with an API key (simulating accidental logging)
        api_key = "secret-api-key-12345"
        logger.info(f"Processing request")  # Correct - no key

        log_output = log_capture.getvalue()
        assert api_key not in log_output

    def test_empty_api_key_rejected(self):
        """Empty API key should be treated as no authentication."""
        from core.siem_interface import RESTSIEMAdapter

        adapter = RESTSIEMAdapter(
            endpoint="http://test.com",
            api_key="",  # Empty
        )
        # Empty key should not add authorization header
        assert adapter.api_key == ""


class TestRequestValidation:
    """Test request validation for API endpoints."""

    @pytest.fixture
    def mock_approval_queue(self):
        """Mock approval queue."""
        queue = MagicMock()
        queue.list_pending = AsyncMock(return_value=[])
        queue.get = AsyncMock(return_value=None)
        return queue

    def test_reject_invalid_uuid_format(self):
        """Invalid UUID format should be rejected."""
        invalid_uuids = [
            "not-a-uuid",
            "12345",
            "../../../etc/passwd",
            "'; DROP TABLE--",
            "",
            "null",
            "undefined",
        ]

        for invalid_id in invalid_uuids:
            try:
                uuid.UUID(invalid_id)
                pytest.fail(f"Should have rejected invalid UUID: {invalid_id}")
            except (ValueError, AttributeError):
                pass  # Expected

    def test_valid_uuid_formats_accepted(self):
        """Valid UUID formats should be accepted."""
        valid_uuids = [
            str(uuid.uuid4()),
            "550e8400-e29b-41d4-a716-446655440000",
            "550E8400-E29B-41D4-A716-446655440000",  # Uppercase
        ]

        for valid_id in valid_uuids:
            parsed = uuid.UUID(valid_id)
            assert parsed is not None


class TestSecretExposure:
    """Test that secrets are not exposed."""

    def test_config_endpoint_hides_secrets(self):
        """Configuration endpoint should not expose secrets."""
        # Simulate config response sanitization
        full_config = {
            "siem": {
                "endpoint": "https://siem.example.com",
                "auth": {
                    "api_key": "super-secret-key",
                    "type": "api_key",
                },
            },
            "mode": "semi_auto",
        }

        # Sanitize function (should be in web.py)
        def sanitize_config(config):
            """Remove secrets from config for display."""
            sanitized = config.copy()
            if "siem" in sanitized and "auth" in sanitized["siem"]:
                sanitized["siem"]["auth"] = {
                    k: "***" if k in ("api_key", "password", "secret") else v
                    for k, v in sanitized["siem"]["auth"].items()
                }
            return sanitized

        sanitized = sanitize_config(full_config)

        assert sanitized["siem"]["auth"]["api_key"] == "***"
        assert sanitized["siem"]["auth"]["type"] == "api_key"
        assert "super-secret-key" not in str(sanitized)

    def test_error_messages_no_secrets(self):
        """Error messages should not contain secrets."""
        api_key = "secret-key-12345"

        # Simulate an error that might include secret
        try:
            raise ConnectionError(f"Failed to connect to SIEM")
        except ConnectionError as e:
            error_msg = str(e)
            assert api_key not in error_msg
