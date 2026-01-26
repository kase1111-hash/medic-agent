"""
Test Fixtures - SIEM Responses

Provides sample SIEM context responses for testing various scenarios.
Based on the spec sheet data model definitions.
"""

import pytest
from datetime import datetime, timedelta, timezone
from typing import List
from unittest.mock import AsyncMock, MagicMock

from core.siem_interface import SIEMContextResponse, ThreatIndicator


@pytest.fixture
def sample_siem_response() -> SIEMContextResponse:
    """Standard SIEM response for testing."""
    return SIEMContextResponse(
        query_id="query-001",
        kill_id="test-kill-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[
            ThreatIndicator(
                indicator_type="behavior",
                value="unusual_network_pattern",
                threat_score=0.6,
                source="behavioral_analytics",
                last_seen=datetime.now(timezone.utc),
                tags=["network", "anomaly"],
            ),
        ],
        historical_behavior={
            "avg_cpu": 45.0,
            "avg_memory": 60.0,
            "avg_requests_per_sec": 150,
            "error_rate": 0.02,
        },
        false_positive_history=2,
        network_context={
            "inbound_connections": 50,
            "outbound_connections": 10,
            "unusual_ports": [],
        },
        user_context=None,
        risk_score=0.4,
        recommendation="investigate",
    )


@pytest.fixture
def low_risk_siem_response() -> SIEMContextResponse:
    """SIEM response indicating low risk."""
    return SIEMContextResponse(
        query_id="query-low-001",
        kill_id="test-kill-low-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[],
        historical_behavior={
            "avg_cpu": 30.0,
            "avg_memory": 40.0,
            "avg_requests_per_sec": 100,
            "error_rate": 0.01,
            "stability_score": 0.95,
        },
        false_positive_history=5,  # Many false positives = likely benign
        network_context={
            "inbound_connections": 20,
            "outbound_connections": 5,
            "unusual_ports": [],
        },
        user_context=None,
        risk_score=0.15,
        recommendation="low_risk",
    )


@pytest.fixture
def high_risk_siem_response() -> SIEMContextResponse:
    """SIEM response indicating high risk."""
    return SIEMContextResponse(
        query_id="query-high-001",
        kill_id="test-kill-high-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[
            ThreatIndicator(
                indicator_type="ip",
                value="192.168.1.100",
                threat_score=0.85,
                source="threat_intel",
                last_seen=datetime.now(timezone.utc),
                tags=["c2", "apt", "known_bad"],
            ),
            ThreatIndicator(
                indicator_type="hash",
                value="abc123def456",
                threat_score=0.9,
                source="malware_db",
                last_seen=datetime.now(timezone.utc),
                tags=["malware", "trojan"],
            ),
            ThreatIndicator(
                indicator_type="behavior",
                value="lateral_movement",
                threat_score=0.8,
                source="ueba",
                last_seen=datetime.now(timezone.utc),
                tags=["lateral", "reconnaissance"],
            ),
        ],
        historical_behavior={
            "avg_cpu": 90.0,
            "avg_memory": 85.0,
            "avg_requests_per_sec": 500,
            "error_rate": 0.15,
            "anomaly_score": 0.85,
        },
        false_positive_history=0,
        network_context={
            "inbound_connections": 200,
            "outbound_connections": 100,
            "unusual_ports": [4444, 8080, 1337],
            "external_ips": ["45.33.32.156", "192.0.2.1"],
        },
        user_context={
            "user_id": "compromised-user-001",
            "risk_level": "high",
            "recent_logins": 50,
            "unusual_activity": True,
        },
        risk_score=0.85,
        recommendation="quarantine",
    )


@pytest.fixture
def critical_siem_response() -> SIEMContextResponse:
    """SIEM response for critical threat."""
    return SIEMContextResponse(
        query_id="query-critical-001",
        kill_id="test-kill-critical-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[
            ThreatIndicator(
                indicator_type="behavior",
                value="ransomware_encryption",
                threat_score=0.99,
                source="endpoint_detection",
                last_seen=datetime.now(timezone.utc),
                tags=["ransomware", "encryption", "critical"],
            ),
            ThreatIndicator(
                indicator_type="file",
                value="ransom_note.txt",
                threat_score=0.95,
                source="file_monitor",
                last_seen=datetime.now(timezone.utc),
                tags=["ransomware", "indicator"],
            ),
        ],
        historical_behavior={
            "avg_cpu": 100.0,
            "avg_memory": 95.0,
            "disk_write_spike": True,
            "file_modification_rate": 10000,
        },
        false_positive_history=0,
        network_context={
            "inbound_connections": 5,
            "outbound_connections": 500,
            "data_exfiltration_detected": True,
            "unusual_ports": [443, 8443],
        },
        user_context=None,
        risk_score=0.98,
        recommendation="isolate_immediately",
    )


@pytest.fixture
def no_context_siem_response() -> SIEMContextResponse:
    """SIEM response with minimal context (new or unknown module)."""
    return SIEMContextResponse(
        query_id="query-empty-001",
        kill_id="test-kill-unknown-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[],
        historical_behavior={},
        false_positive_history=0,
        network_context={},
        user_context=None,
        risk_score=0.5,  # Default middle score due to lack of data
        recommendation="gather_more_data",
    )


@pytest.fixture
def frequent_fp_siem_response() -> SIEMContextResponse:
    """SIEM response for module with many false positives."""
    return SIEMContextResponse(
        query_id="query-fp-001",
        kill_id="test-kill-fp-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[
            ThreatIndicator(
                indicator_type="behavior",
                value="high_cpu_usage",
                threat_score=0.5,
                source="resource_monitor",
                last_seen=datetime.now(timezone.utc),
                tags=["resource", "cpu"],
            ),
        ],
        historical_behavior={
            "avg_cpu": 70.0,
            "avg_memory": 60.0,
            "known_cpu_spikes": True,
            "spike_pattern": "batch_processing",
        },
        false_positive_history=15,  # Many false positives
        network_context={
            "inbound_connections": 30,
            "outbound_connections": 10,
        },
        user_context=None,
        risk_score=0.2,
        recommendation="likely_false_positive",
    )


@pytest.fixture
def stale_siem_response() -> SIEMContextResponse:
    """SIEM response with stale data."""
    return SIEMContextResponse(
        query_id="query-stale-001",
        kill_id="test-kill-stale-001",
        timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
        threat_indicators=[
            ThreatIndicator(
                indicator_type="ip",
                value="10.0.0.50",
                threat_score=0.6,
                source="old_intel",
                last_seen=datetime.now(timezone.utc) - timedelta(days=30),
                tags=["stale", "needs_review"],
            ),
        ],
        historical_behavior={
            "last_seen": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
        },
        false_positive_history=1,
        network_context={},
        user_context=None,
        risk_score=0.4,
        recommendation="data_may_be_stale",
    )


# Mock SIEM Adapter fixtures

@pytest.fixture
def mock_siem_adapter():
    """Mock SIEM adapter for testing."""
    adapter = AsyncMock()
    adapter.query_context.return_value = SIEMContextResponse(
        query_id="mock-query-001",
        kill_id="mock-kill-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[],
        historical_behavior={},
        false_positive_history=2,
        network_context={},
        user_context=None,
        risk_score=0.3,
        recommendation="low_risk",
    )
    adapter.health_check.return_value = True
    adapter.get_historical_data.return_value = []
    adapter.report_outcome.return_value = True
    return adapter


@pytest.fixture
def mock_siem_adapter_high_risk(mock_siem_adapter, high_risk_siem_response):
    """Mock SIEM adapter that returns high risk response."""
    mock_siem_adapter.query_context.return_value = high_risk_siem_response
    return mock_siem_adapter


@pytest.fixture
def mock_siem_adapter_low_risk(mock_siem_adapter, low_risk_siem_response):
    """Mock SIEM adapter that returns low risk response."""
    mock_siem_adapter.query_context.return_value = low_risk_siem_response
    return mock_siem_adapter


@pytest.fixture
def mock_siem_adapter_failing():
    """Mock SIEM adapter that fails."""
    adapter = AsyncMock()
    from core.errors import SIEMQueryError
    adapter.query_context.side_effect = SIEMQueryError("SIEM unavailable")
    adapter.health_check.return_value = False
    return adapter


@pytest.fixture
def mock_siem_adapter_slow():
    """Mock SIEM adapter with slow responses."""
    import asyncio

    async def slow_query(*args, **kwargs):
        await asyncio.sleep(2)
        return SIEMContextResponse(
            query_id="slow-query-001",
            kill_id="slow-kill-001",
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.5,
            recommendation="delayed_response",
        )

    adapter = AsyncMock()
    adapter.query_context = slow_query
    adapter.health_check.return_value = True
    return adapter


# Factory function for custom SIEM responses
def create_siem_response(
    query_id: str = None,
    kill_id: str = "test-kill-001",
    risk_score: float = 0.5,
    false_positive_history: int = 0,
    threat_indicators: List[ThreatIndicator] = None,
    **kwargs,
) -> SIEMContextResponse:
    """Factory function to create custom SIEM responses for testing."""
    import uuid

    defaults = {
        "query_id": query_id or str(uuid.uuid4()),
        "kill_id": kill_id,
        "timestamp": datetime.now(timezone.utc),
        "threat_indicators": threat_indicators or [],
        "historical_behavior": {},
        "false_positive_history": false_positive_history,
        "network_context": {},
        "user_context": None,
        "risk_score": risk_score,
        "recommendation": "test",
    }
    defaults.update(kwargs)
    return SIEMContextResponse(**defaults)


def create_threat_indicator(
    indicator_type: str = "behavior",
    value: str = "test_indicator",
    threat_score: float = 0.5,
    **kwargs,
) -> ThreatIndicator:
    """Factory function to create threat indicators for testing."""
    defaults = {
        "indicator_type": indicator_type,
        "value": value,
        "threat_score": threat_score,
        "source": "test_source",
        "last_seen": datetime.now(timezone.utc),
        "tags": [],
    }
    defaults.update(kwargs)
    return ThreatIndicator(**defaults)
