"""
Pytest configuration and shared fixtures for Medic Agent tests.
"""

import pytest
import asyncio
from datetime import datetime
from typing import Dict, Any
import uuid

# Import models
from core.models import (
    KillReport,
    KillReason,
    Severity,
    SIEMContextResponse,
    ThreatIndicator,
    ResurrectionDecision,
    DecisionOutcome,
    RiskLevel,
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_kill_report() -> KillReport:
    """Standard kill report for testing."""
    return KillReport(
        kill_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        target_module="test-service",
        target_instance_id="instance-001",
        kill_reason=KillReason.ANOMALY_BEHAVIOR,
        severity=Severity.MEDIUM,
        confidence_score=0.75,
        evidence=["log-entry-001", "metric-anomaly-002"],
        dependencies=["downstream-a", "downstream-b"],
        source_agent="smith-01",
        metadata={"region": "us-east-1"},
    )


@pytest.fixture
def low_risk_kill_report() -> KillReport:
    """Kill report that should result in low risk assessment."""
    return KillReport(
        kill_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        target_module="low-risk-service",
        target_instance_id="instance-002",
        kill_reason=KillReason.RESOURCE_EXHAUSTION,
        severity=Severity.LOW,
        confidence_score=0.5,
        evidence=["oom-event"],
        dependencies=[],
        source_agent="smith-01",
        metadata={},
    )


@pytest.fixture
def high_risk_kill_report() -> KillReport:
    """Kill report for high risk threat."""
    return KillReport(
        kill_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        target_module="critical-service",
        target_instance_id="instance-003",
        kill_reason=KillReason.THREAT_DETECTED,
        severity=Severity.CRITICAL,
        confidence_score=0.95,
        evidence=["malware-signature", "c2-communication"],
        dependencies=["auth", "database"],
        source_agent="smith-01",
        metadata={"threat_type": "malware"},
    )


@pytest.fixture
def sample_siem_response(sample_kill_report: KillReport) -> SIEMContextResponse:
    """Standard SIEM response for testing."""
    return SIEMContextResponse(
        query_id=str(uuid.uuid4()),
        kill_id=sample_kill_report.kill_id,
        timestamp=datetime.utcnow(),
        threat_indicators=[],
        historical_behavior={
            "avg_cpu_usage": 45.0,
            "avg_memory_mb": 512,
            "restart_count_30d": 2,
        },
        false_positive_history=2,
        network_context={"outbound_connections_24h": 150},
        user_context=None,
        risk_score=0.35,
        recommendation="low_risk_auto_approve",
    )


@pytest.fixture
def low_risk_siem_response(low_risk_kill_report: KillReport) -> SIEMContextResponse:
    """SIEM response indicating low risk."""
    return SIEMContextResponse(
        query_id=str(uuid.uuid4()),
        kill_id=low_risk_kill_report.kill_id,
        timestamp=datetime.utcnow(),
        threat_indicators=[],
        historical_behavior={},
        false_positive_history=5,  # Many false positives
        network_context={},
        user_context=None,
        risk_score=0.15,
        recommendation="likely_false_positive",
    )


@pytest.fixture
def high_risk_siem_response(high_risk_kill_report: KillReport) -> SIEMContextResponse:
    """SIEM response indicating high risk."""
    return SIEMContextResponse(
        query_id=str(uuid.uuid4()),
        kill_id=high_risk_kill_report.kill_id,
        timestamp=datetime.utcnow(),
        threat_indicators=[
            ThreatIndicator(
                indicator_type="malware",
                value="trojan.generic",
                threat_score=0.92,
                source="threat_intel",
                last_seen=datetime.utcnow(),
                tags=["malware", "trojan"],
            ),
        ],
        historical_behavior={},
        false_positive_history=0,
        network_context={"c2_connections": 3},
        user_context=None,
        risk_score=0.88,
        recommendation="critical_risk_deny",
    )


@pytest.fixture
def sample_config() -> Dict[str, Any]:
    """Standard configuration for testing."""
    return {
        "mode": {"current": "observer"},
        "smith": {
            "event_bus": {
                "type": "mock",
                "host": "localhost",
                "port": 6379,
            }
        },
        "siem": {
            "adapter": "mock",
            "endpoint": "http://localhost:8080/siem",
        },
        "decision": {
            "confidence_threshold": 0.7,
            "auto_approve": {
                "enabled": False,
                "min_confidence": 0.85,
            },
        },
        "risk": {
            "weights": {
                "smith_confidence": 0.30,
                "siem_risk_score": 0.25,
                "false_positive_history": 0.20,
                "module_criticality": 0.15,
                "time_of_day": 0.10,
            }
        },
        "logging": {
            "level": "DEBUG",
            "format": "text",
        },
    }


@pytest.fixture
def temp_data_dir(tmp_path):
    """Temporary directory for test data."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def temp_log_dir(tmp_path):
    """Temporary directory for test logs."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return log_dir


@pytest.fixture
def temp_reports_dir(tmp_path):
    """Temporary directory for test reports."""
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    return reports_dir
