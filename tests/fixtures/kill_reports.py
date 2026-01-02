"""
Test Fixtures - Kill Reports

Provides sample kill reports for testing various scenarios.
Based on the spec sheet data model definitions.
"""

import pytest
from datetime import datetime, timedelta
from typing import List

from core.models import KillReport, KillReason, Severity


@pytest.fixture
def sample_kill_report() -> KillReport:
    """Standard kill report for testing."""
    return KillReport(
        kill_id="test-kill-001",
        timestamp=datetime.utcnow(),
        target_module="test-service",
        target_instance_id="instance-001",
        kill_reason=KillReason.ANOMALY_BEHAVIOR,
        severity=Severity.MEDIUM,
        confidence_score=0.75,
        evidence=["log-entry-001", "metric-anomaly-002"],
        dependencies=["downstream-a", "downstream-b"],
        source_agent="smith-01",
        metadata={"region": "us-east-1", "cluster": "prod-1"},
    )


@pytest.fixture
def low_risk_kill_report() -> KillReport:
    """Kill report that should result in low risk assessment."""
    return KillReport(
        kill_id="test-kill-low-001",
        timestamp=datetime.utcnow(),
        target_module="cache-service",
        target_instance_id="cache-001",
        kill_reason=KillReason.RESOURCE_EXHAUSTION,
        severity=Severity.LOW,
        confidence_score=0.5,
        evidence=["memory-spike-001"],
        dependencies=[],
        source_agent="smith-02",
        metadata={"region": "us-east-1", "auto_scalable": True},
    )


@pytest.fixture
def high_risk_kill_report() -> KillReport:
    """Kill report that should result in high risk assessment."""
    return KillReport(
        kill_id="test-kill-high-001",
        timestamp=datetime.utcnow(),
        target_module="auth-service",
        target_instance_id="auth-001",
        kill_reason=KillReason.THREAT_DETECTED,
        severity=Severity.HIGH,
        confidence_score=0.9,
        evidence=["ioc-match-001", "lateral-movement-002", "c2-beacon-003"],
        dependencies=["api-gateway", "user-service", "session-service"],
        source_agent="smith-01",
        metadata={
            "region": "us-east-1",
            "critical_path": True,
            "threat_type": "apt",
        },
    )


@pytest.fixture
def critical_kill_report() -> KillReport:
    """Kill report for critical threat requiring immediate attention."""
    return KillReport(
        kill_id="test-kill-critical-001",
        timestamp=datetime.utcnow(),
        target_module="payment-processor",
        target_instance_id="payment-001",
        kill_reason=KillReason.THREAT_DETECTED,
        severity=Severity.CRITICAL,
        confidence_score=0.95,
        evidence=[
            "ransomware-signature-001",
            "encryption-behavior-002",
            "network-exfil-003",
        ],
        dependencies=[
            "transaction-service",
            "ledger-service",
            "notification-service",
        ],
        source_agent="smith-01",
        metadata={
            "region": "us-east-1",
            "pci_scope": True,
            "threat_type": "ransomware",
            "urgency": "immediate",
        },
    )


@pytest.fixture
def policy_violation_kill_report() -> KillReport:
    """Kill report for policy violation."""
    return KillReport(
        kill_id="test-kill-policy-001",
        timestamp=datetime.utcnow(),
        target_module="data-exporter",
        target_instance_id="exporter-001",
        kill_reason=KillReason.POLICY_VIOLATION,
        severity=Severity.MEDIUM,
        confidence_score=0.85,
        evidence=["policy-violation-dlp-001", "unauthorized-egress-002"],
        dependencies=["data-warehouse"],
        source_agent="smith-03",
        metadata={
            "policy_name": "no-external-data-transfer",
            "violation_type": "egress",
        },
    )


@pytest.fixture
def cascade_kill_report() -> KillReport:
    """Kill report for dependency cascade scenario."""
    return KillReport(
        kill_id="test-kill-cascade-001",
        timestamp=datetime.utcnow(),
        target_module="database-proxy",
        target_instance_id="proxy-001",
        kill_reason=KillReason.DEPENDENCY_CASCADE,
        severity=Severity.HIGH,
        confidence_score=0.7,
        evidence=["cascade-trigger-001"],
        dependencies=[
            "service-a",
            "service-b",
            "service-c",
            "service-d",
            "service-e",
        ],
        source_agent="smith-01",
        metadata={
            "cascade_depth": 3,
            "affected_services": 12,
            "original_failure": "primary-db",
        },
    )


@pytest.fixture
def manual_override_kill_report() -> KillReport:
    """Kill report for manual override by operator."""
    return KillReport(
        kill_id="test-kill-manual-001",
        timestamp=datetime.utcnow(),
        target_module="legacy-adapter",
        target_instance_id="adapter-001",
        kill_reason=KillReason.MANUAL_OVERRIDE,
        severity=Severity.INFO,
        confidence_score=1.0,
        evidence=["operator-decision-001"],
        dependencies=[],
        source_agent="smith-operator",
        metadata={
            "operator_id": "ops-user-123",
            "reason": "Scheduled maintenance",
            "ticket": "OPS-4567",
        },
    )


@pytest.fixture
def flapping_module_kill_report() -> KillReport:
    """Kill report for a module that has been killed multiple times recently."""
    return KillReport(
        kill_id="test-kill-flap-001",
        timestamp=datetime.utcnow(),
        target_module="unstable-service",
        target_instance_id="unstable-001",
        kill_reason=KillReason.ANOMALY_BEHAVIOR,
        severity=Severity.MEDIUM,
        confidence_score=0.6,
        evidence=["behavior-anomaly-001"],
        dependencies=["dependent-service"],
        source_agent="smith-01",
        metadata={
            "previous_kills_24h": 5,
            "previous_resurrections_24h": 4,
            "stability_score": 0.3,
        },
    )


@pytest.fixture
def old_kill_report() -> KillReport:
    """Kill report that is older (for timeout testing)."""
    return KillReport(
        kill_id="test-kill-old-001",
        timestamp=datetime.utcnow() - timedelta(hours=2),
        target_module="old-service",
        target_instance_id="old-001",
        kill_reason=KillReason.ANOMALY_BEHAVIOR,
        severity=Severity.LOW,
        confidence_score=0.6,
        evidence=["old-evidence-001"],
        dependencies=[],
        source_agent="smith-01",
        metadata={"stale": True},
    )


@pytest.fixture
def kill_report_batch() -> List[KillReport]:
    """Batch of kill reports for bulk testing."""
    base_time = datetime.utcnow()
    return [
        KillReport(
            kill_id=f"test-kill-batch-{i:03d}",
            timestamp=base_time - timedelta(minutes=i * 5),
            target_module=f"service-{i % 5}",
            target_instance_id=f"instance-{i:03d}",
            kill_reason=list(KillReason)[i % len(KillReason)],
            severity=list(Severity)[i % len(Severity)],
            confidence_score=0.5 + (i % 5) * 0.1,
            evidence=[f"evidence-{i}"],
            dependencies=[f"dep-{j}" for j in range(i % 3)],
            source_agent=f"smith-{i % 3:02d}",
            metadata={"batch_index": i},
        )
        for i in range(10)
    ]


@pytest.fixture
def kill_report_for_module(request) -> KillReport:
    """
    Parameterized fixture for testing specific modules.

    Usage:
        @pytest.mark.parametrize('kill_report_for_module', ['auth-service'], indirect=True)
        def test_something(kill_report_for_module):
            ...
    """
    module_name = getattr(request, 'param', 'test-service')
    return KillReport(
        kill_id=f"test-kill-{module_name}-001",
        timestamp=datetime.utcnow(),
        target_module=module_name,
        target_instance_id=f"{module_name}-001",
        kill_reason=KillReason.ANOMALY_BEHAVIOR,
        severity=Severity.MEDIUM,
        confidence_score=0.75,
        evidence=["evidence-001"],
        dependencies=[],
        source_agent="smith-01",
        metadata={},
    )


# Factory function for custom kill reports
def create_kill_report(
    kill_id: str = None,
    target_module: str = "test-service",
    kill_reason: KillReason = KillReason.ANOMALY_BEHAVIOR,
    severity: Severity = Severity.MEDIUM,
    confidence_score: float = 0.75,
    **kwargs,
) -> KillReport:
    """Factory function to create custom kill reports for testing."""
    import uuid

    defaults = {
        "kill_id": kill_id or str(uuid.uuid4()),
        "timestamp": datetime.utcnow(),
        "target_module": target_module,
        "target_instance_id": f"{target_module}-001",
        "kill_reason": kill_reason,
        "severity": severity,
        "confidence_score": confidence_score,
        "evidence": ["test-evidence-001"],
        "dependencies": [],
        "source_agent": "smith-test",
        "metadata": {},
    }
    defaults.update(kwargs)
    return KillReport(**defaults)
