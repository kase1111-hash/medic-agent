"""
Unit Tests - Risk Assessor

Tests for the risk assessment engine and related functionality.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from core.models import KillReport, KillReason, Severity, RiskLevel
from core.risk import (
    create_risk_assessor,
    AdvancedRiskAssessor,
    RiskAssessment,
    RiskFactor,
)
from core.siem_interface import SIEMContextResponse, ThreatIndicator


# Test fixtures

@pytest.fixture
def default_config():
    """Default risk configuration."""
    return {
        "risk": {
            "thresholds": {
                "minimal": 0.2,
                "low": 0.4,
                "medium": 0.6,
                "high": 0.8,
            },
            "weights": {
                "smith_confidence": 0.3,
                "siem_risk_score": 0.25,
                "false_positive_history": 0.2,
                "module_criticality": 0.15,
                "time_of_day": 0.1,
            },
        },
        "decision": {
            "auto_approve": {
                "max_risk_level": "low",
                "min_confidence": 0.85,
            },
        },
    }


@pytest.fixture
def risk_assessor(default_config):
    """Create a risk assessor instance."""
    return create_risk_assessor(default_config)


@pytest.fixture
def sample_kill_report():
    """Standard kill report for testing."""
    return KillReport(
        kill_id="test-kill-001",
        timestamp=datetime.now(timezone.utc),
        target_module="test-service",
        target_instance_id="instance-001",
        kill_reason=KillReason.ANOMALY_BEHAVIOR,
        severity=Severity.MEDIUM,
        confidence_score=0.75,
        evidence=["evidence-001"],
        dependencies=["dep-a", "dep-b"],
        source_agent="smith-01",
        metadata={},
    )


@pytest.fixture
def low_risk_kill_report():
    """Kill report that should result in low risk."""
    return KillReport(
        kill_id="test-kill-low-001",
        timestamp=datetime.now(timezone.utc),
        target_module="cache-service",
        target_instance_id="cache-001",
        kill_reason=KillReason.RESOURCE_EXHAUSTION,
        severity=Severity.LOW,
        confidence_score=0.5,
        evidence=["memory-spike"],
        dependencies=[],
        source_agent="smith-01",
        metadata={},
    )


@pytest.fixture
def high_risk_kill_report():
    """Kill report that should result in high risk."""
    return KillReport(
        kill_id="test-kill-high-001",
        timestamp=datetime.now(timezone.utc),
        target_module="auth-service",
        target_instance_id="auth-001",
        kill_reason=KillReason.THREAT_DETECTED,
        severity=Severity.HIGH,
        confidence_score=0.9,
        evidence=["threat-indicator-001", "threat-indicator-002"],
        dependencies=["api-gateway", "user-service"],
        source_agent="smith-01",
        metadata={"critical_path": True},
    )


@pytest.fixture
def sample_siem_context():
    """Standard SIEM context for testing."""
    return SIEMContextResponse(
        query_id="query-001",
        kill_id="test-kill-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[],
        historical_behavior={"error_rate": 0.02},
        false_positive_history=2,
        network_context={},
        user_context=None,
        risk_score=0.4,
        recommendation="investigate",
    )


@pytest.fixture
def low_risk_siem_context():
    """SIEM context indicating low risk."""
    return SIEMContextResponse(
        query_id="query-low-001",
        kill_id="test-kill-low-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[],
        historical_behavior={"stability_score": 0.95},
        false_positive_history=5,
        network_context={},
        user_context=None,
        risk_score=0.15,
        recommendation="low_risk",
    )


@pytest.fixture
def high_risk_siem_context():
    """SIEM context indicating high risk."""
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
                tags=["c2", "apt"],
            ),
        ],
        historical_behavior={"anomaly_score": 0.8},
        false_positive_history=0,
        network_context={"unusual_ports": [4444]},
        user_context=None,
        risk_score=0.85,
        recommendation="quarantine",
    )


# Tests for risk assessment

class TestRiskAssessor:
    """Tests for the AdvancedRiskAssessor class."""

    def test_create_risk_assessor(self, default_config):
        """Test that risk assessor can be created."""
        assessor = create_risk_assessor(default_config)
        assert assessor is not None
        assert isinstance(assessor, AdvancedRiskAssessor)

    def test_assess_returns_risk_assessment(
        self, risk_assessor, sample_kill_report, sample_siem_context
    ):
        """Test that assess returns a RiskAssessment object."""
        result = risk_assessor.assess(sample_kill_report, sample_siem_context)
        assert isinstance(result, RiskAssessment)
        assert hasattr(result, "risk_level")
        assert hasattr(result, "risk_score")
        assert hasattr(result, "factors")

    def test_risk_score_in_valid_range(
        self, risk_assessor, sample_kill_report, sample_siem_context
    ):
        """Test that risk score is between 0 and 1."""
        result = risk_assessor.assess(sample_kill_report, sample_siem_context)
        assert 0.0 <= result.risk_score <= 1.0

    def test_low_risk_assessment(
        self, risk_assessor, low_risk_kill_report, low_risk_siem_context
    ):
        """Test assessment of low risk scenario."""
        result = risk_assessor.assess(low_risk_kill_report, low_risk_siem_context)
        assert result.risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW)
        assert result.risk_score < 0.5

    def test_high_risk_assessment(
        self, risk_assessor, high_risk_kill_report, high_risk_siem_context
    ):
        """Test assessment of high risk scenario."""
        result = risk_assessor.assess(high_risk_kill_report, high_risk_siem_context)
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert result.risk_score > 0.6

    def test_auto_approve_eligibility_low_risk(
        self, risk_assessor, low_risk_kill_report, low_risk_siem_context
    ):
        """Test that low risk assessments are eligible for auto-approve."""
        result = risk_assessor.assess(low_risk_kill_report, low_risk_siem_context)
        assert result.auto_approve_eligible is True

    def test_auto_approve_ineligibility_high_risk(
        self, risk_assessor, high_risk_kill_report, high_risk_siem_context
    ):
        """Test that high risk assessments are not eligible for auto-approve."""
        result = risk_assessor.assess(high_risk_kill_report, high_risk_siem_context)
        assert result.auto_approve_eligible is False

    def test_risk_factors_included(
        self, risk_assessor, sample_kill_report, sample_siem_context
    ):
        """Test that risk factors are included in assessment."""
        result = risk_assessor.assess(sample_kill_report, sample_siem_context)
        assert len(result.factors) > 0
        for factor in result.factors:
            assert isinstance(factor, RiskFactor)
            assert factor.name
            assert 0.0 <= factor.weighted_score <= 1.0

    def test_critical_module_increases_risk(self, risk_assessor, sample_siem_context):
        """Test that critical modules have higher risk scores."""
        regular_report = KillReport(
            kill_id="regular-001",
            timestamp=datetime.now(timezone.utc),
            target_module="cache-service",
            target_instance_id="cache-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.7,
            evidence=[],
            dependencies=[],
            source_agent="smith-01",
            metadata={},
        )

        critical_report = KillReport(
            kill_id="critical-001",
            timestamp=datetime.now(timezone.utc),
            target_module="auth-service",  # Critical module
            target_instance_id="auth-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.7,
            evidence=[],
            dependencies=[],
            source_agent="smith-01",
            metadata={},
        )

        regular_result = risk_assessor.assess(regular_report, sample_siem_context)
        critical_result = risk_assessor.assess(critical_report, sample_siem_context)

        # Critical module should have higher risk
        assert critical_result.risk_score >= regular_result.risk_score

    def test_high_confidence_smith_kill_increases_risk(
        self, risk_assessor, sample_siem_context
    ):
        """Test that high Smith confidence increases risk score."""
        low_confidence = KillReport(
            kill_id="low-conf-001",
            timestamp=datetime.now(timezone.utc),
            target_module="test-service",
            target_instance_id="test-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.3,  # Low confidence
            evidence=[],
            dependencies=[],
            source_agent="smith-01",
            metadata={},
        )

        high_confidence = KillReport(
            kill_id="high-conf-001",
            timestamp=datetime.now(timezone.utc),
            target_module="test-service",
            target_instance_id="test-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.95,  # High confidence
            evidence=[],
            dependencies=[],
            source_agent="smith-01",
            metadata={},
        )

        low_result = risk_assessor.assess(low_confidence, sample_siem_context)
        high_result = risk_assessor.assess(high_confidence, sample_siem_context)

        # Higher Smith confidence should result in higher risk score
        assert high_result.risk_score > low_result.risk_score

    def test_false_positive_history_reduces_risk(self, risk_assessor, sample_kill_report):
        """Test that high false positive history reduces risk."""
        no_fp_context = SIEMContextResponse(
            query_id="no-fp-001",
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.5,
            recommendation="investigate",
        )

        high_fp_context = SIEMContextResponse(
            query_id="high-fp-001",
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=10,  # Many false positives
            network_context={},
            user_context=None,
            risk_score=0.5,
            recommendation="investigate",
        )

        no_fp_result = risk_assessor.assess(sample_kill_report, no_fp_context)
        high_fp_result = risk_assessor.assess(sample_kill_report, high_fp_context)

        # High false positive history should reduce risk
        assert high_fp_result.risk_score < no_fp_result.risk_score

    def test_threat_indicators_increase_risk(self, risk_assessor, sample_kill_report):
        """Test that threat indicators increase risk score."""
        no_threats = SIEMContextResponse(
            query_id="no-threats-001",
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.3,
            recommendation="low_risk",
        )

        with_threats = SIEMContextResponse(
            query_id="with-threats-001",
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[
                ThreatIndicator(
                    indicator_type="ip",
                    value="evil.ip",
                    threat_score=0.9,
                    source="threat_intel",
                    last_seen=datetime.now(timezone.utc),
                    tags=["malicious"],
                ),
            ],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.8,
            recommendation="high_risk",
        )

        no_threats_result = risk_assessor.assess(sample_kill_report, no_threats)
        with_threats_result = risk_assessor.assess(sample_kill_report, with_threats)

        assert with_threats_result.risk_score > no_threats_result.risk_score

    def test_assessment_includes_factor_breakdown(
        self, risk_assessor, sample_kill_report, sample_siem_context
    ):
        """Test that assessment includes factor breakdown."""
        result = risk_assessor.assess(sample_kill_report, sample_siem_context)
        # Factors are included in the assessment result
        assert isinstance(result.factors, list)
        assert len(result.factors) > 0
        # Each factor has required attributes
        for factor in result.factors:
            assert hasattr(factor, 'name')
            assert hasattr(factor, 'weighted_score')

    def test_update_thresholds(self, risk_assessor):
        """Test that thresholds can be updated."""
        new_thresholds = {"low": 0.35, "medium": 0.55}
        risk_assessor.update_thresholds(new_thresholds)

        # Verify thresholds were updated
        thresholds = risk_assessor.get_thresholds()
        assert thresholds.get("low") == 0.35
        assert thresholds.get("medium") == 0.55


class TestRiskLevelMapping:
    """Tests for risk level calculation from scores."""

    def test_minimal_risk_level(self, risk_assessor, sample_siem_context):
        """Test that scores below 0.2 result in MINIMAL risk."""
        report = KillReport(
            kill_id="minimal-001",
            timestamp=datetime.now(timezone.utc),
            target_module="non-critical",
            target_instance_id="nc-001",
            kill_reason=KillReason.RESOURCE_EXHAUSTION,
            severity=Severity.INFO,
            confidence_score=0.1,
            evidence=[],
            dependencies=[],
            source_agent="smith-01",
            metadata={},
        )

        low_context = SIEMContextResponse(
            query_id="min-001",
            kill_id=report.kill_id,
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=10,
            network_context={},
            user_context=None,
            risk_score=0.05,
            recommendation="benign",
        )

        result = risk_assessor.assess(report, low_context)
        # Should be minimal or low given the inputs
        assert result.risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW)

    def test_critical_risk_level(self, risk_assessor):
        """Test that very high scores result in HIGH or CRITICAL risk."""
        report = KillReport(
            kill_id="critical-001",
            timestamp=datetime.now(timezone.utc),
            target_module="payment-processor",
            target_instance_id="payment-001",
            kill_reason=KillReason.THREAT_DETECTED,
            severity=Severity.CRITICAL,
            confidence_score=0.99,
            evidence=["ransomware", "encryption", "exfiltration"],
            dependencies=["ledger", "transactions"],
            source_agent="smith-01",
            metadata={"pci_scope": True},
        )

        critical_context = SIEMContextResponse(
            query_id="crit-001",
            kill_id=report.kill_id,
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[
                ThreatIndicator(
                    indicator_type="behavior",
                    value="ransomware_encryption",
                    threat_score=0.99,
                    source="edr",
                    last_seen=datetime.now(timezone.utc),
                    tags=["ransomware"],
                ),
            ],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.98,
            recommendation="isolate",
        )

        result = risk_assessor.assess(report, critical_context)
        # High threat scenario should result in HIGH or CRITICAL risk
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert result.risk_score >= 0.7


class TestRiskAssessmentEdgeCases:
    """Tests for edge cases in risk assessment."""

    def test_minimal_siem_context_handled(self, risk_assessor, sample_kill_report):
        """Test that minimal SIEM context is handled gracefully."""
        # Create minimal SIEM context with default values
        minimal_context = SIEMContextResponse(
            query_id="minimal-001",
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.now(timezone.utc),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.5,
            recommendation="unknown",
        )
        result = risk_assessor.assess(sample_kill_report, minimal_context)
        assert isinstance(result, RiskAssessment)
        # With minimal context, should still produce valid assessment
        assert 0.0 <= result.risk_score <= 1.0

    def test_empty_evidence_handled(self, risk_assessor, sample_siem_context):
        """Test assessment with empty evidence."""
        report = KillReport(
            kill_id="empty-evidence-001",
            timestamp=datetime.now(timezone.utc),
            target_module="test-service",
            target_instance_id="test-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.5,
            evidence=[],  # Empty evidence
            dependencies=[],
            source_agent="smith-01",
            metadata={},
        )

        result = risk_assessor.assess(report, sample_siem_context)
        assert isinstance(result, RiskAssessment)

    def test_many_dependencies_considered(self, risk_assessor, sample_siem_context):
        """Test that many dependencies affect risk."""
        few_deps = KillReport(
            kill_id="few-deps-001",
            timestamp=datetime.now(timezone.utc),
            target_module="isolated-service",
            target_instance_id="iso-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.7,
            evidence=[],
            dependencies=[],  # No dependencies
            source_agent="smith-01",
            metadata={},
        )

        many_deps = KillReport(
            kill_id="many-deps-001",
            timestamp=datetime.now(timezone.utc),
            target_module="core-service",
            target_instance_id="core-001",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.7,
            evidence=[],
            dependencies=["svc-1", "svc-2", "svc-3", "svc-4", "svc-5"],  # Many deps
            source_agent="smith-01",
            metadata={},
        )

        few_result = risk_assessor.assess(few_deps, sample_siem_context)
        many_result = risk_assessor.assess(many_deps, sample_siem_context)

        # More dependencies should increase risk
        assert many_result.risk_score >= few_result.risk_score
