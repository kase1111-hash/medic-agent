"""
Unit tests for the decision engine.
"""

import pytest
from datetime import datetime

from core.decision import (
    DecisionEngine,
    ObserverDecisionEngine,
    RiskAssessor,
    DecisionConfig,
    create_decision_engine,
)
from core.models import (
    KillReport,
    KillReason,
    Severity,
    SIEMContextResponse,
    DecisionOutcome,
    RiskLevel,
)


class TestRiskAssessor:
    """Tests for the RiskAssessor class."""

    @pytest.fixture
    def risk_assessor(self):
        """Create a RiskAssessor with default config."""
        return RiskAssessor(DecisionConfig())

    def test_assess_low_risk(
        self, risk_assessor, low_risk_kill_report, low_risk_siem_response
    ):
        """Test risk assessment for low-risk scenario."""
        risk_level, risk_score, factors = risk_assessor.assess_risk(
            low_risk_kill_report, low_risk_siem_response
        )

        assert risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW)
        assert risk_score < 0.4
        assert "smith_confidence" in factors
        assert "siem_risk" in factors

    def test_assess_high_risk(
        self, risk_assessor, high_risk_kill_report, high_risk_siem_response
    ):
        """Test risk assessment for high-risk scenario."""
        risk_level, risk_score, factors = risk_assessor.assess_risk(
            high_risk_kill_report, high_risk_siem_response
        )

        assert risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert risk_score > 0.6

    def test_false_positive_history_reduces_risk(
        self, risk_assessor, sample_kill_report
    ):
        """Test that false positive history reduces risk score."""
        # Response with no FP history
        no_fp_response = SIEMContextResponse(
            query_id="query-1",
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.5,
            recommendation="review",
        )

        # Response with high FP history
        high_fp_response = SIEMContextResponse(
            query_id="query-2",
            kill_id=sample_kill_report.kill_id,
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=10,
            network_context={},
            user_context=None,
            risk_score=0.5,
            recommendation="review",
        )

        _, score_no_fp, factors_no_fp = risk_assessor.assess_risk(
            sample_kill_report, no_fp_response
        )
        _, score_high_fp, factors_high_fp = risk_assessor.assess_risk(
            sample_kill_report, high_fp_response
        )

        # High FP history should result in lower risk factor
        assert factors_high_fp["false_positive_history"] < factors_no_fp["false_positive_history"]

    def test_severity_affects_risk(self, risk_assessor, sample_siem_response):
        """Test that severity level affects risk score."""
        # Create kill reports with different severities
        low_severity = KillReport(
            kill_id="kill-low",
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

        high_severity = KillReport(
            kill_id="kill-high",
            timestamp=datetime.utcnow(),
            target_module="test",
            target_instance_id="instance",
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.CRITICAL,
            confidence_score=0.5,
            evidence=[],
            dependencies=[],
            source_agent="smith",
        )

        _, _, factors_low = risk_assessor.assess_risk(low_severity, sample_siem_response)
        _, _, factors_high = risk_assessor.assess_risk(high_severity, sample_siem_response)

        assert factors_high["severity"] > factors_low["severity"]


class TestObserverDecisionEngine:
    """Tests for the ObserverDecisionEngine class."""

    @pytest.fixture
    def decision_engine(self):
        """Create an ObserverDecisionEngine with default config."""
        return ObserverDecisionEngine()

    def test_should_resurrect_low_risk(
        self, decision_engine, low_risk_kill_report, low_risk_siem_response
    ):
        """Test decision for low-risk case."""
        decision = decision_engine.should_resurrect(
            low_risk_kill_report, low_risk_siem_response
        )

        assert decision.decision_id is not None
        assert decision.kill_id == low_risk_kill_report.kill_id
        assert decision.risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW)
        # In observer mode, low risk should result in approve_auto or pending_review
        assert decision.outcome in (
            DecisionOutcome.APPROVE_AUTO,
            DecisionOutcome.PENDING_REVIEW,
        )

    def test_should_resurrect_high_risk(
        self, decision_engine, high_risk_kill_report, high_risk_siem_response
    ):
        """Test decision for high-risk case."""
        decision = decision_engine.should_resurrect(
            high_risk_kill_report, high_risk_siem_response
        )

        assert decision.outcome == DecisionOutcome.DENY
        assert decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert decision.risk_score > 0.6

    def test_deny_for_confirmed_threat(self, decision_engine, sample_siem_response):
        """Test immediate denial for confirmed threats."""
        # Kill report with confirmed threat and very high confidence
        threat_report = KillReport(
            kill_id="threat-kill",
            timestamp=datetime.utcnow(),
            target_module="infected-service",
            target_instance_id="instance",
            kill_reason=KillReason.THREAT_DETECTED,
            severity=Severity.CRITICAL,
            confidence_score=0.98,  # Very high confidence
            evidence=["malware-detected"],
            dependencies=[],
            source_agent="smith",
        )

        decision = decision_engine.should_resurrect(threat_report, sample_siem_response)

        assert decision.outcome == DecisionOutcome.DENY
        assert "Immediate denial" in decision.reasoning[0] or "threat" in str(decision.reasoning).lower()

    def test_deny_for_blacklisted_module(self, sample_kill_report, sample_siem_response):
        """Test denial for blacklisted modules."""
        config = DecisionConfig(always_deny_modules=["test-service"])
        engine = ObserverDecisionEngine(config)

        decision = engine.should_resurrect(sample_kill_report, sample_siem_response)

        assert decision.outcome == DecisionOutcome.DENY

    def test_reasoning_is_populated(
        self, decision_engine, sample_kill_report, sample_siem_response
    ):
        """Test that reasoning is populated with useful information."""
        decision = decision_engine.should_resurrect(
            sample_kill_report, sample_siem_response
        )

        assert len(decision.reasoning) > 0
        assert any("kill" in r.lower() or "module" in r.lower() for r in decision.reasoning)

    def test_confidence_calculation(
        self, decision_engine, sample_kill_report, sample_siem_response
    ):
        """Test that confidence is calculated and within bounds."""
        decision = decision_engine.should_resurrect(
            sample_kill_report, sample_siem_response
        )

        assert 0.0 <= decision.confidence <= 1.0

    def test_explain_decision(
        self, decision_engine, sample_kill_report, sample_siem_response
    ):
        """Test human-readable decision explanation."""
        decision = decision_engine.should_resurrect(
            sample_kill_report, sample_siem_response
        )

        explanation = decision_engine.explain_decision(decision)

        assert "Decision:" in explanation
        assert "Risk Level:" in explanation
        assert "Reasoning:" in explanation
        assert "Recommended Action:" in explanation

    def test_get_decision_factors(self, decision_engine):
        """Test getting list of decision factors."""
        factors = decision_engine.get_decision_factors()

        assert len(factors) > 0
        assert any("smith" in f.lower() for f in factors)
        assert any("siem" in f.lower() for f in factors)

    def test_statistics_tracking(
        self, decision_engine, sample_kill_report, sample_siem_response
    ):
        """Test that statistics are tracked."""
        initial_stats = decision_engine.get_statistics()
        initial_count = initial_stats["total_decisions"]

        decision_engine.should_resurrect(sample_kill_report, sample_siem_response)

        updated_stats = decision_engine.get_statistics()
        assert updated_stats["total_decisions"] == initial_count + 1


class TestDecisionEngineFactory:
    """Tests for the decision engine factory function."""

    def test_create_observer_engine(self, sample_config):
        """Test creating an observer mode engine."""
        engine = create_decision_engine(sample_config)

        assert isinstance(engine, ObserverDecisionEngine)

    def test_create_with_custom_thresholds(self):
        """Test creating engine with custom risk weights."""
        config = {
            "mode": {"current": "observer"},
            "decision": {
                "confidence_threshold": 0.8,
            },
            "risk": {
                "weights": {
                    "smith_confidence": 0.5,
                    "siem_risk_score": 0.3,
                    "false_positive_history": 0.1,
                    "module_criticality": 0.05,
                    "time_of_day": 0.05,
                }
            },
        }

        engine = create_decision_engine(config)

        assert engine.config.smith_confidence_weight == 0.5
        assert engine.config.siem_risk_weight == 0.3
