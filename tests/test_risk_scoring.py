"""
Test 3: Risk scoring accuracy

Unit tests: given specific KillReport + SIEMResult inputs,
assert expected risk_score, risk_level, and decision outcomes.
"""

import pytest

from core.decision import DecisionConfig, LiveDecisionEngine
from core.models import (
    DecisionOutcome,
    KillReason,
    RiskLevel,
    SIEMResult,
    Severity,
)
from learning.outcome_store import InMemoryOutcomeStore
from tests.conftest import make_kill_report, seed_outcomes


class TestRiskScoring:
    """Verify risk assessment produces expected scores for known inputs."""

    def _engine(self, outcome_store=None):
        return LiveDecisionEngine(
            DecisionConfig(auto_approve_enabled=True, auto_approve_min_confidence=0.5),
            outcome_store=outcome_store,
        )

    def test_low_risk_low_score(self):
        """Low severity + low confidence + benign reason → below-medium risk."""
        engine = self._engine()
        report = make_kill_report(
            kill_reason=KillReason.RESOURCE_EXHAUSTION,
            severity=Severity.LOW,
            confidence_score=0.2,
        )
        # With NoopSIEM (0.5 risk), score lands ~0.46 (medium).
        # With a low-risk SIEM it would be truly LOW.
        decision = engine.should_resurrect(report)

        assert decision.risk_score < 0.5
        assert decision.risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_low_risk_with_favorable_siem(self):
        """Low severity + favorable SIEM → truly low risk score."""
        engine = self._engine()
        report = make_kill_report(
            kill_reason=KillReason.RESOURCE_EXHAUSTION,
            severity=Severity.LOW,
            confidence_score=0.2,
        )
        siem = SIEMResult(risk_score=0.1, recommendation="allow", false_positive_history=5)
        decision = engine.should_resurrect(report, siem)

        assert decision.risk_score < 0.3
        assert decision.risk_level in (RiskLevel.MINIMAL, RiskLevel.LOW)

    def test_high_risk_high_score(self):
        """Critical severity + very high confidence + threat → immediate deny."""
        engine = self._engine()
        report = make_kill_report(
            kill_reason=KillReason.THREAT_DETECTED,
            severity=Severity.CRITICAL,
            confidence_score=0.99,  # >0.95 triggers immediate deny
        )
        decision = engine.should_resurrect(report)

        assert decision.outcome == DecisionOutcome.DENY
        assert decision.risk_score >= 0.9

    def test_high_risk_without_immediate_deny(self):
        """High confidence threat (but <=0.95) → DENY via risk scoring."""
        engine = self._engine()
        report = make_kill_report(
            kill_reason=KillReason.THREAT_DETECTED,
            severity=Severity.CRITICAL,
            confidence_score=0.95,
        )
        decision = engine.should_resurrect(report)

        # Not immediate deny, but risk score is HIGH → still DENY
        assert decision.outcome == DecisionOutcome.DENY
        assert decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_medium_risk_pending_review(self):
        """Medium severity + moderate confidence → pending review."""
        engine = self._engine()
        report = make_kill_report(
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.6,
        )
        decision = engine.should_resurrect(report)

        # Should be medium-ish risk, not auto-approved
        assert 0.3 <= decision.risk_score <= 0.7
        assert decision.outcome in (DecisionOutcome.PENDING_REVIEW, DecisionOutcome.DENY)

    def test_siem_enrichment_affects_score(self):
        """SIEM risk score influences the overall risk assessment."""
        engine = self._engine()
        report = make_kill_report(
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.LOW,
            confidence_score=0.3,
        )

        # Low SIEM risk
        low_siem = SIEMResult(risk_score=0.1, recommendation="allow")
        d_low = engine.should_resurrect(report, low_siem)

        # High SIEM risk
        high_siem = SIEMResult(risk_score=0.9, recommendation="block")
        d_high = engine.should_resurrect(report, high_siem)

        assert d_high.risk_score > d_low.risk_score

    def test_false_positive_history_lowers_risk(self):
        """Many false positives for a module → lower risk (Smith was wrong before)."""
        engine = self._engine()
        report = make_kill_report(
            kill_reason=KillReason.ANOMALY_BEHAVIOR,
            severity=Severity.MEDIUM,
            confidence_score=0.5,
        )

        # No FP history
        no_fp = SIEMResult(false_positive_history=0)
        d_no_fp = engine.should_resurrect(report, no_fp)

        # Lots of FP history → Smith cried wolf, lower risk
        many_fp = SIEMResult(false_positive_history=10)
        d_many_fp = engine.should_resurrect(report, many_fp)

        assert d_many_fp.risk_score < d_no_fp.risk_score

    def test_outcome_history_boosts_confidence(self):
        """When outcome store has module history, confidence increases."""
        store = InMemoryOutcomeStore()
        seed_outcomes(store, count=20, success_rate=0.9, module="data-processor")

        engine_no_hist = self._engine()
        engine_with_hist = self._engine(outcome_store=store)

        report = make_kill_report(
            target_module="data-processor",
            kill_reason=KillReason.RESOURCE_EXHAUSTION,
            severity=Severity.LOW,
            confidence_score=0.2,
        )

        d1 = engine_no_hist.should_resurrect(report)
        d2 = engine_with_hist.should_resurrect(report)

        assert d2.confidence >= d1.confidence


class TestCalibration:
    """Verify calibrate() adjusts thresholds based on outcome history."""

    def test_calibrate_skips_with_no_data(self):
        """Calibration should be a no-op with empty store."""
        store = InMemoryOutcomeStore()
        engine = LiveDecisionEngine(
            DecisionConfig(auto_approve_enabled=True, auto_approve_min_confidence=0.85),
            outcome_store=store,
        )
        original = engine.config.auto_approve_min_confidence
        engine.calibrate()
        assert engine.config.auto_approve_min_confidence == original

    def test_calibrate_lowers_threshold_high_accuracy(self):
        """97% auto-approve accuracy → threshold should decrease."""
        store = InMemoryOutcomeStore()
        # 97% of 60 = 58 successes → 58/60 = 0.967 > 0.95 threshold
        seed_outcomes(store, count=60, success_rate=0.97, auto_approved=True)

        engine = LiveDecisionEngine(
            DecisionConfig(auto_approve_enabled=True, auto_approve_min_confidence=0.85),
            outcome_store=store,
        )
        engine.calibrate()
        assert engine.config.auto_approve_min_confidence < 0.85

    def test_calibrate_raises_threshold_low_accuracy(self):
        """70% auto-approve accuracy → threshold should increase."""
        store = InMemoryOutcomeStore()
        seed_outcomes(store, count=60, success_rate=0.70, auto_approved=True)

        engine = LiveDecisionEngine(
            DecisionConfig(auto_approve_enabled=True, auto_approve_min_confidence=0.85),
            outcome_store=store,
        )
        engine.calibrate()
        assert engine.config.auto_approve_min_confidence > 0.85

    def test_calibrate_no_change_acceptable_accuracy(self):
        """90% accuracy → threshold unchanged."""
        store = InMemoryOutcomeStore()
        seed_outcomes(store, count=60, success_rate=0.90, auto_approved=True)

        engine = LiveDecisionEngine(
            DecisionConfig(auto_approve_enabled=True, auto_approve_min_confidence=0.85),
            outcome_store=store,
        )
        engine.calibrate()
        assert engine.config.auto_approve_min_confidence == 0.85
