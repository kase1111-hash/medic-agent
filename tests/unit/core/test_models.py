"""
Unit tests for core data models.
"""

import pytest
from datetime import datetime, timezone

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


class TestKillReport:
    """Tests for KillReport model."""

    def test_create_kill_report(self, sample_kill_report):
        """Test creating a valid kill report."""
        assert sample_kill_report.kill_id is not None
        assert sample_kill_report.target_module == "test-service"
        assert sample_kill_report.kill_reason == KillReason.ANOMALY_BEHAVIOR
        assert sample_kill_report.severity == Severity.MEDIUM
        assert 0.0 <= sample_kill_report.confidence_score <= 1.0

    def test_invalid_confidence_score(self):
        """Test that invalid confidence score raises error."""
        with pytest.raises(ValueError):
            KillReport(
                kill_id="test",
                timestamp=datetime.now(timezone.utc),
                target_module="test",
                target_instance_id="test",
                kill_reason=KillReason.ANOMALY_BEHAVIOR,
                severity=Severity.MEDIUM,
                confidence_score=1.5,  # Invalid: > 1.0
                evidence=[],
                dependencies=[],
                source_agent="smith",
            )

    def test_from_dict(self):
        """Test creating KillReport from dictionary."""
        data = {
            "kill_id": "test-kill-001",
            "timestamp": "2024-01-15T10:30:00Z",
            "target_module": "auth-service",
            "target_instance_id": "instance-001",
            "kill_reason": "threat_detected",
            "severity": "high",
            "confidence_score": 0.85,
            "evidence": ["evidence-1"],
            "dependencies": ["dep-1"],
            "source_agent": "smith-01",
            "metadata": {"key": "value"},
        }

        report = KillReport.from_dict(data)

        assert report.kill_id == "test-kill-001"
        assert report.target_module == "auth-service"
        assert report.kill_reason == KillReason.THREAT_DETECTED
        assert report.severity == Severity.HIGH
        assert report.confidence_score == 0.85

    def test_to_dict(self, sample_kill_report):
        """Test converting KillReport to dictionary."""
        data = sample_kill_report.to_dict()

        assert data["kill_id"] == sample_kill_report.kill_id
        assert data["target_module"] == "test-service"
        assert data["kill_reason"] == "anomaly_behavior"
        assert data["severity"] == "medium"


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_from_score_minimal(self):
        """Test minimal risk level from score."""
        assert RiskLevel.from_score(0.1) == RiskLevel.MINIMAL

    def test_from_score_low(self):
        """Test low risk level from score."""
        assert RiskLevel.from_score(0.3) == RiskLevel.LOW

    def test_from_score_medium(self):
        """Test medium risk level from score."""
        assert RiskLevel.from_score(0.5) == RiskLevel.MEDIUM

    def test_from_score_high(self):
        """Test high risk level from score."""
        assert RiskLevel.from_score(0.7) == RiskLevel.HIGH

    def test_from_score_critical(self):
        """Test critical risk level from score."""
        assert RiskLevel.from_score(0.9) == RiskLevel.CRITICAL

    def test_from_score_boundary(self):
        """Test boundary values."""
        assert RiskLevel.from_score(0.0) == RiskLevel.MINIMAL
        assert RiskLevel.from_score(0.2) == RiskLevel.LOW
        assert RiskLevel.from_score(1.0) == RiskLevel.CRITICAL


class TestSIEMContextResponse:
    """Tests for SIEMContextResponse model."""

    def test_create_siem_response(self, sample_siem_response):
        """Test creating a valid SIEM response."""
        assert sample_siem_response.query_id is not None
        assert sample_siem_response.risk_score == 0.35
        assert sample_siem_response.false_positive_history == 2

    def test_from_dict_with_indicators(self):
        """Test creating SIEMContextResponse with threat indicators."""
        data = {
            "query_id": "query-001",
            "kill_id": "kill-001",
            "timestamp": "2024-01-15T10:30:00Z",
            "threat_indicators": [
                {
                    "indicator_type": "ip",
                    "value": "192.168.1.1",
                    "threat_score": 0.75,
                    "source": "threat_intel",
                    "last_seen": "2024-01-15T10:00:00Z",
                    "tags": ["malicious", "c2"],
                }
            ],
            "historical_behavior": {},
            "false_positive_history": 0,
            "network_context": {},
            "user_context": None,
            "risk_score": 0.75,
            "recommendation": "high_risk",
        }

        response = SIEMContextResponse.from_dict(data)

        assert len(response.threat_indicators) == 1
        assert response.threat_indicators[0].indicator_type == "ip"
        assert response.threat_indicators[0].threat_score == 0.75


class TestResurrectionDecision:
    """Tests for ResurrectionDecision model."""

    def test_create_decision(self):
        """Test creating a decision using factory method."""
        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.45,
            confidence=0.75,
            reasoning=["Moderate risk detected", "Manual review recommended"],
            recommended_action="Queue for human review",
        )

        assert decision.decision_id is not None
        assert decision.kill_id == "kill-001"
        assert decision.outcome == DecisionOutcome.PENDING_REVIEW
        assert decision.risk_level == RiskLevel.MEDIUM
        assert decision.requires_human_review is True
        assert decision.auto_approve_eligible is False

    def test_auto_approve_eligible(self):
        """Test auto-approve eligibility calculation."""
        # Low risk, high confidence -> eligible
        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.APPROVE_AUTO,
            risk_score=0.15,
            confidence=0.9,
            reasoning=["Low risk"],
            recommended_action="Auto-approve",
        )

        assert decision.auto_approve_eligible is True

        # Low risk, low confidence -> not eligible
        decision = ResurrectionDecision.create(
            kill_id="kill-002",
            outcome=DecisionOutcome.PENDING_REVIEW,
            risk_score=0.15,
            confidence=0.6,
            reasoning=["Low risk but uncertain"],
            recommended_action="Review",
        )

        assert decision.auto_approve_eligible is False

    def test_to_dict(self):
        """Test converting decision to dictionary."""
        decision = ResurrectionDecision.create(
            kill_id="kill-001",
            outcome=DecisionOutcome.DENY,
            risk_score=0.85,
            confidence=0.9,
            reasoning=["High risk"],
            recommended_action="Deny",
        )

        data = decision.to_dict()

        assert data["kill_id"] == "kill-001"
        assert data["outcome"] == "deny"
        assert data["risk_level"] == "critical"
        assert "timestamp" in data
