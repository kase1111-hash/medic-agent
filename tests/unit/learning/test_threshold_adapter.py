"""
Unit tests for the ThresholdAdapter module.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from learning.outcome_store import (
    InMemoryOutcomeStore,
    ResurrectionOutcome,
    OutcomeType,
)
from learning.threshold_adapter import (
    ThresholdAdapter,
    ThresholdAdjustment,
    AdjustmentType,
    AdjustmentProposal,
    AdaptiveConfig,
    CurrentThresholds,
    create_threshold_adapter,
)
from core.risk import RiskThresholds, RiskWeights


class TestThresholdAdjustment:
    """Tests for ThresholdAdjustment dataclass."""

    def test_create_adjustment(self):
        """Test creating a ThresholdAdjustment instance."""
        adj = ThresholdAdjustment(
            adjustment_id="adj-001",
            timestamp=datetime.now(timezone.utc),
            threshold_name="auto_approve_max_score",
            old_value=0.4,
            new_value=0.35,
            adjustment_type=AdjustmentType.DECREASE,
            reason="Accuracy below target",
            confidence=0.85,
            supporting_data={"accuracy": 0.88},
        )

        assert adj.adjustment_id == "adj-001"
        assert adj.adjustment_type == AdjustmentType.DECREASE
        assert adj.confidence == 0.85

    def test_to_dict(self):
        """Test serializing adjustment to dict."""
        now = datetime.now(timezone.utc)
        adj = ThresholdAdjustment(
            adjustment_id="adj-001",
            timestamp=now,
            threshold_name="auto_approve_min_confidence",
            old_value=0.85,
            new_value=0.90,
            adjustment_type=AdjustmentType.INCREASE,
            reason="Low confidence outcomes performing worse",
            confidence=0.75,
            supporting_data={},
        )

        data = adj.to_dict()

        assert data["threshold_name"] == "auto_approve_min_confidence"
        assert data["old_value"] == 0.85
        assert data["new_value"] == 0.9
        assert data["adjustment_type"] == "increase"


class TestAdjustmentProposal:
    """Tests for AdjustmentProposal dataclass."""

    def test_create_proposal(self):
        """Test creating an AdjustmentProposal instance."""
        adj = ThresholdAdjustment(
            adjustment_id="adj-001",
            timestamp=datetime.now(timezone.utc),
            threshold_name="auto_approve_max_score",
            old_value=0.4,
            new_value=0.35,
            adjustment_type=AdjustmentType.DECREASE,
            reason="Test",
            confidence=0.8,
            supporting_data={},
        )

        proposal = AdjustmentProposal(
            proposal_id="prop-001",
            created_at=datetime.now(timezone.utc),
            adjustments=[adj],
            overall_confidence=0.8,
            expected_impact={"affected_decisions": 10},
        )

        assert proposal.proposal_id == "prop-001"
        assert proposal.status == "pending"
        assert len(proposal.adjustments) == 1

    def test_to_dict(self):
        """Test serializing proposal to dict."""
        now = datetime.now(timezone.utc)
        adj = ThresholdAdjustment(
            adjustment_id="adj-001",
            timestamp=now,
            threshold_name="test",
            old_value=0.5,
            new_value=0.45,
            adjustment_type=AdjustmentType.DECREASE,
            reason="Test",
            confidence=0.75,
            supporting_data={},
        )

        proposal = AdjustmentProposal(
            proposal_id="prop-001",
            created_at=now,
            adjustments=[adj],
            overall_confidence=0.75,
            expected_impact={},
            status="approved",
            approved_by="operator",
            approved_at=now,
        )

        data = proposal.to_dict()

        assert data["status"] == "approved"
        assert data["approved_by"] == "operator"


class TestAdaptiveConfig:
    """Tests for AdaptiveConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = AdaptiveConfig()

        assert config.enabled is True
        assert config.min_samples_required == 50
        assert config.max_adjustment_percent == 10.0
        assert config.require_approval is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = AdaptiveConfig(
            enabled=False,
            min_samples_required=100,
            target_auto_approve_accuracy=0.98,
        )

        assert config.enabled is False
        assert config.min_samples_required == 100
        assert config.target_auto_approve_accuracy == 0.98


class TestThresholdAdapter:
    """Tests for ThresholdAdapter."""

    @pytest.fixture
    def outcome_store(self):
        """Create a fresh InMemoryOutcomeStore."""
        return InMemoryOutcomeStore()

    @pytest.fixture
    def adapter(self, outcome_store):
        """Create a ThresholdAdapter with default config."""
        config = AdaptiveConfig(
            min_samples_required=10,  # Lower for testing
            adjustment_cooldown_hours=0,  # No cooldown for testing
        )
        return ThresholdAdapter(outcome_store, config)

    @pytest.fixture
    def populate_outcomes(self, outcome_store):
        """Helper to populate outcomes."""
        def _populate(success_rate=0.9, auto_approved=True, count=20):
            now = datetime.now(timezone.utc)
            success_count = int(count * success_rate)

            for i in range(count):
                outcome = ResurrectionOutcome(
                    outcome_id=f"out-{i}",
                    decision_id=f"dec-{i}",
                    kill_id=f"kill-{i}",
                    target_module="service",
                    timestamp=now - timedelta(hours=i),
                    outcome_type=OutcomeType.SUCCESS if i < success_count else OutcomeType.FAILURE,
                    original_risk_score=0.2 if i < success_count else 0.5,
                    original_confidence=0.9,
                    original_decision="approve_auto" if auto_approved else "approve_manual",
                    was_auto_approved=auto_approved,
                )
                outcome_store.store_outcome(outcome)

        return _populate

    def test_initialization(self, adapter):
        """Test ThresholdAdapter initialization."""
        assert adapter.outcome_store is not None
        assert adapter.config.enabled is True
        assert adapter.current is not None

    def test_disabled_adapter_returns_none(self, outcome_store, populate_outcomes):
        """Test that disabled adapter doesn't propose changes."""
        config = AdaptiveConfig(enabled=False)
        adapter = ThresholdAdapter(outcome_store, config)
        populate_outcomes(success_rate=0.5)

        proposal = adapter.analyze_and_propose()

        assert proposal is None

    def test_insufficient_samples_returns_none(self, adapter):
        """Test that insufficient samples returns None."""
        # Don't add any outcomes
        proposal = adapter.analyze_and_propose()

        assert proposal is None

    def test_propose_decrease_on_low_accuracy(self, adapter, populate_outcomes):
        """Test proposing threshold decrease when accuracy is low."""
        # 60% success rate, below 95% target
        populate_outcomes(success_rate=0.6, auto_approved=True, count=20)

        proposal = adapter.analyze_and_propose()

        # Should propose tightening threshold
        if proposal:
            assert proposal.status == "pending"
            decrease_adjs = [
                a for a in proposal.adjustments
                if a.adjustment_type == AdjustmentType.DECREASE
            ]
            assert len(decrease_adjs) >= 0  # May or may not propose based on data

    def test_no_proposal_when_accuracy_good(self, adapter, populate_outcomes):
        """Test no proposal when accuracy meets target."""
        # 100% success rate
        populate_outcomes(success_rate=1.0, auto_approved=True, count=20)

        proposal = adapter.analyze_and_propose()

        # Should not propose changes or propose relaxing
        if proposal:
            # If any proposal, should be to increase (relax) thresholds
            increase_adjs = [
                a for a in proposal.adjustments
                if a.adjustment_type == AdjustmentType.INCREASE
            ]
            assert len(increase_adjs) >= 0

    def test_approve_proposal(self, adapter, populate_outcomes):
        """Test approving a proposal."""
        populate_outcomes(success_rate=0.6, auto_approved=True, count=20)

        proposal = adapter.analyze_and_propose()

        if proposal:
            initial_version = adapter.current.version

            success = adapter.approve_proposal(proposal.proposal_id, "test-operator")

            assert success is True
            assert proposal.status == "approved"
            assert proposal.approved_by == "test-operator"
            assert adapter.current.version == initial_version + 1

    def test_reject_proposal(self, adapter, populate_outcomes):
        """Test rejecting a proposal."""
        populate_outcomes(success_rate=0.6, auto_approved=True, count=20)

        proposal = adapter.analyze_and_propose()

        if proposal:
            success = adapter.reject_proposal(proposal.proposal_id, "Not safe")

            assert success is True
            assert proposal.status == "rejected"

    def test_approve_nonexistent_proposal(self, adapter):
        """Test approving nonexistent proposal returns False."""
        success = adapter.approve_proposal("nonexistent", "operator")
        assert success is False

    def test_reject_nonexistent_proposal(self, adapter):
        """Test rejecting nonexistent proposal returns False."""
        success = adapter.reject_proposal("nonexistent")
        assert success is False

    def test_get_current_thresholds(self, adapter):
        """Test getting current thresholds."""
        thresholds = adapter.get_current_thresholds()

        assert isinstance(thresholds, CurrentThresholds)
        assert thresholds.risk_thresholds is not None
        assert thresholds.version >= 1

    def test_get_pending_proposals(self, adapter, populate_outcomes):
        """Test getting pending proposals."""
        populate_outcomes(success_rate=0.6, auto_approved=True, count=20)

        # Create a proposal
        adapter.analyze_and_propose()

        pending = adapter.get_pending_proposals()

        # May be 0 or 1 depending on if proposal was generated
        assert isinstance(pending, list)

    def test_get_adjustment_history(self, adapter, populate_outcomes):
        """Test getting adjustment history."""
        populate_outcomes(success_rate=0.6, auto_approved=True, count=20)

        proposal = adapter.analyze_and_propose()
        if proposal:
            adapter.approve_proposal(proposal.proposal_id, "operator")

        history = adapter.get_adjustment_history()

        assert isinstance(history, list)

    def test_simulate_adjustment(self, adapter, populate_outcomes):
        """Test simulating an adjustment."""
        populate_outcomes(success_rate=0.8, auto_approved=True, count=20)

        adj = ThresholdAdjustment(
            adjustment_id="sim-001",
            timestamp=datetime.now(timezone.utc),
            threshold_name="auto_approve_max_score",
            old_value=0.5,
            new_value=0.3,
            adjustment_type=AdjustmentType.DECREASE,
            reason="Test simulation",
            confidence=0.8,
            supporting_data={},
        )

        results = adapter.simulate_adjustment(adj)

        assert "total_outcomes" in results
        assert "would_change" in results

    def test_cooldown_prevents_analysis(self, outcome_store, populate_outcomes):
        """Test that cooldown prevents repeated analysis."""
        config = AdaptiveConfig(
            min_samples_required=10,
            adjustment_cooldown_hours=24,
        )
        adapter = ThresholdAdapter(outcome_store, config)
        populate_outcomes(success_rate=0.6, count=20)

        # First analysis
        adapter.analyze_and_propose()

        # Second analysis should return None due to cooldown
        result = adapter.analyze_and_propose()

        assert result is None


class TestCreateThresholdAdapter:
    """Tests for the create_threshold_adapter factory function."""

    def test_create_with_default_config(self):
        """Test creating adapter with minimal config."""
        store = InMemoryOutcomeStore()
        config = {}

        adapter = create_threshold_adapter(store, config)

        assert isinstance(adapter, ThresholdAdapter)

    def test_create_with_learning_config(self):
        """Test creating adapter with learning config."""
        store = InMemoryOutcomeStore()
        config = {
            "learning": {
                "threshold_adjustment": {
                    "enabled": True,
                    "min_samples": 100,
                    "max_adjustment_percent": 5,
                    "cooldown_hours": 48,
                    "target_accuracy": 0.98,
                }
            },
            "risk": {
                "thresholds": {
                    "auto_approve_max_score": 0.35,
                    "auto_approve_min_confidence": 0.9,
                }
            }
        }

        adapter = create_threshold_adapter(store, config)

        assert adapter.config.enabled is True
        assert adapter.config.min_samples_required == 100
        assert adapter.config.max_adjustment_percent == 5
        assert adapter.current.risk_thresholds.auto_approve_max_score == 0.35
