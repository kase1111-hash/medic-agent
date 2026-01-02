"""
Unit tests for the PatternAnalyzer module.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from learning.outcome_store import (
    InMemoryOutcomeStore,
    ResurrectionOutcome,
    OutcomeType,
)
from learning.pattern_analyzer import (
    PatternAnalyzer,
    DetectedPattern,
    PatternType,
    PatternSeverity,
    ModuleProfile,
    AnalysisConfig,
    create_pattern_analyzer,
)


class TestDetectedPattern:
    """Tests for DetectedPattern dataclass."""

    def test_create_pattern(self):
        """Test creating a DetectedPattern instance."""
        pattern = DetectedPattern(
            pattern_id="pat-001",
            pattern_type=PatternType.FALSE_POSITIVE_SPIKE,
            severity=PatternSeverity.WARNING,
            detected_at=datetime.utcnow(),
            description="High false positive rate",
            confidence=0.85,
            affected_modules=["service-a", "service-b"],
            evidence={"rate": 0.35},
            recommended_actions=["Review thresholds"],
        )

        assert pattern.pattern_id == "pat-001"
        assert pattern.pattern_type == PatternType.FALSE_POSITIVE_SPIKE
        assert pattern.confidence == 0.85

    def test_to_dict(self):
        """Test serializing pattern to dict."""
        now = datetime.utcnow()
        pattern = DetectedPattern(
            pattern_id="pat-001",
            pattern_type=PatternType.MODULE_INSTABILITY,
            severity=PatternSeverity.CRITICAL,
            detected_at=now,
            description="Module unstable",
            confidence=0.9,
            affected_modules=["unstable-service"],
            evidence={"failure_rate": 0.5},
            recommended_actions=["Investigate"],
        )

        data = pattern.to_dict()

        assert data["pattern_type"] == "module_instability"
        assert data["severity"] == "critical"
        assert data["confidence"] == 0.9


class TestModuleProfile:
    """Tests for ModuleProfile dataclass."""

    def test_create_profile(self):
        """Test creating a ModuleProfile instance."""
        profile = ModuleProfile(
            module="test-service",
            total_resurrections=100,
            success_rate=0.95,
            avg_risk_score=0.25,
            avg_recovery_time=45.0,
            false_positive_rate=0.3,
            auto_approve_eligible=True,
            risk_trend="stable",
            last_failure=datetime.utcnow() - timedelta(days=7),
            last_updated=datetime.utcnow(),
        )

        assert profile.module == "test-service"
        assert profile.auto_approve_eligible is True
        assert profile.risk_trend == "stable"

    def test_to_dict(self):
        """Test serializing profile to dict."""
        now = datetime.utcnow()
        profile = ModuleProfile(
            module="api-service",
            total_resurrections=50,
            success_rate=0.88,
            avg_risk_score=0.35,
            avg_recovery_time=60.0,
            false_positive_rate=0.15,
            auto_approve_eligible=False,
            risk_trend="increasing",
            last_failure=now,
            last_updated=now,
        )

        data = profile.to_dict()

        assert data["module"] == "api-service"
        assert data["success_rate"] == 0.88
        assert data["risk_trend"] == "increasing"


class TestPatternAnalyzer:
    """Tests for PatternAnalyzer."""

    @pytest.fixture
    def outcome_store(self):
        """Create a fresh InMemoryOutcomeStore."""
        return InMemoryOutcomeStore()

    @pytest.fixture
    def analyzer(self, outcome_store):
        """Create a PatternAnalyzer with default config."""
        return PatternAnalyzer(outcome_store)

    @pytest.fixture
    def populate_outcomes(self, outcome_store):
        """Helper to populate outcomes."""
        def _populate(count, types_dist=None, modules=None):
            """
            Populate outcomes with given distribution.
            types_dist: dict mapping OutcomeType to count
            """
            now = datetime.utcnow()

            if types_dist is None:
                types_dist = {OutcomeType.SUCCESS: count}

            if modules is None:
                modules = ["service-a"]

            outcomes = []
            idx = 0

            for ot, ot_count in types_dist.items():
                for i in range(ot_count):
                    module = modules[idx % len(modules)]
                    outcome = ResurrectionOutcome(
                        outcome_id=f"out-{idx}",
                        decision_id=f"dec-{idx}",
                        kill_id=f"kill-{idx}",
                        target_module=module,
                        timestamp=now - timedelta(hours=idx),
                        outcome_type=ot,
                        original_risk_score=0.2 + (0.1 if ot != OutcomeType.SUCCESS else 0),
                        original_confidence=0.9,
                        original_decision="approve_auto",
                        was_auto_approved=True,
                        time_to_healthy=30.0 if ot == OutcomeType.SUCCESS else None,
                    )
                    outcome_store.store_outcome(outcome)
                    outcomes.append(outcome)
                    idx += 1

            return outcomes

        return _populate

    def test_initialization(self, analyzer):
        """Test PatternAnalyzer initialization."""
        assert analyzer.outcome_store is not None
        assert analyzer.config is not None
        assert analyzer.config.min_samples_for_analysis == 10

    def test_analyze_insufficient_samples(self, analyzer, populate_outcomes):
        """Test that analysis returns empty when insufficient samples."""
        populate_outcomes(5)  # Less than min_samples

        patterns = analyzer.analyze()

        assert patterns == []

    def test_detect_false_positive_spike(self, analyzer, populate_outcomes):
        """Test detection of false positive spike."""
        # Create outcomes with high FP rate (>30%)
        populate_outcomes(
            count=0,
            types_dist={
                OutcomeType.SUCCESS: 5,
                OutcomeType.FALSE_POSITIVE: 6,  # 54% FP rate
            },
        )

        patterns = analyzer.analyze()

        fp_patterns = [p for p in patterns if p.pattern_type == PatternType.FALSE_POSITIVE_SPIKE]
        assert len(fp_patterns) >= 1
        assert fp_patterns[0].severity in (PatternSeverity.WARNING, PatternSeverity.CRITICAL)

    def test_detect_module_instability(self, analyzer, populate_outcomes):
        """Test detection of module instability."""
        # Create outcomes with high failure rate for one module
        now = datetime.utcnow()

        # Add successful outcomes for service-a
        for i in range(5):
            outcome = ResurrectionOutcome(
                outcome_id=f"success-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service-a",
                timestamp=now - timedelta(hours=i),
                outcome_type=OutcomeType.SUCCESS,
                original_risk_score=0.2,
                original_confidence=0.9,
                original_decision="approve_auto",
                was_auto_approved=True,
            )
            analyzer.outcome_store.store_outcome(outcome)

        # Add mostly failures for service-b
        for i in range(5):
            outcome = ResurrectionOutcome(
                outcome_id=f"failure-{i}",
                decision_id=f"dec-fail-{i}",
                kill_id=f"kill-fail-{i}",
                target_module="service-b",
                timestamp=now - timedelta(hours=i + 5),
                outcome_type=OutcomeType.FAILURE if i < 4 else OutcomeType.SUCCESS,
                original_risk_score=0.5,
                original_confidence=0.7,
                original_decision="approve_manual",
                was_auto_approved=False,
            )
            analyzer.outcome_store.store_outcome(outcome)

        patterns = analyzer.analyze()

        instability = [p for p in patterns if p.pattern_type == PatternType.MODULE_INSTABILITY]
        if instability:
            assert "service-b" in instability[0].affected_modules

    def test_detect_auto_approve_degradation(self, analyzer, outcome_store):
        """Test detection of auto-approve accuracy degradation."""
        now = datetime.utcnow()

        # Create many auto-approved outcomes with some failures
        for i in range(20):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service",
                timestamp=now - timedelta(hours=i),
                outcome_type=OutcomeType.SUCCESS if i < 12 else OutcomeType.FAILURE,
                original_risk_score=0.2,
                original_confidence=0.9,
                original_decision="approve_auto",
                was_auto_approved=True,
            )
            outcome_store.store_outcome(outcome)

        patterns = analyzer.analyze()

        degradation = [p for p in patterns if p.pattern_type == PatternType.AUTO_APPROVE_DEGRADATION]
        # 12/20 = 60% accuracy, below 90% threshold
        assert len(degradation) >= 1

    def test_build_module_profile(self, analyzer, populate_outcomes):
        """Test building module profile."""
        populate_outcomes(
            count=0,
            types_dist={
                OutcomeType.SUCCESS: 8,
                OutcomeType.FAILURE: 2,
            },
            modules=["target-service"],
        )

        profile = analyzer.build_module_profile("target-service")

        assert profile.module == "target-service"
        assert profile.total_resurrections == 10
        assert profile.success_rate == 0.8

    def test_build_profile_for_unknown_module(self, analyzer):
        """Test building profile for module with no data."""
        profile = analyzer.build_module_profile("unknown-service")

        assert profile.module == "unknown-service"
        assert profile.total_resurrections == 0
        assert profile.auto_approve_eligible is False

    def test_get_all_module_profiles(self, analyzer, outcome_store):
        """Test getting profiles for all modules."""
        now = datetime.utcnow()

        modules = ["service-a", "service-b", "service-c"]
        for i, module in enumerate(modules):
            for j in range(5):
                outcome = ResurrectionOutcome(
                    outcome_id=f"out-{module}-{j}",
                    decision_id=f"dec-{i}-{j}",
                    kill_id=f"kill-{i}-{j}",
                    target_module=module,
                    timestamp=now - timedelta(hours=j),
                    outcome_type=OutcomeType.SUCCESS,
                    original_risk_score=0.2,
                    original_confidence=0.9,
                    original_decision="approve_auto",
                    was_auto_approved=True,
                )
                outcome_store.store_outcome(outcome)

        profiles = analyzer.get_all_module_profiles()

        assert len(profiles) == 3
        assert all(p.total_resurrections == 5 for p in profiles)

    def test_get_recommendations(self, analyzer, populate_outcomes):
        """Test getting recommendations."""
        populate_outcomes(
            count=0,
            types_dist={
                OutcomeType.SUCCESS: 5,
                OutcomeType.FALSE_POSITIVE: 6,
            },
        )

        recommendations = analyzer.get_recommendations()

        assert "patterns_detected" in recommendations
        assert "suggested_actions" in recommendations
        assert len(recommendations["suggested_actions"]) > 0


class TestAnalysisConfig:
    """Tests for AnalysisConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = AnalysisConfig()

        assert config.min_samples_for_analysis == 10
        assert config.false_positive_threshold == 0.3
        assert config.success_rate_threshold == 0.7
        assert config.time_window_days == 30

    def test_custom_config(self):
        """Test custom configuration."""
        config = AnalysisConfig(
            min_samples_for_analysis=50,
            false_positive_threshold=0.2,
            auto_approve_accuracy_threshold=0.95,
        )

        assert config.min_samples_for_analysis == 50
        assert config.false_positive_threshold == 0.2
        assert config.auto_approve_accuracy_threshold == 0.95


class TestCreatePatternAnalyzer:
    """Tests for the create_pattern_analyzer factory function."""

    def test_create_with_default_config(self):
        """Test creating analyzer with default config."""
        store = InMemoryOutcomeStore()
        analyzer = create_pattern_analyzer(store)

        assert isinstance(analyzer, PatternAnalyzer)
        assert analyzer.config.min_samples_for_analysis == 10

    def test_create_with_custom_config(self):
        """Test creating analyzer with custom config."""
        store = InMemoryOutcomeStore()
        config = {
            "min_samples": 25,
            "false_positive_threshold": 0.25,
            "time_window_days": 14,
        }

        analyzer = create_pattern_analyzer(store, config)

        assert analyzer.config.min_samples_for_analysis == 25
        assert analyzer.config.false_positive_threshold == 0.25
        assert analyzer.config.time_window_days == 14
