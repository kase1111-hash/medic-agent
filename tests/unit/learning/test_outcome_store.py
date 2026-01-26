"""
Unit tests for the OutcomeStore module.
"""

import pytest
import tempfile
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from learning.outcome_store import (
    OutcomeStore,
    SQLiteOutcomeStore,
    InMemoryOutcomeStore,
    ResurrectionOutcome,
    OutcomeType,
    FeedbackSource,
    OutcomeStatistics,
    create_outcome_store,
)


class TestResurrectionOutcome:
    """Tests for ResurrectionOutcome dataclass."""

    def test_create_outcome(self):
        """Test creating a ResurrectionOutcome instance."""
        outcome = ResurrectionOutcome(
            outcome_id="out-001",
            decision_id="dec-001",
            kill_id="kill-001",
            target_module="test-service",
            timestamp=datetime.now(timezone.utc),
            outcome_type=OutcomeType.SUCCESS,
            original_risk_score=0.3,
            original_confidence=0.9,
            original_decision="approve_auto",
            was_auto_approved=True,
        )

        assert outcome.outcome_id == "out-001"
        assert outcome.outcome_type == OutcomeType.SUCCESS
        assert outcome.was_auto_approved is True

    def test_to_dict(self):
        """Test serializing ResurrectionOutcome to dict."""
        now = datetime.now(timezone.utc)
        outcome = ResurrectionOutcome(
            outcome_id="out-001",
            decision_id="dec-001",
            kill_id="kill-001",
            target_module="test-service",
            timestamp=now,
            outcome_type=OutcomeType.FAILURE,
            original_risk_score=0.5,
            original_confidence=0.8,
            original_decision="pending_review",
            was_auto_approved=False,
            health_score_after=0.6,
            time_to_healthy=45.0,
        )

        data = outcome.to_dict()

        assert data["outcome_id"] == "out-001"
        assert data["outcome_type"] == "failure"
        assert data["health_score_after"] == 0.6
        assert data["time_to_healthy"] == 45.0

    def test_from_dict(self):
        """Test deserializing ResurrectionOutcome from dict."""
        data = {
            "outcome_id": "out-002",
            "decision_id": "dec-002",
            "kill_id": "kill-002",
            "target_module": "api-service",
            "timestamp": "2024-01-15T10:30:00",
            "outcome_type": "rollback",
            "original_risk_score": 0.7,
            "original_confidence": 0.75,
            "original_decision": "approve_manual",
            "was_auto_approved": False,
            "feedback_source": "human",
            "metadata": {"notes": "test"},
        }

        outcome = ResurrectionOutcome.from_dict(data)

        assert outcome.outcome_id == "out-002"
        assert outcome.outcome_type == OutcomeType.ROLLBACK
        assert outcome.feedback_source == FeedbackSource.HUMAN_OPERATOR
        assert outcome.metadata == {"notes": "test"}


class TestInMemoryOutcomeStore:
    """Tests for InMemoryOutcomeStore."""

    @pytest.fixture
    def store(self):
        """Create a fresh InMemoryOutcomeStore."""
        return InMemoryOutcomeStore()

    @pytest.fixture
    def sample_outcome(self):
        """Create sample outcome for testing."""
        return ResurrectionOutcome(
            outcome_id="test-outcome-001",
            decision_id="dec-001",
            kill_id="kill-001",
            target_module="test-service",
            timestamp=datetime.now(timezone.utc),
            outcome_type=OutcomeType.SUCCESS,
            original_risk_score=0.25,
            original_confidence=0.9,
            original_decision="approve_auto",
            was_auto_approved=True,
            time_to_healthy=30.0,
        )

    def test_store_and_get_outcome(self, store, sample_outcome):
        """Test storing and retrieving an outcome."""
        store.store_outcome(sample_outcome)

        retrieved = store.get_outcome("test-outcome-001")

        assert retrieved is not None
        assert retrieved.outcome_id == sample_outcome.outcome_id
        assert retrieved.outcome_type == OutcomeType.SUCCESS

    def test_get_nonexistent_outcome(self, store):
        """Test retrieving nonexistent outcome returns None."""
        result = store.get_outcome("nonexistent")
        assert result is None

    def test_get_outcomes_by_module(self, store):
        """Test getting outcomes filtered by module."""
        for i in range(5):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service-a" if i < 3 else "service-b",
                timestamp=datetime.now(timezone.utc),
                outcome_type=OutcomeType.SUCCESS,
                original_risk_score=0.2,
                original_confidence=0.9,
                original_decision="approve_auto",
                was_auto_approved=True,
            )
            store.store_outcome(outcome)

        service_a = store.get_outcomes_by_module("service-a")
        service_b = store.get_outcomes_by_module("service-b")

        assert len(service_a) == 3
        assert len(service_b) == 2

    def test_get_outcomes_by_type(self, store):
        """Test getting outcomes filtered by type."""
        types = [OutcomeType.SUCCESS, OutcomeType.SUCCESS, OutcomeType.FAILURE, OutcomeType.ROLLBACK]

        for i, ot in enumerate(types):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service",
                timestamp=datetime.now(timezone.utc),
                outcome_type=ot,
                original_risk_score=0.3,
                original_confidence=0.8,
                original_decision="approve_auto",
                was_auto_approved=True,
            )
            store.store_outcome(outcome)

        successes = store.get_outcomes_by_type(OutcomeType.SUCCESS)
        failures = store.get_outcomes_by_type(OutcomeType.FAILURE)

        assert len(successes) == 2
        assert len(failures) == 1

    def test_get_recent_outcomes(self, store):
        """Test getting recent outcomes."""
        now = datetime.now(timezone.utc)

        for i in range(10):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service",
                timestamp=now - timedelta(hours=i),
                outcome_type=OutcomeType.SUCCESS,
                original_risk_score=0.2,
                original_confidence=0.9,
                original_decision="approve_auto",
                was_auto_approved=True,
            )
            store.store_outcome(outcome)

        recent = store.get_recent_outcomes(limit=5)

        assert len(recent) == 5
        # Should be ordered by timestamp descending
        assert recent[0].outcome_id == "out-0"

    def test_get_statistics(self, store):
        """Test getting aggregated statistics."""
        outcomes = [
            (OutcomeType.SUCCESS, True, 0.2),
            (OutcomeType.SUCCESS, True, 0.25),
            (OutcomeType.SUCCESS, True, 0.3),
            (OutcomeType.FAILURE, False, 0.6),
            (OutcomeType.ROLLBACK, False, 0.7),
            (OutcomeType.FALSE_POSITIVE, False, 0.4),
        ]

        for i, (ot, auto, risk) in enumerate(outcomes):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service",
                timestamp=datetime.now(timezone.utc),
                outcome_type=ot,
                original_risk_score=risk,
                original_confidence=0.8,
                original_decision="approve_auto" if auto else "pending_review",
                was_auto_approved=auto,
                time_to_healthy=30.0 if ot == OutcomeType.SUCCESS else None,
            )
            store.store_outcome(outcome)

        stats = store.get_statistics()

        assert stats.total_outcomes == 6
        assert stats.success_count == 3
        assert stats.failure_count == 1
        assert stats.rollback_count == 1
        assert stats.false_positive_count == 1
        assert stats.auto_approve_accuracy == 1.0  # All auto-approved succeeded

    def test_update_outcome(self, store, sample_outcome):
        """Test updating an existing outcome."""
        store.store_outcome(sample_outcome)

        success = store.update_outcome(
            "test-outcome-001",
            {"outcome_type": OutcomeType.ROLLBACK, "required_rollback": True},
        )

        assert success is True

        updated = store.get_outcome("test-outcome-001")
        assert updated.outcome_type == OutcomeType.ROLLBACK
        assert updated.required_rollback is True

    def test_update_nonexistent_outcome(self, store):
        """Test updating nonexistent outcome returns False."""
        success = store.update_outcome("nonexistent", {"outcome_type": OutcomeType.FAILURE})
        assert success is False


class TestSQLiteOutcomeStore:
    """Tests for SQLiteOutcomeStore."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a SQLiteOutcomeStore with temp database."""
        db_path = tmp_path / "test_outcomes.db"
        return SQLiteOutcomeStore(str(db_path))

    @pytest.fixture
    def sample_outcome(self):
        """Create sample outcome for testing."""
        return ResurrectionOutcome(
            outcome_id="sqlite-test-001",
            decision_id="dec-001",
            kill_id="kill-001",
            target_module="test-service",
            timestamp=datetime.now(timezone.utc),
            outcome_type=OutcomeType.SUCCESS,
            original_risk_score=0.25,
            original_confidence=0.9,
            original_decision="approve_auto",
            was_auto_approved=True,
            time_to_healthy=30.0,
            metadata={"test_key": "test_value"},
        )

    def test_store_and_get_outcome(self, store, sample_outcome):
        """Test storing and retrieving an outcome."""
        store.store_outcome(sample_outcome)

        retrieved = store.get_outcome("sqlite-test-001")

        assert retrieved is not None
        assert retrieved.outcome_id == sample_outcome.outcome_id
        assert retrieved.metadata == {"test_key": "test_value"}

    def test_get_outcomes_by_module(self, store):
        """Test getting outcomes by module."""
        for i in range(5):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="target-module" if i < 3 else "other-module",
                timestamp=datetime.now(timezone.utc),
                outcome_type=OutcomeType.SUCCESS,
                original_risk_score=0.2,
                original_confidence=0.9,
                original_decision="approve_auto",
                was_auto_approved=True,
            )
            store.store_outcome(outcome)

        results = store.get_outcomes_by_module("target-module")
        assert len(results) == 3

    def test_get_outcomes_with_since_filter(self, store):
        """Test getting outcomes with date filter."""
        now = datetime.now(timezone.utc)

        for i in range(5):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service",
                timestamp=now - timedelta(days=i),
                outcome_type=OutcomeType.SUCCESS,
                original_risk_score=0.2,
                original_confidence=0.9,
                original_decision="approve_auto",
                was_auto_approved=True,
            )
            store.store_outcome(outcome)

        # Get outcomes from last 2 days
        since = now - timedelta(days=2)
        results = store.get_recent_outcomes(since=since)

        assert len(results) == 3  # out-0, out-1, out-2

    def test_get_statistics(self, store):
        """Test SQLite statistics aggregation."""
        outcomes = [
            (OutcomeType.SUCCESS, True),
            (OutcomeType.SUCCESS, True),
            (OutcomeType.FAILURE, False),
            (OutcomeType.ROLLBACK, False),
        ]

        for i, (ot, auto) in enumerate(outcomes):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="service",
                timestamp=datetime.now(timezone.utc),
                outcome_type=ot,
                original_risk_score=0.3,
                original_confidence=0.8,
                original_decision="approve_auto" if auto else "pending",
                was_auto_approved=auto,
                time_to_healthy=30.0 if ot == OutcomeType.SUCCESS else None,
            )
            store.store_outcome(outcome)

        stats = store.get_statistics()

        assert stats.total_outcomes == 4
        assert stats.success_count == 2
        assert stats.failure_count == 1
        assert stats.rollback_count == 1

    def test_update_outcome(self, store, sample_outcome):
        """Test updating outcome in SQLite."""
        store.store_outcome(sample_outcome)

        success = store.update_outcome(
            "sqlite-test-001",
            {
                "outcome_type": OutcomeType.FAILURE,
                "human_feedback": "Failed during testing",
            },
        )

        assert success is True

        updated = store.get_outcome("sqlite-test-001")
        assert updated.outcome_type == OutcomeType.FAILURE
        assert updated.human_feedback == "Failed during testing"

    def test_update_with_invalid_field_rejected(self, store, sample_outcome):
        """Test that invalid fields are rejected in update."""
        store.store_outcome(sample_outcome)

        # Try to update non-allowed field
        success = store.update_outcome(
            "sqlite-test-001",
            {"outcome_id": "hacked-id"},  # This should be rejected
        )

        # Should still return True but outcome_id unchanged
        updated = store.get_outcome("sqlite-test-001")
        assert updated.outcome_id == "sqlite-test-001"

    def test_get_module_statistics(self, store):
        """Test module-specific statistics."""
        for i in range(5):
            outcome = ResurrectionOutcome(
                outcome_id=f"out-{i}",
                decision_id=f"dec-{i}",
                kill_id=f"kill-{i}",
                target_module="target-service",
                timestamp=datetime.now(timezone.utc),
                outcome_type=OutcomeType.SUCCESS if i < 4 else OutcomeType.FAILURE,
                original_risk_score=0.2 + i * 0.1,
                original_confidence=0.9,
                original_decision="approve_auto",
                was_auto_approved=True,
                time_to_healthy=30.0,
            )
            store.store_outcome(outcome)

        stats = store.get_module_statistics("target-service")

        assert stats["module"] == "target-service"
        assert stats["total_resurrections"] == 5
        assert stats["success_count"] == 4
        assert stats["failure_count"] == 1
        assert stats["success_rate"] == 0.8

    def test_close_connection(self, store, sample_outcome):
        """Test closing database connection."""
        store.store_outcome(sample_outcome)
        store.close()

        # Should not raise an error
        assert True


class TestCreateOutcomeStore:
    """Tests for the create_outcome_store factory function."""

    def test_create_sqlite_store(self, tmp_path):
        """Test creating SQLite store from config."""
        config = {
            "learning": {
                "database": {
                    "type": "sqlite",
                    "path": str(tmp_path / "test.db"),
                }
            }
        }

        store = create_outcome_store(config)

        assert isinstance(store, SQLiteOutcomeStore)

    def test_create_memory_store(self):
        """Test creating in-memory store from config."""
        config = {
            "learning": {
                "database": {
                    "type": "memory",
                }
            }
        }

        store = create_outcome_store(config)

        assert isinstance(store, InMemoryOutcomeStore)

    def test_create_with_empty_config_defaults_to_sqlite(self):
        """Test that empty config defaults to SQLite."""
        store = create_outcome_store({})

        assert isinstance(store, SQLiteOutcomeStore)

    def test_create_unknown_type_defaults_to_memory(self):
        """Test that unknown type defaults to in-memory."""
        config = {
            "learning": {
                "database": {
                    "type": "postgres",  # Not implemented
                }
            }
        }

        store = create_outcome_store(config)

        assert isinstance(store, InMemoryOutcomeStore)
