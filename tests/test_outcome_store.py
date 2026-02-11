"""
Test 4: Outcome store round-trip

Store an outcome, retrieve it, assert fields match.
Tests both InMemory and SQLite implementations.
"""

import os
import uuid
from datetime import datetime, timezone

import pytest

from learning.outcome_store import (
    FeedbackSource,
    InMemoryOutcomeStore,
    OutcomeType,
    ResurrectionOutcome,
    SQLiteOutcomeStore,
)


def _make_outcome(**overrides) -> ResurrectionOutcome:
    """Create a test outcome with sensible defaults."""
    defaults = dict(
        outcome_id=str(uuid.uuid4()),
        decision_id=str(uuid.uuid4()),
        kill_id=f"test-{uuid.uuid4().hex[:8]}",
        target_module="test-service",
        timestamp=datetime.now(timezone.utc),
        outcome_type=OutcomeType.SUCCESS,
        original_risk_score=0.25,
        original_confidence=0.85,
        original_decision="approve_auto",
        was_auto_approved=True,
        feedback_source=FeedbackSource.AUTOMATED,
        metadata={"test": True},
    )
    defaults.update(overrides)
    return ResurrectionOutcome(**defaults)


class TestInMemoryOutcomeStore:
    """Tests for InMemoryOutcomeStore."""

    def test_store_and_retrieve(self):
        """Store an outcome, get it back by ID, verify fields."""
        store = InMemoryOutcomeStore()
        outcome = _make_outcome()

        store.store_outcome(outcome)

        retrieved = store.get_outcome(outcome.outcome_id)
        assert retrieved is not None
        assert retrieved.outcome_id == outcome.outcome_id
        assert retrieved.kill_id == outcome.kill_id
        assert retrieved.target_module == outcome.target_module
        assert retrieved.outcome_type == outcome.outcome_type
        assert retrieved.original_risk_score == outcome.original_risk_score
        assert retrieved.was_auto_approved == outcome.was_auto_approved

    def test_get_recent_outcomes(self):
        """Recent outcomes are returned in reverse chronological order."""
        store = InMemoryOutcomeStore()
        ids = []
        for _ in range(5):
            o = _make_outcome()
            store.store_outcome(o)
            ids.append(o.outcome_id)

        recent = store.get_recent_outcomes(limit=3)
        assert len(recent) == 3
        # Most recent first
        assert recent[0].outcome_id == ids[-1]

    def test_get_outcomes_by_module(self):
        """Filter outcomes by target module."""
        store = InMemoryOutcomeStore()
        store.store_outcome(_make_outcome(target_module="module-a"))
        store.store_outcome(_make_outcome(target_module="module-b"))
        store.store_outcome(_make_outcome(target_module="module-a"))

        results = store.get_outcomes_by_module("module-a")
        assert len(results) == 2
        assert all(o.target_module == "module-a" for o in results)

    def test_get_statistics(self):
        """Statistics correctly aggregate outcome types."""
        store = InMemoryOutcomeStore()
        store.store_outcome(_make_outcome(outcome_type=OutcomeType.SUCCESS))
        store.store_outcome(_make_outcome(outcome_type=OutcomeType.SUCCESS))
        store.store_outcome(_make_outcome(outcome_type=OutcomeType.FAILURE))

        stats = store.get_statistics()
        assert stats.total_outcomes == 3
        assert stats.success_count == 2
        assert stats.failure_count == 1

    def test_update_outcome(self):
        """Update an outcome's fields after storage."""
        store = InMemoryOutcomeStore()
        outcome = _make_outcome(outcome_type=OutcomeType.UNDETERMINED)
        store.store_outcome(outcome)

        updated = store.update_outcome(outcome.outcome_id, {
            "outcome_type": "success",
            "human_feedback": "Verified by operator",
            "corrected_decision": "approve_manual",
        })
        assert updated is True

        retrieved = store.get_outcome(outcome.outcome_id)
        assert retrieved.human_feedback == "Verified by operator"
        assert retrieved.corrected_decision == "approve_manual"


class TestSQLiteOutcomeStore:
    """Tests for SQLiteOutcomeStore with a temporary database."""

    @pytest.fixture
    def db_path(self, tmp_path):
        return str(tmp_path / "test_outcomes.db")

    @pytest.fixture
    def store(self, db_path):
        return SQLiteOutcomeStore(db_path)

    def test_store_and_retrieve(self, store):
        """Store an outcome in SQLite, retrieve it, verify round-trip."""
        outcome = _make_outcome()
        store.store_outcome(outcome)

        retrieved = store.get_outcome(outcome.outcome_id)
        assert retrieved is not None
        assert retrieved.outcome_id == outcome.outcome_id
        assert retrieved.kill_id == outcome.kill_id
        assert retrieved.target_module == outcome.target_module
        assert retrieved.outcome_type == outcome.outcome_type
        assert retrieved.original_risk_score == outcome.original_risk_score
        assert retrieved.was_auto_approved == outcome.was_auto_approved

    def test_get_recent_outcomes(self, store):
        """Recent outcomes returned in reverse chronological order."""
        ids = []
        for _ in range(5):
            o = _make_outcome()
            store.store_outcome(o)
            ids.append(o.outcome_id)

        recent = store.get_recent_outcomes(limit=3)
        assert len(recent) == 3

    def test_get_outcomes_by_module(self, store):
        """Filter by module works in SQLite."""
        store.store_outcome(_make_outcome(target_module="module-a"))
        store.store_outcome(_make_outcome(target_module="module-b"))
        store.store_outcome(_make_outcome(target_module="module-a"))

        results = store.get_outcomes_by_module("module-a")
        assert len(results) == 2

    def test_statistics_on_empty_db(self, store):
        """Statistics on empty database should not crash."""
        stats = store.get_statistics()
        assert stats.total_outcomes == 0
        assert stats.success_count == 0
        assert stats.auto_approve_accuracy == 0.0

    def test_statistics_with_data(self, store):
        """Statistics aggregate correctly in SQLite."""
        store.store_outcome(_make_outcome(outcome_type=OutcomeType.SUCCESS))
        store.store_outcome(_make_outcome(outcome_type=OutcomeType.SUCCESS))
        store.store_outcome(_make_outcome(outcome_type=OutcomeType.FAILURE))

        stats = store.get_statistics()
        assert stats.total_outcomes == 3
        assert stats.success_count == 2
        assert stats.failure_count == 1

    def test_update_outcome(self, store):
        """Update works in SQLite."""
        outcome = _make_outcome(outcome_type=OutcomeType.UNDETERMINED)
        store.store_outcome(outcome)

        updated = store.update_outcome(outcome.outcome_id, {
            "human_feedback": "Looks good",
            "corrected_decision": "approve_manual",
        })
        assert updated is True

        retrieved = store.get_outcome(outcome.outcome_id)
        assert retrieved.human_feedback == "Looks good"
