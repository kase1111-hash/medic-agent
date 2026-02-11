"""
Test 5: API endpoint tests

Tests all four API endpoints using FastAPI's TestClient.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api import app, configure
from core.decision import DecisionConfig, LiveDecisionEngine
from learning.outcome_store import (
    FeedbackSource,
    InMemoryOutcomeStore,
    OutcomeType,
    ResurrectionOutcome,
)


@pytest.fixture
def client():
    """Set up API with fresh test dependencies."""
    store = InMemoryOutcomeStore()
    engine = LiveDecisionEngine(
        DecisionConfig(auto_approve_enabled=True),
        outcome_store=store,
    )
    configure(store, engine, mode="test")

    # Seed some outcomes
    for i in range(3):
        store.store_outcome(ResurrectionOutcome(
            outcome_id=f"test-outcome-{i}",
            decision_id=f"test-decision-{i}",
            kill_id=f"test-kill-{i}",
            target_module="api-test-service",
            timestamp=datetime.now(timezone.utc),
            outcome_type=OutcomeType.SUCCESS if i < 2 else OutcomeType.UNDETERMINED,
            original_risk_score=0.2 + i * 0.1,
            original_confidence=0.85,
            original_decision="approve_auto",
            was_auto_approved=True,
            feedback_source=FeedbackSource.AUTOMATED,
            metadata={"test_index": i},
        ))

    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["mode"] == "test"
        assert "uptime_seconds" in data
        assert data["version"] == "0.2.0-alpha"


class TestDecisionsRecentEndpoint:
    def test_returns_seeded_decisions(self, client):
        resp = client.get("/decisions/recent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert len(data["decisions"]) == 3

    def test_decisions_have_required_fields(self, client):
        resp = client.get("/decisions/recent")
        decision = resp.json()["decisions"][0]
        required = [
            "outcome_id", "decision_id", "kill_id", "target_module",
            "timestamp", "outcome_type", "original_risk_score",
        ]
        for field in required:
            assert field in decision, f"Missing field: {field}"


class TestStatsEndpoint:
    def test_stats_returns_aggregates(self, client):
        resp = client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_outcomes"] == 3
        assert data["success_count"] == 2
        assert "decision_engine" in data

    def test_stats_includes_engine_data(self, client):
        resp = client.get("/stats")
        engine_data = resp.json()["decision_engine"]
        assert "total_decisions" in engine_data
        assert "outcome_counts" in engine_data


class TestApproveEndpoint:
    def test_approve_pending_outcome(self, client):
        """Approve an UNDETERMINED outcome (test-kill-2)."""
        resp = client.post("/approve/test-kill-2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "approved"
        assert data["kill_id"] == "test-kill-2"

    def test_approve_nonexistent_returns_404(self, client):
        resp = client.post("/approve/nonexistent-kill-id")
        assert resp.status_code == 404

    def test_approve_already_resolved_returns_409(self, client):
        """Approving a SUCCESS outcome should fail with 409."""
        resp = client.post("/approve/test-kill-0")
        assert resp.status_code == 409
        assert "already resolved" in resp.json()["detail"]
