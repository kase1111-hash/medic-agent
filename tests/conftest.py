"""Shared test fixtures for medic-agent tests."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from core.decision import (
    DecisionConfig,
    LiveDecisionEngine,
    ObserverDecisionEngine,
    create_decision_engine,
)
from core.models import (
    DecisionOutcome,
    KillReason,
    KillReport,
    RiskLevel,
    SIEMResult,
    Severity,
)
from core.resurrector import DryRunResurrector
from core.siem import NoopSIEMClient
from learning.outcome_store import (
    FeedbackSource,
    InMemoryOutcomeStore,
    OutcomeType,
    ResurrectionOutcome,
)


@pytest.fixture
def outcome_store():
    """Fresh in-memory outcome store."""
    return InMemoryOutcomeStore()


@pytest.fixture
def siem_client():
    """Noop SIEM client."""
    return NoopSIEMClient()


@pytest.fixture
def resurrector():
    """Dry-run resurrector that logs but doesn't touch Docker."""
    return DryRunResurrector()


@pytest.fixture
def live_engine(outcome_store):
    """Live decision engine with auto-approve enabled."""
    config = DecisionConfig(
        auto_approve_enabled=True,
        auto_approve_min_confidence=0.85,
    )
    return LiveDecisionEngine(config, outcome_store=outcome_store)


@pytest.fixture
def observer_engine(outcome_store):
    """Observer decision engine."""
    config = DecisionConfig()
    return ObserverDecisionEngine(config, outcome_store=outcome_store)


def make_kill_report(
    target_module: str = "test-service",
    kill_reason: KillReason = KillReason.ANOMALY_BEHAVIOR,
    severity: Severity = Severity.LOW,
    confidence_score: float = 0.3,
    kill_id: str = None,
) -> KillReport:
    """Helper to create kill reports with sensible defaults."""
    return KillReport(
        kill_id=kill_id or str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        target_module=target_module,
        target_instance_id="inst-001",
        kill_reason=kill_reason,
        severity=severity,
        confidence_score=confidence_score,
        evidence=["test_evidence"],
        dependencies=[],
        source_agent="smith-test",
    )


def seed_outcomes(
    store: InMemoryOutcomeStore,
    count: int = 60,
    success_rate: float = 0.96,
    auto_approved: bool = True,
    module: str = "test-service",
) -> None:
    """Seed outcome store with historical data."""
    success_count = int(count * success_rate)
    for i in range(count):
        store.store_outcome(ResurrectionOutcome(
            outcome_id=str(uuid.uuid4()),
            decision_id=str(uuid.uuid4()),
            kill_id=f"seed-{i}",
            target_module=module,
            timestamp=datetime.now(timezone.utc) - timedelta(days=i % 30),
            outcome_type=OutcomeType.SUCCESS if i < success_count else OutcomeType.FAILURE,
            original_risk_score=0.2,
            original_confidence=0.9,
            original_decision="approve_auto" if auto_approved else "pending_review",
            was_auto_approved=auto_approved,
            feedback_source=FeedbackSource.AUTOMATED,
        ))
