"""
Medic Agent Learning Module

Outcome tracking for resurrection decisions.
"""

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

__all__ = [
    "OutcomeStore",
    "SQLiteOutcomeStore",
    "InMemoryOutcomeStore",
    "ResurrectionOutcome",
    "OutcomeType",
    "FeedbackSource",
    "OutcomeStatistics",
    "create_outcome_store",
]
