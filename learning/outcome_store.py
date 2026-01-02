"""
Medic Agent Outcome Storage

Persistent storage for resurrection outcomes, enabling learning
from past decisions and pattern analysis.
"""

import json
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import threading

from core.logger import get_logger

logger = get_logger("learning.outcome_store")


class OutcomeType(Enum):
    """Types of resurrection outcomes."""
    SUCCESS = "success"           # Resurrection successful, module healthy
    PARTIAL_SUCCESS = "partial"   # Resurrection worked but with issues
    FAILURE = "failure"           # Resurrection failed
    ROLLBACK = "rollback"         # Had to rollback after resurrection
    FALSE_POSITIVE = "false_positive"  # Smith kill was incorrect
    TRUE_POSITIVE = "true_positive"    # Smith kill was correct
    UNDETERMINED = "undetermined"      # Outcome not yet known


class FeedbackSource(Enum):
    """Source of outcome feedback."""
    AUTOMATED = "automated"       # From monitoring system
    HUMAN_OPERATOR = "human"      # Human operator feedback
    SIEM_CORRELATION = "siem"     # Correlated from SIEM data
    ROLLBACK_TRIGGER = "rollback" # Inferred from rollback


@dataclass
class ResurrectionOutcome:
    """Record of a resurrection outcome for learning."""
    outcome_id: str
    decision_id: str
    kill_id: str
    target_module: str
    timestamp: datetime
    outcome_type: OutcomeType

    # Decision context
    original_risk_score: float
    original_confidence: float
    original_decision: str  # approve_auto, pending_review, deny
    was_auto_approved: bool

    # Outcome details
    health_score_after: Optional[float] = None
    time_to_healthy: Optional[float] = None  # seconds
    anomalies_detected: int = 0
    required_rollback: bool = False

    # Feedback
    feedback_source: FeedbackSource = FeedbackSource.AUTOMATED
    human_feedback: Optional[str] = None
    corrected_decision: Optional[str] = None

    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "outcome_id": self.outcome_id,
            "decision_id": self.decision_id,
            "kill_id": self.kill_id,
            "target_module": self.target_module,
            "timestamp": self.timestamp.isoformat(),
            "outcome_type": self.outcome_type.value,
            "original_risk_score": self.original_risk_score,
            "original_confidence": self.original_confidence,
            "original_decision": self.original_decision,
            "was_auto_approved": self.was_auto_approved,
            "health_score_after": self.health_score_after,
            "time_to_healthy": self.time_to_healthy,
            "anomalies_detected": self.anomalies_detected,
            "required_rollback": self.required_rollback,
            "feedback_source": self.feedback_source.value,
            "human_feedback": self.human_feedback,
            "corrected_decision": self.corrected_decision,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResurrectionOutcome":
        """Create from dictionary."""
        return cls(
            outcome_id=data["outcome_id"],
            decision_id=data["decision_id"],
            kill_id=data["kill_id"],
            target_module=data["target_module"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            outcome_type=OutcomeType(data["outcome_type"]),
            original_risk_score=data["original_risk_score"],
            original_confidence=data["original_confidence"],
            original_decision=data["original_decision"],
            was_auto_approved=data["was_auto_approved"],
            health_score_after=data.get("health_score_after"),
            time_to_healthy=data.get("time_to_healthy"),
            anomalies_detected=data.get("anomalies_detected", 0),
            required_rollback=data.get("required_rollback", False),
            feedback_source=FeedbackSource(data.get("feedback_source", "automated")),
            human_feedback=data.get("human_feedback"),
            corrected_decision=data.get("corrected_decision"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class OutcomeStatistics:
    """Aggregated statistics for outcomes."""
    total_outcomes: int
    success_count: int
    failure_count: int
    rollback_count: int
    false_positive_count: int
    true_positive_count: int

    avg_risk_score_success: float
    avg_risk_score_failure: float
    avg_time_to_healthy: float

    auto_approve_accuracy: float
    human_override_rate: float

    period_start: datetime
    period_end: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_outcomes": self.total_outcomes,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "rollback_count": self.rollback_count,
            "false_positive_count": self.false_positive_count,
            "true_positive_count": self.true_positive_count,
            "avg_risk_score_success": round(self.avg_risk_score_success, 3),
            "avg_risk_score_failure": round(self.avg_risk_score_failure, 3),
            "avg_time_to_healthy": round(self.avg_time_to_healthy, 1),
            "auto_approve_accuracy": round(self.auto_approve_accuracy, 3),
            "human_override_rate": round(self.human_override_rate, 3),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
        }


class OutcomeStore(ABC):
    """Abstract interface for outcome storage."""

    @abstractmethod
    def store_outcome(self, outcome: ResurrectionOutcome) -> None:
        """Store a resurrection outcome."""
        pass

    @abstractmethod
    def get_outcome(self, outcome_id: str) -> Optional[ResurrectionOutcome]:
        """Get an outcome by ID."""
        pass

    @abstractmethod
    def get_outcomes_by_module(
        self,
        module: str,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get outcomes for a specific module."""
        pass

    @abstractmethod
    def get_outcomes_by_type(
        self,
        outcome_type: OutcomeType,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get outcomes by type."""
        pass

    @abstractmethod
    def get_recent_outcomes(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get recent outcomes."""
        pass

    @abstractmethod
    def get_statistics(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> OutcomeStatistics:
        """Get aggregated statistics."""
        pass

    @abstractmethod
    def update_outcome(
        self,
        outcome_id: str,
        updates: Dict[str, Any],
    ) -> bool:
        """Update an existing outcome."""
        pass


class SQLiteOutcomeStore(OutcomeStore):
    """SQLite-based outcome storage."""

    def __init__(self, db_path: str = "data/outcomes.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()
        logger.info(f"SQLiteOutcomeStore initialized at {db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "connection"):
            self._local.connection = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    def _init_schema(self) -> None:
        """Initialize database schema."""
        conn = self._get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS outcomes (
                outcome_id TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL,
                kill_id TEXT NOT NULL,
                target_module TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                outcome_type TEXT NOT NULL,
                original_risk_score REAL NOT NULL,
                original_confidence REAL NOT NULL,
                original_decision TEXT NOT NULL,
                was_auto_approved INTEGER NOT NULL,
                health_score_after REAL,
                time_to_healthy REAL,
                anomalies_detected INTEGER DEFAULT 0,
                required_rollback INTEGER DEFAULT 0,
                feedback_source TEXT DEFAULT 'automated',
                human_feedback TEXT,
                corrected_decision TEXT,
                metadata TEXT DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_outcomes_module
                ON outcomes(target_module);
            CREATE INDEX IF NOT EXISTS idx_outcomes_type
                ON outcomes(outcome_type);
            CREATE INDEX IF NOT EXISTS idx_outcomes_timestamp
                ON outcomes(timestamp);
            CREATE INDEX IF NOT EXISTS idx_outcomes_decision
                ON outcomes(decision_id);
        """)
        conn.commit()

    def store_outcome(self, outcome: ResurrectionOutcome) -> None:
        """Store a resurrection outcome."""
        conn = self._get_connection()
        conn.execute(
            """
            INSERT OR REPLACE INTO outcomes (
                outcome_id, decision_id, kill_id, target_module, timestamp,
                outcome_type, original_risk_score, original_confidence,
                original_decision, was_auto_approved, health_score_after,
                time_to_healthy, anomalies_detected, required_rollback,
                feedback_source, human_feedback, corrected_decision, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                outcome.outcome_id,
                outcome.decision_id,
                outcome.kill_id,
                outcome.target_module,
                outcome.timestamp.isoformat(),
                outcome.outcome_type.value,
                outcome.original_risk_score,
                outcome.original_confidence,
                outcome.original_decision,
                1 if outcome.was_auto_approved else 0,
                outcome.health_score_after,
                outcome.time_to_healthy,
                outcome.anomalies_detected,
                1 if outcome.required_rollback else 0,
                outcome.feedback_source.value,
                outcome.human_feedback,
                outcome.corrected_decision,
                json.dumps(outcome.metadata),
            ),
        )
        conn.commit()
        logger.debug(f"Stored outcome: {outcome.outcome_id}")

    def get_outcome(self, outcome_id: str) -> Optional[ResurrectionOutcome]:
        """Get an outcome by ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM outcomes WHERE outcome_id = ?",
            (outcome_id,),
        ).fetchone()

        if row:
            return self._row_to_outcome(row)
        return None

    def get_outcomes_by_module(
        self,
        module: str,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get outcomes for a specific module."""
        conn = self._get_connection()

        if since:
            rows = conn.execute(
                """
                SELECT * FROM outcomes
                WHERE target_module = ? AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (module, since.isoformat(), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM outcomes
                WHERE target_module = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (module, limit),
            ).fetchall()

        return [self._row_to_outcome(row) for row in rows]

    def get_outcomes_by_type(
        self,
        outcome_type: OutcomeType,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get outcomes by type."""
        conn = self._get_connection()

        if since:
            rows = conn.execute(
                """
                SELECT * FROM outcomes
                WHERE outcome_type = ? AND timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (outcome_type.value, since.isoformat(), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM outcomes
                WHERE outcome_type = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (outcome_type.value, limit),
            ).fetchall()

        return [self._row_to_outcome(row) for row in rows]

    def get_recent_outcomes(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get recent outcomes."""
        conn = self._get_connection()

        if since:
            rows = conn.execute(
                """
                SELECT * FROM outcomes
                WHERE timestamp >= ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (since.isoformat(), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM outcomes
                ORDER BY timestamp DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [self._row_to_outcome(row) for row in rows]

    def get_statistics(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> OutcomeStatistics:
        """Get aggregated statistics."""
        conn = self._get_connection()

        # Build query with optional date range
        where_clauses = []
        params = []

        if since:
            where_clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if until:
            where_clauses.append("timestamp <= ?")
            params.append(until.isoformat())

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        # Get counts by type
        rows = conn.execute(
            f"""
            SELECT outcome_type, COUNT(*) as count
            FROM outcomes {where_sql}
            GROUP BY outcome_type
            """,
            params,
        ).fetchall()

        type_counts = {row["outcome_type"]: row["count"] for row in rows}

        # Get averages for success/failure
        success_stats = conn.execute(
            f"""
            SELECT AVG(original_risk_score) as avg_risk,
                   AVG(time_to_healthy) as avg_time
            FROM outcomes
            {where_sql + " AND " if where_sql else "WHERE "} outcome_type = 'success'
            """,
            params,
        ).fetchone()

        failure_stats = conn.execute(
            f"""
            SELECT AVG(original_risk_score) as avg_risk
            FROM outcomes
            {where_sql + " AND " if where_sql else "WHERE "} outcome_type IN ('failure', 'rollback')
            """,
            params,
        ).fetchone()

        # Get auto-approve accuracy
        auto_stats = conn.execute(
            f"""
            SELECT
                SUM(CASE WHEN was_auto_approved = 1 AND outcome_type = 'success' THEN 1 ELSE 0 END) as auto_success,
                SUM(CASE WHEN was_auto_approved = 1 THEN 1 ELSE 0 END) as auto_total,
                SUM(CASE WHEN corrected_decision IS NOT NULL THEN 1 ELSE 0 END) as overrides,
                COUNT(*) as total
            FROM outcomes {where_sql}
            """,
            params,
        ).fetchone()

        # Calculate date range
        date_range = conn.execute(
            f"""
            SELECT MIN(timestamp) as min_ts, MAX(timestamp) as max_ts
            FROM outcomes {where_sql}
            """,
            params,
        ).fetchone()

        period_start = datetime.fromisoformat(date_range["min_ts"]) if date_range["min_ts"] else datetime.utcnow()
        period_end = datetime.fromisoformat(date_range["max_ts"]) if date_range["max_ts"] else datetime.utcnow()

        total = sum(type_counts.values())

        return OutcomeStatistics(
            total_outcomes=total,
            success_count=type_counts.get("success", 0),
            failure_count=type_counts.get("failure", 0),
            rollback_count=type_counts.get("rollback", 0),
            false_positive_count=type_counts.get("false_positive", 0),
            true_positive_count=type_counts.get("true_positive", 0),
            avg_risk_score_success=success_stats["avg_risk"] or 0.0,
            avg_risk_score_failure=failure_stats["avg_risk"] or 0.0,
            avg_time_to_healthy=success_stats["avg_time"] or 0.0,
            auto_approve_accuracy=(
                auto_stats["auto_success"] / auto_stats["auto_total"]
                if auto_stats["auto_total"] > 0 else 0.0
            ),
            human_override_rate=(
                auto_stats["overrides"] / auto_stats["total"]
                if auto_stats["total"] > 0 else 0.0
            ),
            period_start=period_start,
            period_end=period_end,
        )

    def update_outcome(
        self,
        outcome_id: str,
        updates: Dict[str, Any],
    ) -> bool:
        """Update an existing outcome."""
        conn = self._get_connection()

        # Build SET clause
        allowed_fields = {
            "outcome_type", "health_score_after", "time_to_healthy",
            "anomalies_detected", "required_rollback", "feedback_source",
            "human_feedback", "corrected_decision", "metadata",
        }

        set_clauses = []
        params = []

        for field, value in updates.items():
            if field not in allowed_fields:
                continue

            if field == "outcome_type" and isinstance(value, OutcomeType):
                value = value.value
            elif field == "feedback_source" and isinstance(value, FeedbackSource):
                value = value.value
            elif field == "metadata" and isinstance(value, dict):
                value = json.dumps(value)
            elif field == "required_rollback":
                value = 1 if value else 0

            set_clauses.append(f"{field} = ?")
            params.append(value)

        if not set_clauses:
            return False

        params.append(outcome_id)

        result = conn.execute(
            f"UPDATE outcomes SET {', '.join(set_clauses)} WHERE outcome_id = ?",
            params,
        )
        conn.commit()

        return result.rowcount > 0

    def _row_to_outcome(self, row: sqlite3.Row) -> ResurrectionOutcome:
        """Convert database row to ResurrectionOutcome."""
        return ResurrectionOutcome(
            outcome_id=row["outcome_id"],
            decision_id=row["decision_id"],
            kill_id=row["kill_id"],
            target_module=row["target_module"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            outcome_type=OutcomeType(row["outcome_type"]),
            original_risk_score=row["original_risk_score"],
            original_confidence=row["original_confidence"],
            original_decision=row["original_decision"],
            was_auto_approved=bool(row["was_auto_approved"]),
            health_score_after=row["health_score_after"],
            time_to_healthy=row["time_to_healthy"],
            anomalies_detected=row["anomalies_detected"],
            required_rollback=bool(row["required_rollback"]),
            feedback_source=FeedbackSource(row["feedback_source"]),
            human_feedback=row["human_feedback"],
            corrected_decision=row["corrected_decision"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    def get_module_statistics(self, module: str) -> Dict[str, Any]:
        """Get statistics for a specific module."""
        conn = self._get_connection()

        stats = conn.execute(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN outcome_type = 'success' THEN 1 ELSE 0 END) as success,
                SUM(CASE WHEN outcome_type IN ('failure', 'rollback') THEN 1 ELSE 0 END) as failure,
                AVG(original_risk_score) as avg_risk,
                AVG(time_to_healthy) as avg_recovery_time
            FROM outcomes
            WHERE target_module = ?
            """,
            (module,),
        ).fetchone()

        return {
            "module": module,
            "total_resurrections": stats["total"],
            "success_count": stats["success"],
            "failure_count": stats["failure"],
            "success_rate": stats["success"] / stats["total"] if stats["total"] > 0 else 0.0,
            "avg_risk_score": stats["avg_risk"] or 0.0,
            "avg_recovery_time": stats["avg_recovery_time"] or 0.0,
        }

    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, "connection"):
            self._local.connection.close()


class InMemoryOutcomeStore(OutcomeStore):
    """In-memory outcome storage for testing."""

    def __init__(self):
        self._outcomes: Dict[str, ResurrectionOutcome] = {}
        logger.info("InMemoryOutcomeStore initialized")

    def store_outcome(self, outcome: ResurrectionOutcome) -> None:
        """Store a resurrection outcome."""
        self._outcomes[outcome.outcome_id] = outcome

    def get_outcome(self, outcome_id: str) -> Optional[ResurrectionOutcome]:
        """Get an outcome by ID."""
        return self._outcomes.get(outcome_id)

    def get_outcomes_by_module(
        self,
        module: str,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get outcomes for a specific module."""
        outcomes = [
            o for o in self._outcomes.values()
            if o.target_module == module
            and (since is None or o.timestamp >= since)
        ]
        outcomes.sort(key=lambda o: o.timestamp, reverse=True)
        return outcomes[:limit]

    def get_outcomes_by_type(
        self,
        outcome_type: OutcomeType,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get outcomes by type."""
        outcomes = [
            o for o in self._outcomes.values()
            if o.outcome_type == outcome_type
            and (since is None or o.timestamp >= since)
        ]
        outcomes.sort(key=lambda o: o.timestamp, reverse=True)
        return outcomes[:limit]

    def get_recent_outcomes(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[ResurrectionOutcome]:
        """Get recent outcomes."""
        outcomes = [
            o for o in self._outcomes.values()
            if since is None or o.timestamp >= since
        ]
        outcomes.sort(key=lambda o: o.timestamp, reverse=True)
        return outcomes[:limit]

    def get_statistics(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> OutcomeStatistics:
        """Get aggregated statistics."""
        outcomes = [
            o for o in self._outcomes.values()
            if (since is None or o.timestamp >= since)
            and (until is None or o.timestamp <= until)
        ]

        if not outcomes:
            now = datetime.utcnow()
            return OutcomeStatistics(
                total_outcomes=0,
                success_count=0,
                failure_count=0,
                rollback_count=0,
                false_positive_count=0,
                true_positive_count=0,
                avg_risk_score_success=0.0,
                avg_risk_score_failure=0.0,
                avg_time_to_healthy=0.0,
                auto_approve_accuracy=0.0,
                human_override_rate=0.0,
                period_start=since or now,
                period_end=until or now,
            )

        success = [o for o in outcomes if o.outcome_type == OutcomeType.SUCCESS]
        failures = [o for o in outcomes if o.outcome_type in (OutcomeType.FAILURE, OutcomeType.ROLLBACK)]
        auto_approved = [o for o in outcomes if o.was_auto_approved]
        auto_success = [o for o in auto_approved if o.outcome_type == OutcomeType.SUCCESS]
        overrides = [o for o in outcomes if o.corrected_decision]

        return OutcomeStatistics(
            total_outcomes=len(outcomes),
            success_count=len(success),
            failure_count=len([o for o in outcomes if o.outcome_type == OutcomeType.FAILURE]),
            rollback_count=len([o for o in outcomes if o.outcome_type == OutcomeType.ROLLBACK]),
            false_positive_count=len([o for o in outcomes if o.outcome_type == OutcomeType.FALSE_POSITIVE]),
            true_positive_count=len([o for o in outcomes if o.outcome_type == OutcomeType.TRUE_POSITIVE]),
            avg_risk_score_success=(
                sum(o.original_risk_score for o in success) / len(success)
                if success else 0.0
            ),
            avg_risk_score_failure=(
                sum(o.original_risk_score for o in failures) / len(failures)
                if failures else 0.0
            ),
            avg_time_to_healthy=(
                sum(o.time_to_healthy or 0 for o in success) / len(success)
                if success else 0.0
            ),
            auto_approve_accuracy=(
                len(auto_success) / len(auto_approved)
                if auto_approved else 0.0
            ),
            human_override_rate=(
                len(overrides) / len(outcomes)
                if outcomes else 0.0
            ),
            period_start=min(o.timestamp for o in outcomes),
            period_end=max(o.timestamp for o in outcomes),
        )

    def update_outcome(
        self,
        outcome_id: str,
        updates: Dict[str, Any],
    ) -> bool:
        """Update an existing outcome."""
        if outcome_id not in self._outcomes:
            return False

        outcome = self._outcomes[outcome_id]
        for field, value in updates.items():
            if hasattr(outcome, field):
                setattr(outcome, field, value)

        return True


def create_outcome_store(config: Dict[str, Any]) -> OutcomeStore:
    """Factory function to create outcome store."""
    learning_config = config.get("learning", {})
    db_config = learning_config.get("database", {})

    db_type = db_config.get("type", "sqlite")

    if db_type == "sqlite":
        db_path = db_config.get("path", "data/outcomes.db")
        return SQLiteOutcomeStore(db_path)
    elif db_type == "memory":
        return InMemoryOutcomeStore()
    else:
        logger.warning(f"Unknown database type: {db_type}, using in-memory")
        return InMemoryOutcomeStore()
