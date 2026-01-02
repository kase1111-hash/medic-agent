"""
Medic Agent Decision Logger

Persists decisions to disk for analysis and auditing.
Maintains both raw decision logs and structured storage.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import threading
from dataclasses import dataclass

from core.models import (
    KillReport,
    SIEMContextResponse,
    ResurrectionDecision,
    DecisionOutcome,
)
from core.logger import get_logger

logger = get_logger("core.log_decisions")


@dataclass
class DecisionRecord:
    """Complete record of a decision including all context."""

    decision: ResurrectionDecision
    kill_report: KillReport
    siem_context: SIEMContextResponse
    recorded_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "decision": self.decision.to_dict(),
            "kill_report": self.kill_report.to_dict(),
            "siem_context": self.siem_context.to_dict(),
            "recorded_at": self.recorded_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionRecord":
        """Create from dictionary."""
        from core.models import KillReport, SIEMContextResponse

        decision_data = data["decision"]
        decision = ResurrectionDecision(
            decision_id=decision_data["decision_id"],
            kill_id=decision_data["kill_id"],
            timestamp=datetime.fromisoformat(decision_data["timestamp"]),
            outcome=DecisionOutcome(decision_data["outcome"]),
            risk_level=decision_data["risk_level"],
            risk_score=decision_data["risk_score"],
            confidence=decision_data["confidence"],
            reasoning=decision_data["reasoning"],
            recommended_action=decision_data["recommended_action"],
            requires_human_review=decision_data["requires_human_review"],
            auto_approve_eligible=decision_data["auto_approve_eligible"],
            constraints=decision_data.get("constraints", []),
            timeout_minutes=decision_data.get("timeout_minutes", 60),
        )

        return cls(
            decision=decision,
            kill_report=KillReport.from_dict(data["kill_report"]),
            siem_context=SIEMContextResponse.from_dict(data["siem_context"]),
            recorded_at=datetime.fromisoformat(data["recorded_at"]),
        )


class DecisionLogger:
    """
    Logs decisions to disk for auditing and analysis.

    Provides both append-only log files and indexed storage
    for efficient querying.
    """

    def __init__(
        self,
        log_dir: str = "logs",
        data_dir: str = "data",
        max_records_per_file: int = 1000,
    ):
        self.log_dir = Path(log_dir)
        self.data_dir = Path(data_dir)
        self.max_records_per_file = max_records_per_file

        # Ensure directories exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # In-memory buffer for batch writes
        self._buffer: List[DecisionRecord] = []
        self._buffer_lock = threading.Lock()

        # Current file handles
        self._current_log_file: Optional[Path] = None
        self._current_record_count = 0

        logger.info(
            "Decision logger initialized",
            log_dir=str(self.log_dir),
            data_dir=str(self.data_dir),
        )

    def log_decision(
        self,
        decision: ResurrectionDecision,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> None:
        """
        Log a decision with full context.

        Args:
            decision: The resurrection decision
            kill_report: The original kill report
            siem_context: SIEM context used in decision
        """
        record = DecisionRecord(
            decision=decision,
            kill_report=kill_report,
            siem_context=siem_context,
            recorded_at=datetime.utcnow(),
        )

        # Write to log file immediately
        self._write_to_log(record)

        # Buffer for batch storage
        with self._buffer_lock:
            self._buffer.append(record)

            if len(self._buffer) >= 10:
                self._flush_buffer()

        logger.debug(
            "Decision logged",
            decision_id=decision.decision_id,
            outcome=decision.outcome.value,
        )

    def _write_to_log(self, record: DecisionRecord) -> None:
        """Write record to the current log file."""
        # Rotate log file if needed
        self._rotate_log_if_needed()

        log_line = json.dumps(record.to_dict()) + "\n"

        with open(self._current_log_file, "a") as f:
            f.write(log_line)

        self._current_record_count += 1

    def _rotate_log_if_needed(self) -> None:
        """Rotate to a new log file if the current one is full or it's a new day."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        expected_file = self.log_dir / f"decisions_{today}.jsonl"

        if (
            self._current_log_file != expected_file
            or self._current_record_count >= self.max_records_per_file
        ):
            if self._current_record_count >= self.max_records_per_file:
                # Add sequence number for multiple files per day
                seq = 1
                while expected_file.exists():
                    expected_file = self.log_dir / f"decisions_{today}_{seq:03d}.jsonl"
                    seq += 1

            self._current_log_file = expected_file
            self._current_record_count = 0

            if expected_file.exists():
                # Count existing records
                with open(expected_file, "r") as f:
                    self._current_record_count = sum(1 for _ in f)

            logger.debug(f"Using log file: {expected_file}")

    def _flush_buffer(self) -> None:
        """Flush buffered records to structured storage."""
        if not self._buffer:
            return

        # Save to daily JSON file
        today = datetime.utcnow().strftime("%Y-%m-%d")
        storage_file = self.data_dir / f"decisions_{today}.json"

        existing_records = []
        if storage_file.exists():
            try:
                with open(storage_file, "r") as f:
                    existing_records = json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Corrupted storage file: {storage_file}")
                existing_records = []

        existing_records.extend([r.to_dict() for r in self._buffer])

        with open(storage_file, "w") as f:
            json.dump(existing_records, f, indent=2)

        self._buffer.clear()

    def flush(self) -> None:
        """Force flush all buffered records."""
        with self._buffer_lock:
            self._flush_buffer()

    def get_decisions(
        self,
        date: Optional[datetime] = None,
        outcome: Optional[DecisionOutcome] = None,
        limit: int = 100,
    ) -> List[DecisionRecord]:
        """
        Retrieve logged decisions.

        Args:
            date: Filter by date (defaults to today)
            outcome: Filter by outcome type
            limit: Maximum records to return

        Returns:
            List of DecisionRecord objects
        """
        if date is None:
            date = datetime.utcnow()

        date_str = date.strftime("%Y-%m-%d")
        storage_file = self.data_dir / f"decisions_{date_str}.json"

        if not storage_file.exists():
            return []

        try:
            with open(storage_file, "r") as f:
                records_data = json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Failed to read storage file: {storage_file}")
            return []

        records = [DecisionRecord.from_dict(r) for r in records_data]

        if outcome:
            records = [r for r in records if r.decision.outcome == outcome]

        return records[:limit]

    def get_daily_summary(self, date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Get summary statistics for a day.

        Args:
            date: The date to summarize (defaults to today)

        Returns:
            Dictionary with summary statistics
        """
        if date is None:
            date = datetime.utcnow()

        records = self.get_decisions(date=date, limit=10000)

        if not records:
            return {
                "date": date.strftime("%Y-%m-%d"),
                "total_decisions": 0,
                "outcomes": {},
                "risk_levels": {},
                "avg_risk_score": 0.0,
                "avg_confidence": 0.0,
            }

        outcome_counts: Dict[str, int] = {}
        risk_level_counts: Dict[str, int] = {}
        total_risk = 0.0
        total_confidence = 0.0

        for record in records:
            # Count outcomes
            outcome = record.decision.outcome.value
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1

            # Count risk levels
            risk_level = record.decision.risk_level.value
            risk_level_counts[risk_level] = risk_level_counts.get(risk_level, 0) + 1

            # Sum scores
            total_risk += record.decision.risk_score
            total_confidence += record.decision.confidence

        total = len(records)

        return {
            "date": date.strftime("%Y-%m-%d"),
            "total_decisions": total,
            "outcomes": outcome_counts,
            "risk_levels": risk_level_counts,
            "avg_risk_score": round(total_risk / total, 3),
            "avg_confidence": round(total_confidence / total, 3),
            "modules_affected": list(set(r.kill_report.target_module for r in records)),
        }

    def get_module_history(
        self,
        module: str,
        days: int = 30,
    ) -> List[DecisionRecord]:
        """
        Get decision history for a specific module.

        Args:
            module: Module name to filter
            days: Number of days of history

        Returns:
            List of decisions for the module
        """
        from datetime import timedelta

        records = []
        today = datetime.utcnow()

        for i in range(days):
            date = today - timedelta(days=i)
            day_records = self.get_decisions(date=date, limit=10000)
            module_records = [
                r for r in day_records if r.kill_report.target_module == module
            ]
            records.extend(module_records)

        return records


class ObserverLogger(DecisionLogger):
    """
    Extended logger for observer mode.

    Adds specialized logging for what-if analysis and
    observer mode specific metrics.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observer_log = self.log_dir / "observer.log"

    def log_decision(
        self,
        decision: ResurrectionDecision,
        kill_report: KillReport,
        siem_context: SIEMContextResponse,
    ) -> None:
        """Log decision with observer mode annotations."""
        super().log_decision(decision, kill_report, siem_context)

        # Write human-readable observer log
        self._write_observer_log(decision, kill_report)

    def _write_observer_log(
        self,
        decision: ResurrectionDecision,
        kill_report: KillReport,
    ) -> None:
        """Write human-readable log entry."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        # Determine what would have happened
        if decision.outcome == DecisionOutcome.APPROVE_AUTO:
            would_have = "WOULD HAVE AUTO-RESURRECTED"
        elif decision.outcome == DecisionOutcome.DENY:
            would_have = "WOULD HAVE DENIED"
        elif decision.outcome == DecisionOutcome.PENDING_REVIEW:
            would_have = "WOULD HAVE QUEUED FOR REVIEW"
        else:
            would_have = f"WOULD HAVE: {decision.outcome.value}"

        log_entry = (
            f"[{timestamp}] {would_have}\n"
            f"  Kill ID: {kill_report.kill_id}\n"
            f"  Module: {kill_report.target_module}\n"
            f"  Reason: {kill_report.kill_reason.value}\n"
            f"  Risk: {decision.risk_level.value} ({decision.risk_score:.2f})\n"
            f"  Confidence: {decision.confidence:.0%}\n"
            f"  Reasoning: {decision.reasoning[0] if decision.reasoning else 'N/A'}\n"
            f"\n"
        )

        with open(self.observer_log, "a") as f:
            f.write(log_entry)


def create_decision_logger(config: Dict[str, Any]) -> DecisionLogger:
    """
    Factory function to create the appropriate decision logger.

    Args:
        config: Configuration dictionary

    Returns:
        Configured DecisionLogger instance
    """
    log_config = config.get("logging", {})
    mode = config.get("mode", {}).get("current", "observer")

    log_dir = "logs"
    for output in log_config.get("outputs", []):
        if output.get("type") == "file":
            log_dir = str(Path(output.get("path", "logs")).parent)
            break

    data_dir = config.get("learning", {}).get("database", {}).get("path", "data")
    if data_dir.endswith(".db"):
        data_dir = str(Path(data_dir).parent)

    if mode == "observer":
        return ObserverLogger(log_dir=log_dir, data_dir=data_dir)

    return DecisionLogger(log_dir=log_dir, data_dir=data_dir)
