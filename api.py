"""
Medic Agent API — Minimal monitoring and manual approval endpoints.

Four endpoints, no dashboard, no auth. Returns JSON from the outcome store.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException

from core.logger import get_logger
from learning.outcome_store import OutcomeStore, OutcomeType

logger = get_logger("medic.api")

app = FastAPI(title="Medic Agent", version="0.2.0-alpha")

# These get wired by main.py before the server starts
_outcome_store: Optional[OutcomeStore] = None
_decision_engine: Optional[Any] = None
_start_time: Optional[datetime] = None
_mode: str = "observer"


def configure(
    outcome_store: OutcomeStore,
    decision_engine: Any,
    mode: str,
) -> None:
    """Wire dependencies. Called once from main.py before serving."""
    global _outcome_store, _decision_engine, _start_time, _mode
    _outcome_store = outcome_store
    _decision_engine = decision_engine
    _start_time = datetime.now(timezone.utc)
    _mode = mode


@app.get("/health")
def health() -> Dict[str, Any]:
    """Basic health check with uptime."""
    uptime = 0.0
    if _start_time:
        uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()

    return {
        "status": "ok",
        "mode": _mode,
        "uptime_seconds": round(uptime, 1),
        "version": "0.2.0-alpha",
    }


@app.get("/decisions/recent")
def recent_decisions() -> Dict[str, Any]:
    """Last 20 decisions from the outcome store."""
    if not _outcome_store:
        raise HTTPException(status_code=503, detail="Outcome store not initialized")

    outcomes = _outcome_store.get_recent_outcomes(limit=20)
    return {
        "count": len(outcomes),
        "decisions": [o.to_dict() for o in outcomes],
    }


@app.get("/stats")
def stats() -> Dict[str, Any]:
    """Aggregated outcome statistics."""
    if not _outcome_store:
        raise HTTPException(status_code=503, detail="Outcome store not initialized")

    outcome_stats = _outcome_store.get_statistics()
    result = outcome_stats.to_dict()

    if _decision_engine:
        result["decision_engine"] = _decision_engine.get_statistics()

    return result


@app.post("/approve/{kill_id}")
def approve(kill_id: str) -> Dict[str, Any]:
    """Manually approve a pending resurrection."""
    if not _outcome_store:
        raise HTTPException(status_code=503, detail="Outcome store not initialized")

    # Find the outcome for this kill
    outcomes = _outcome_store.get_recent_outcomes(limit=500)
    match = None
    for o in outcomes:
        if o.kill_id == kill_id:
            match = o
            break

    if not match:
        raise HTTPException(status_code=404, detail=f"No outcome found for kill_id: {kill_id}")

    if match.outcome_type not in (OutcomeType.UNDETERMINED,):
        raise HTTPException(
            status_code=409,
            detail=f"Outcome already resolved: {match.outcome_type.value}",
        )

    updated = _outcome_store.update_outcome(
        match.outcome_id,
        {
            "corrected_decision": "approve_manual",
            "feedback_source": "human",
            "human_feedback": "Manually approved via API",
        },
    )

    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update outcome")

    logger.info(
        "Manual approval via API",
        kill_id=kill_id,
        outcome_id=match.outcome_id,
    )

    return {
        "status": "approved",
        "kill_id": kill_id,
        "outcome_id": match.outcome_id,
    }
