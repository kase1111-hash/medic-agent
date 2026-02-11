# Claude.md - Medic Agent

## Project Overview

Medic Agent is an autonomous resilience layer that monitors kill events from Smith (a security agent), evaluates resurrection risk using SIEM data and historical outcomes, and restarts containers when safe. It learns from past decisions to calibrate its thresholds over time.

**Version**: v0.2.0-alpha (post-reboot)
**Language**: Python 3.11+
**Key deps**: FastAPI, Redis, Docker SDK, structlog, httpx

## Architecture

The system is a single async loop:

```
Redis Stream → Listener → Decision Engine → Resurrector → Outcome Store
                              ↑                                 │
                              │    calibrate() on startup       │
                              └─────────────────────────────────┘
```

A FastAPI server runs alongside the loop on port 8000.

## Project Structure

```
medic-agent/
├── main.py                 # Entry point: async loop + API server
├── api.py                  # FastAPI (GET /health, /decisions/recent, /stats; POST /approve/{kill_id})
├── core/
│   ├── listener.py         # RedisSmithListener + MockSmithListener
│   ├── decision.py         # _BaseDecisionEngine → ObserverDecisionEngine / LiveDecisionEngine
│   ├── risk.py             # AdvancedRiskAssessor (standalone, not wired into decision engine)
│   ├── siem.py             # BoundarySIEMClient + NoopSIEMClient
│   ├── resurrector.py      # DockerResurrector + DryRunResurrector
│   ├── models.py           # KillReport, SIEMResult, ResurrectionDecision, enums
│   ├── validation.py       # Input validation (module names, scores, evidence)
│   ├── errors.py           # MedicError hierarchy
│   └── logger.py           # structlog configuration
├── learning/
│   └── outcome_store.py    # SQLiteOutcomeStore + InMemoryOutcomeStore
├── tests/
│   ├── conftest.py         # Fixtures: make_kill_report(), seed_outcomes()
│   ├── test_end_to_end.py  # Full pipeline: resurrection + denial + observer
│   ├── test_risk_scoring.py # Risk math, SIEM effects, calibration
│   ├── test_outcome_store.py # SQLite + InMemory round-trip
│   └── test_api.py         # All 4 API endpoints
├── config/
│   └── medic.yaml          # Main configuration
└── pyproject.toml          # Project metadata + pytest config
```

## Key Types

- `KillReport` — inbound event from Smith (kill_id, target_module, kill_reason, severity, confidence_score)
- `SIEMResult` — enrichment from Boundary-SIEM (risk_score, false_positive_history, recommendation)
- `ResurrectionDecision` — engine output (outcome, risk_score, confidence, reasoning)
- `DecisionOutcome` — enum: APPROVE_AUTO, APPROVE_MANUAL, PENDING_REVIEW, DENY, DEFER
- `ResurrectionOutcome` — stored result (outcome_type, was_auto_approved, health_score_after)

## Decision Engine

`core/decision.py` contains the main logic:

- `_BaseDecisionEngine` — shared risk assessment, confidence calculation, calibration
- `ObserverDecisionEngine` — classifies but never triggers actions
- `LiveDecisionEngine` — returns actionable decisions; auto-approve requires config flag
- `calibrate()` — adjusts `auto_approve_min_confidence` based on historical accuracy
- `_get_module_history()` — queries outcome store for per-module false positive counts

Risk is computed from 5 weighted factors (smith_confidence, siem_risk, false_positive_history, module_criticality, severity). The FP factor merges SIEM data with outcome store history.

## Development Commands

```bash
# Run with mock listener (no Redis)
python main.py --mock

# Run with Redis in live mode
python main.py --mode live

# Run tests (34 tests)
pytest tests/ -v

# Run specific test file
pytest tests/test_end_to_end.py -v
```

## Configuration

`config/medic.yaml` — key sections:

- `mode`: "observer" or "live"
- `smith.event_bus`: Redis connection or "mock" type
- `siem`: Boundary-SIEM connection (enabled: false by default)
- `decision.auto_approve`: enabled flag + min_confidence threshold
- `risk.weights`: factor weights (smith_confidence, siem_risk_score, etc.)
- `resurrection.executor`: "docker" or "mock"

Environment overrides: `MEDIC_MODE`, `MEDIC_CONFIG_PATH`

## Code Style

- structlog for all logging (JSON or text format)
- dataclasses for models (not Pydantic)
- async/await for I/O (listener, API server)
- Synchronous for decision logic, risk assessment, outcome store
- No type: ignore, no broad except, no mutable default args

## Testing

pytest with `asyncio_mode = "auto"` (pyproject.toml). Tests use:
- `InMemoryOutcomeStore` — no SQLite needed for most tests
- `DryRunResurrector` — logs but doesn't touch Docker
- `_FakeListener` / `_LowRiskSIEM` — test-only stubs in test files
- `make_kill_report()` / `seed_outcomes()` — helpers in conftest.py
