# Medic Agent

**Autonomous Resilience Layer for Smith Kill Events**

Medic Agent listens for kill reports from Smith (a security agent), evaluates whether the kill was a false positive, and resurrects containers when safe to do so. It learns from past decisions to improve over time.

## Current Version

**v0.2.0-alpha** — Post-reboot. Core loop works end-to-end with real Docker, SIEM integration, outcome-driven calibration, and a monitoring API.

## How It Works

```
Smith kill report → Redis Stream → Medic Agent
                                      │
                            ┌─────────┼─────────┐
                            ▼         ▼         ▼
                         Enrich    Assess     Check
                         (SIEM)    (Risk)    (History)
                            │         │         │
                            └─────────┼─────────┘
                                      ▼
                                   Decide
                              ┌───────┼───────┐
                              ▼       ▼       ▼
                           Approve  Pending  Deny
                              │       │
                              ▼       ▼
                           Restart  Queue for
                          Container  Review
                              │
                              ▼
                         Record Outcome
                         (SQLite → calibrate)
```

## Quick Start

### Prerequisites

- Python 3.11+
- Redis (for Smith event bus)
- Docker (for container resurrection)

### Install and Run

```bash
pip install -r requirements.txt

# Observer mode with mock listener (no Redis needed)
python main.py --mock

# Live mode with Redis
python main.py --mode live

# Custom config file
python main.py --config path/to/config.yaml
```

The API starts automatically on port 8000.

### Docker Compose

```bash
docker compose up -d
```

This starts the agent in observer mode alongside Redis. Edit `docker-compose.yaml` environment variables to change the mode.

### Configuration

Edit `config/medic.yaml`:

```yaml
mode: "observer"  # observer | live

smith:
  event_bus:
    type: "redis"    # redis | mock
    host: "localhost"
    port: 6379

siem:
  enabled: false     # Set true for Boundary-SIEM integration
  base_url: "http://localhost:8080"

decision:
  auto_approve:
    enabled: false   # Set true to auto-resurrect low-risk kills
    min_confidence: 0.85

resurrection:
  executor: "docker" # docker | mock
```

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | Status, mode, uptime, version |
| `GET /decisions/recent` | Last 20 decisions with full metadata |
| `GET /stats` | Aggregated outcome statistics |
| `POST /approve/{kill_id}` | Manually approve a pending resurrection |

```bash
curl http://localhost:8000/health
curl http://localhost:8000/stats
curl http://localhost:8000/decisions/recent
curl -X POST http://localhost:8000/approve/kill-123
```

## Operating Modes

| Mode | What Happens |
|---|---|
| **Observer** | Classifies decisions, logs everything, never acts |
| **Live** | Makes real decisions; auto-approve requires `decision.auto_approve.enabled: true` |

## Risk Assessment

Five weighted factors produce a 0.0-1.0 risk score:

| Factor | Weight | Source |
|---|---|---|
| Smith confidence | 0.30 | Kill report |
| SIEM risk score | 0.25 | Boundary-SIEM query |
| False positive history | 0.20 | SIEM + outcome store |
| Module criticality | 0.15 | Config list |
| Severity | 0.10 | Kill report |

**Outcome-driven calibration**: On startup, the engine reviews past auto-approve accuracy. If >95% were successful, it relaxes the confidence threshold. If <80%, it tightens it.

## Project Structure

```
medic-agent/
├── main.py                 # Entry point: listen → decide → act → record
├── api.py                  # FastAPI app (4 endpoints)
├── core/
│   ├── listener.py         # Redis Streams + mock listener
│   ├── decision.py         # Decision engine (observer/live modes, inline risk scoring)
│   ├── risk.py             # AdvancedRiskAssessor (standalone, richer analysis)
│   ├── siem.py             # Boundary-SIEM HTTP client
│   ├── resurrector.py      # Docker SDK container restart + dry-run
│   ├── models.py           # KillReport, SIEMResult, Decision, etc.
│   ├── validation.py       # Input validation
│   ├── errors.py           # Custom exceptions
│   └── logger.py           # Structured logging
├── learning/
│   └── outcome_store.py    # SQLite + in-memory outcome persistence
├── tests/
│   ├── conftest.py         # Shared fixtures
│   ├── test_end_to_end.py  # Full pipeline tests
│   ├── test_risk_scoring.py # Risk math + calibration tests
│   ├── test_outcome_store.py # SQLite + InMemory round-trip
│   └── test_api.py         # API endpoint tests
├── config/
│   └── medic.yaml          # Main configuration
├── Dockerfile              # Multi-stage build (Python 3.11-slim)
├── docker-compose.yaml     # Dev environment (agent + Redis)
├── pyproject.toml          # Project metadata, dependencies, tool config
└── requirements.txt        # Pinned dependency versions
```

## Testing

```bash
# Run all tests (34 tests)
pytest tests/ -v

# Run specific test files
pytest tests/test_end_to_end.py -v      # Pipeline tests
pytest tests/test_risk_scoring.py -v    # Risk + calibration
pytest tests/test_outcome_store.py -v   # Storage round-trip
pytest tests/test_api.py -v             # API endpoints
```

## Environment Variables

| Variable | Description |
|---|---|
| `MEDIC_MODE` | Override operating mode |
| `MEDIC_CONFIG_PATH` | Custom config file path |
| `SIEM_USERNAME` | Boundary-SIEM username |
| `SIEM_PASSWORD` | Boundary-SIEM password |

## License

MIT. See [LICENSE.md](LICENSE.md).

## Connected Repositories

| Repository | Description |
|---|---|
| [Agent-OS](https://github.com/kase1111-hash/Agent-OS) | Natural-language native operating system for AI agents |
| [Boundary-SIEM](https://github.com/kase1111-hash/Boundary-SIEM) | Security Information and Event Management for AI agents |
| [boundary-daemon](https://github.com/kase1111-hash/boundary-daemon-) | Trust enforcement layer defining cognition boundaries |
