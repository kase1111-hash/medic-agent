# Claude.md - Medic Agent

## Project Overview

Medic Agent is an autonomous resilience layer and self-healing AI system that monitors kill events from Smith (a security agent) and makes intelligent decisions about whether to resurrect terminated processes. It's part of the Agent-OS ecosystem.

**Version**: v0.1.0-alpha
**Language**: Python 3.11+
**Framework**: FastAPI with async/await patterns

## Key Concepts

- **Kill Reports**: Events from Smith indicating a process was terminated
- **SIEM Integration**: Queries external threat intelligence for context
- **Risk Assessment**: Multi-factor scoring (confidence, threats, history, criticality)
- **Resurrection**: Workflow to bring back terminated processes after evaluation
- **Operating Modes**: observer → manual → semi_auto → full_auto (progressive autonomy)

## Project Structure

```
medic-agent/
├── main.py              # Application entry point and MedicAgent orchestrator
├── core/                # Core business logic
│   ├── listener.py      # Smith event bus subscription (Redis Streams)
│   ├── decision.py      # Decision engine with strategy pattern
│   ├── risk.py          # Multi-factor risk assessment
│   ├── siem_interface.py # SIEM adapter for threat queries
│   ├── models.py        # Pydantic data models
│   ├── event_bus.py     # Internal async pub/sub
│   └── errors.py        # Custom exceptions + circuit breaker
├── execution/           # Resurrection execution
│   ├── resurrector.py   # Resurrection workflow
│   ├── monitor.py       # Post-resurrection health monitoring
│   └── auto_resurrect.py # Automatic resurrection controller
├── interfaces/          # User-facing interfaces
│   ├── web.py           # FastAPI REST API (OpenAPI docs at /docs)
│   ├── dashboard.py     # Web dashboard UI
│   ├── auth.py          # API key auth + RBAC
│   └── cli.py           # Command-line interface
├── learning/            # Adaptive learning system
│   ├── outcome_store.py # SQLite outcome persistence
│   ├── pattern_analyzer.py
│   └── threshold_adapter.py
├── integration/         # External system integrations
│   ├── smith_negotiator.py # Bidirectional Smith protocol
│   ├── edge_case_manager.py # Cascading/rapid/flapping detection
│   └── cluster_manager.py # Multi-cluster coordination
├── config/              # Configuration files
│   ├── medic.yaml       # Main configuration
│   └── constitution.yaml # Phase toggles and safety constraints
├── tests/               # Test suite
│   ├── unit/            # Unit tests
│   ├── integration/     # End-to-end tests
│   ├── security/        # Security tests
│   └── performance/     # Load tests
└── kubernetes/          # K8s manifests with Kustomize overlays
```

## Development Commands

```bash
# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run application
python main.py --mode observer    # Observer mode (default)
python main.py --mode manual      # Manual approval mode
python main.py --mode semi_auto   # Auto-approve low-risk
python main.py --mode full_auto   # Fully autonomous
python main.py --web --port 8000  # Enable web interface

# Run tests
pytest tests/ -v
pytest tests/unit/ -v              # Unit tests only
pytest tests/integration/ -v       # Integration tests
pytest tests/ --cov=core --cov=execution --cov=learning --cov-report=html

# Code quality
black .                            # Format code
isort .                            # Sort imports
mypy core/ execution/ learning/ integration/  # Type check
ruff check .                       # Lint
```

## Code Style

- **Formatter**: Black (88 char line length)
- **Import Sorter**: isort (black profile)
- **Type Checker**: mypy (strict mode, disallow_untyped_defs)
- **Linter**: ruff (E, W, F, I, B, C4, UP, S rules)

All code uses:
- Type hints throughout
- Pydantic models for data validation
- async/await for I/O operations
- structlog for JSON-formatted logging
- Prometheus metrics for observability

## Testing

Test markers available:
- `@pytest.mark.slow` - Long-running tests
- `@pytest.mark.integration` - End-to-end tests
- `@pytest.mark.security` - Security-focused tests
- `@pytest.mark.performance` - Load/throughput tests
- `@pytest.mark.edge_case` - Edge case scenarios

Test fixtures are in `tests/fixtures/` and `tests/conftest.py`.

## Key Data Models (core/models.py)

- `KillReport` - Event from Smith about a terminated process
- `DecisionOutcome` - Result of the decision engine (resurrect/defer/deny)
- `RiskAssessment` - Multi-factor risk score
- `ResurrectionResult` - Outcome of resurrection attempt

## Configuration

Main config is in `config/medic.yaml`. Key sections:
- `smith`: Connection settings for Smith event bus
- `siem`: SIEM integration settings
- `risk`: Risk thresholds and factor weights
- `modes`: Operating mode configurations
- `learning`: Adaptive learning parameters

Environment variables (see `.env.example`):
- `SIEM_API_KEY` - Required for SIEM integration
- `MEDIC_ADMIN_API_KEY`, `MEDIC_OPERATOR_API_KEY`, `MEDIC_VIEWER_API_KEY` - API auth
- `MEDIC_MODE` - Operating mode
- `MEDIC_LOG_LEVEL` - Logging verbosity

## API Endpoints

Base URL: `http://localhost:8000`

- `GET /health` - Health check
- `GET /api/v1/queue` - Get approval queue
- `POST /api/v1/queue/{id}/approve` - Approve resurrection
- `POST /api/v1/queue/{id}/deny` - Deny resurrection
- `GET /api/v1/decisions` - List decisions
- `GET /api/v1/metrics` - Prometheus metrics
- `WS /ws` - WebSocket for real-time events

Full API docs at `/docs` (OpenAPI/Swagger UI).

## Authentication

API uses key-based auth with three roles:
- **Admin**: Full access including configuration
- **Operator**: Approve/deny resurrections
- **Viewer**: Read-only access

Pass API key via `X-API-Key` header.

## Important Notes

1. **Operating Modes**: The system progresses through phases of autonomy. Start with `observer` mode for monitoring only.

2. **Risk Thresholds**: Default thresholds in `config/medic.yaml`:
   - Low risk: < 0.3
   - Medium risk: 0.3 - 0.7
   - High risk: > 0.7

3. **Circuit Breaker**: The system has circuit breaker patterns in `core/errors.py` to handle failures gracefully.

4. **Self-Monitoring**: `integration/self_monitor.py` monitors the agent's own health and can trigger auto-remediation.

5. **Learning System**: Stores outcomes in SQLite and adapts thresholds over time based on feedback.

## Documentation

- `README.md` - Project overview and quick start
- `docs/API.md` - Complete REST API reference
- `docs/ARCHITECTURE.md` - System design and patterns
- `docs/CONFIGURATION.md` - Configuration guide
- `docs/SPEC_SHEET.md` - Technical specifications
- `CONTRIBUTING.md` - Development guidelines
- `SECURITY.md` - Security policy
