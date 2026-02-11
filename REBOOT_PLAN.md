# Medic Agent Reboot Plan

## Guiding Principle

Build from the core outward. Prove each layer works end-to-end with real infrastructure before adding the next. Every line of code must participate in a working system — no mocks, no stubs, no "future phase" placeholders.

---

## Phase 0: Gut the Repo

**Goal:** Remove all non-functional code. What remains must compile, run, and do something real.

### DELETE — Entire directories

| Path | Reason |
|------|--------|
| `integration/` | Smith negotiation, veto protocol, edge case manager, self-monitor, cluster manager — all mocks with no real counterpart |
| `interfaces/` | Web dashboard, CLI, approval queue, auth — UI for a system that doesn't work |
| `kubernetes/` | Production deployment manifests for pre-alpha code |
| `deploy/` | Prometheus/Grafana configs — premature observability |
| `docs/` | Architecture docs describe a system that doesn't exist; rewrite after reboot |
| `tests/` | Tests validate mocks; rewrite against real behavior |

### DELETE — Individual files

| File | Reason |
|------|------|
| `execution/monitor.py` | Post-resurrection monitoring against mock health checks |
| `execution/auto_resurrect.py` | Auto-resurrection manager for mock resurrections |
| `execution/recommendation.py` | Generates recommendations nobody reads |
| `learning/pattern_analyzer.py` | Analyzes an empty database |
| `learning/threshold_adapter.py` | Adapts thresholds with no data |
| `learning/feedback.py` | Collects feedback on events that didn't happen |
| `core/event_bus.py` | Internal pub/sub with no subscribers |
| `core/metrics.py` | Prometheus metrics for phantom activity |
| `core/reporting.py` | Reports on nothing |
| `core/siem_interface.py` | SIEM adapter that falls back to mock — rebuild in Phase 2 |
| `config/constitution.yaml` | 7-phase toggle system; replace with a single config boolean |
| `main.py` | 1,185-line orchestrator for 26 optional components — rewrite from scratch |
| `execution/resurrector.py` | Mock executor with 90% random health checks — rewrite from scratch |

### KEEP — Salvageable modules (with cleanup)

| File | What's good | What to fix |
|------|------------|-------------|
| `core/models.py` | Data models are well-typed with proper validation. `KillReport`, `ResurrectionDecision`, `OutcomeRecord` are all sound. | Remove `ThreatIndicator` and `SIEMContextResponse` for now — they depend on a SIEM that doesn't exist. Add a simpler `SIEMResult` placeholder dataclass with just `risk_score: float` and `recommendation: str` until Phase 2 wires in a real SIEM. |
| `core/validation.py` | Input sanitization is solid. Path traversal prevention, length limits, pattern matching all work. | Remove the constant-time `hmac.compare_digest` comparison for confidence scores (lines 317-331) — this is not a timing-attack surface. A simple `0.0 <= score <= 1.0` check suffices. |
| `core/errors.py` | Custom exception hierarchy. | Keep as-is. |
| `core/logger.py` | Structured JSON logging with trace context and context manager. Production-quality. | Keep as-is. |
| `core/risk.py` | `AdvancedRiskAssessor` has sound multi-factor scoring with configurable weights. | Wire `history_provider` to the outcome store so `_get_module_history()` returns real incident counts instead of always defaulting to `{"incident_count_30d": 0}`. |
| `core/decision.py` | `ObserverDecisionEngine` correctly evaluates risk and classifies decisions. | Add a `LiveDecisionEngine` subclass that actually returns actionable outcomes (not just observer-mode classification). It should call through to the resurrector when `outcome == APPROVE_AUTO`. |
| `core/listener.py` | `SmithEventListener` does real Redis Streams integration — `xreadgroup`, `xack`, consumer groups. `MockSmithListener` is useful for dev. | Keep both. The Redis listener is the one piece of real infrastructure integration in the entire codebase. |
| `learning/outcome_store.py` | `SQLiteOutcomeStore` has proper schema, indices, parameterized queries, retry logic, and thread-safe connections. | Keep as-is. Wire it into the main loop so outcomes are actually recorded. |

### SIMPLIFY — Config and infrastructure

**`config/medic.yaml`** — Strip to essentials:

```yaml
version: "1.0"

mode: "observer"  # observer | live

smith:
  event_bus:
    type: "redis"  # redis | mock
    host: "localhost"
    port: 6379
    topic: "smith.events.kill_notifications"
    consumer_group: "medic-agent"

decision:
  confidence_threshold: 0.7
  auto_approve:
    enabled: false
    min_confidence: 0.85

risk:
  weights:
    smith_confidence: 0.30
    siem_risk_score: 0.25
    false_positive_history: 0.20
    module_criticality: 0.15
    severity: 0.10

resurrection:
  executor: "docker"  # docker | kubernetes | mock
  health_check_interval_seconds: 10
  health_check_timeout_seconds: 60
  max_retry_attempts: 2

learning:
  database:
    type: "sqlite"
    path: "data/outcomes.db"

logging:
  level: "INFO"
  format: "text"
```

**`requirements.txt`** — Strip to what's actually used:

```
# Core
pyyaml>=6.0.1
redis>=5.0.0

# HTTP (for SIEM integration in Phase 2)
httpx>=0.25.0

# Logging
structlog>=23.2.0

# Testing
pytest>=7.4.0
pytest-asyncio>=0.21.0

# Docker SDK (NEW — for real resurrection)
docker>=7.0.0
```

**`docker-compose.yaml`** — Two services only:

```yaml
services:
  medic-agent:
    build: .
    ports:
      - "8000:8000"
    environment:
      - MEDIC_CONFIG_PATH=/app/config/medic.yaml
      - MEDIC_MODE=observer
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
    depends_on:
      redis:
        condition: service_healthy

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
```

### File tree after Phase 0

```
medic-agent/
├── core/
│   ├── __init__.py
│   ├── models.py          (trimmed)
│   ├── validation.py      (simplified)
│   ├── errors.py          (as-is)
│   ├── logger.py          (as-is)
│   ├── risk.py            (wired to outcome store)
│   ├── decision.py        (add LiveDecisionEngine)
│   └── listener.py        (as-is)
├── execution/
│   ├── __init__.py
│   └── resurrector.py     (NEW — real Docker integration)
├── learning/
│   ├── __init__.py
│   └── outcome_store.py   (as-is)
├── config/
│   └── medic.yaml         (stripped to ~40 lines)
├── tests/
│   ├── test_end_to_end.py (NEW)
│   └── test_decision.py   (NEW)
├── main.py                (NEW — ~200 lines)
├── requirements.txt       (stripped)
├── docker-compose.yaml    (stripped)
├── Dockerfile             (simplified)
└── README.md              (rewritten)
```

---

## Phase 1: The 200-Line Main Loop

**Goal:** A working `main.py` that does the one thing this project claims to do.

### What it does

```
1. Load config
2. Connect to Redis
3. Initialize decision engine, risk assessor, outcome store
4. Loop:
   a. Receive kill report from Redis Stream
   b. Assess risk
   c. Make resurrection decision
   d. If approved: execute resurrection via Docker SDK
   e. Record outcome in SQLite
   f. Acknowledge message
   g. Log everything
```

### `main.py` structure

```python
async def main():
    config = load_config()
    listener = create_listener(config)
    decision_engine = create_decision_engine(config)
    resurrector = create_resurrector(config)
    outcome_store = create_outcome_store(config)

    await listener.connect()

    async for kill_report in listener.listen():
        # 1. Assess risk and decide
        decision = decision_engine.should_resurrect(kill_report, siem_context=None)

        # 2. Execute if approved
        result = None
        if decision.outcome == DecisionOutcome.APPROVE_AUTO:
            result = await resurrector.resurrect(kill_report)

        # 3. Record outcome
        outcome = build_outcome(decision, result)
        outcome_store.store_outcome(outcome)

        # 4. Acknowledge
        await listener.acknowledge(kill_report.kill_id)
```

### Key design decisions

- **No SIEM in Phase 1.** Pass `siem_context=None` to the decision engine. Risk assessment uses Smith confidence + severity + historical outcomes only. SIEM enrichment comes in Phase 2.
- **No observer mode split.** The decision engine returns a real `DecisionOutcome`. If config says `auto_approve: false`, everything goes to `PENDING_REVIEW` and gets logged but not executed. If `auto_approve: true`, low-risk reports get resurrected.
- **Synchronous processing.** One kill report at a time. No async queues, no worker pools, no parallelism. Get it right before making it fast.
- **Outcome recording on every decision.** Even observer-mode decisions get recorded with `outcome_type=UNDETERMINED`. This populates the database for future learning.

---

## Phase 2: Real Resurrector

**Goal:** Replace the mock executor with actual Docker container management.

### `execution/resurrector.py` — New implementation

```python
import docker

class DockerResurrector:
    def __init__(self, config):
        self.client = docker.from_env()

    async def resurrect(self, kill_report: KillReport) -> ResurrectionResult:
        container_name = kill_report.target_module
        try:
            container = self.client.containers.get(container_name)
            container.restart(timeout=30)
            # Wait for health check
            healthy = await self._wait_for_healthy(container, timeout=60)
            return ResurrectionResult(
                success=healthy,
                container_id=container.id,
                action="restart",
            )
        except docker.errors.NotFound:
            return ResurrectionResult(success=False, error="Container not found")

    async def _wait_for_healthy(self, container, timeout=60):
        # Poll container health status
        ...

    async def rollback(self, container_id: str):
        container = self.client.containers.get(container_id)
        container.stop(timeout=10)
```

### What this enables

- **Real `docker restart`** on the target container
- **Real health check polling** via Docker's health status API
- **Real rollback** — stop the container if post-restart health fails
- **Outcome recording with real data** — `time_to_healthy` is actual seconds, `health_score_after` is real

### Test it

```bash
# Start a test container
docker run -d --name test-module --health-cmd "curl -f http://localhost/ || exit 1" nginx

# Publish a kill report to Redis
redis-cli XADD smith.events.kill_notifications '*' payload '{"kill_id":"test-1","timestamp":"2026-02-11T00:00:00Z","target_module":"test-module","target_instance_id":"test-1","kill_reason":"anomaly_behavior","severity":"medium","confidence_score":0.5,"evidence":[],"dependencies":[],"source_agent":"smith-test"}'

# Watch medic-agent restart it and record the outcome
docker logs medic-agent
```

---

## Phase 3: SIEM Integration

**Goal:** Enrich kill reports with real threat intelligence before making decisions.

### What to build

1. **`core/siem.py`** — A simple HTTP client that queries one SIEM endpoint
2. Restore `SIEMContextResponse` and `ThreatIndicator` to `core/models.py`
3. Wire into the main loop between "receive kill report" and "assess risk"

### Pick one SIEM to start

Target **Elasticsearch/OpenSearch** — most common, well-documented API, can be self-hosted for dev:

```python
class ElasticsearchSIEM:
    def __init__(self, endpoint: str, api_key: str):
        self.client = httpx.AsyncClient(base_url=endpoint, headers={"Authorization": f"ApiKey {api_key}"})

    async def query_context(self, kill_report: KillReport) -> SIEMContextResponse:
        # Query for threat indicators matching the module
        response = await self.client.post("/_search", json={
            "query": {"bool": {"must": [
                {"match": {"module": kill_report.target_module}},
                {"range": {"timestamp": {"gte": "now-24h"}}}
            ]}}
        })
        # Parse response into SIEMContextResponse
        ...
```

### Updated main loop

```python
async for kill_report in listener.listen():
    siem_context = await siem.query_context(kill_report)  # NEW
    decision = decision_engine.should_resurrect(kill_report, siem_context)
    ...
```

### Add to docker-compose

```yaml
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
```

---

## Phase 4: Outcome-Driven Risk Calibration

**Goal:** The outcome store now has real data. Use it to improve risk scoring.

### What to build

1. **Wire `outcome_store` as `history_provider` to `AdvancedRiskAssessor`** — so `_get_module_history()` returns real incident counts from SQLite instead of defaulting to 0
2. **Add a simple `calibrate()` method** to `AdvancedRiskAssessor` — queries outcomes, computes success rates by risk score bucket, and adjusts `auto_approve_max_score` if the data supports it
3. **Run calibration on startup and daily** — not a background thread, just a function call

### What this looks like

```python
class AdvancedRiskAssessor:
    def calibrate(self, outcome_store: OutcomeStore):
        stats = outcome_store.get_statistics(since=thirty_days_ago)
        if stats.total_outcomes < 50:
            return  # Not enough data

        # If auto-approved resurrections have >95% success rate,
        # consider raising the auto-approve threshold
        if stats.auto_approve_accuracy > 0.95:
            self.thresholds.auto_approve_max_score = min(
                self.thresholds.auto_approve_max_score + 0.05, 0.5
            )
```

### No separate pattern_analyzer or threshold_adapter

One method on the risk assessor. No new files. No new abstractions. If it grows beyond 50 lines, then split it out.

---

## Phase 5: Minimal API

**Goal:** A small FastAPI app for monitoring and manual approval — only after the core loop works.

### What to build

One file: `api.py` (~100 lines)

```
GET  /health              → {"status": "ok", "mode": "observer", "uptime": ...}
GET  /decisions/recent    → last 20 decisions from outcome_store
GET  /stats               → outcome_store.get_statistics()
POST /approve/{kill_id}   → manually approve a pending resurrection
```

No dashboard. No WebSocket. No RBAC. No rate limiting. Just four endpoints that return JSON from the existing outcome store.

### Add to main.py

```python
import uvicorn
from api import app

# Run API in background
asyncio.create_task(uvicorn.Server(uvicorn.Config(app, port=8000)).serve())
```

---

## Phase 6: Tests That Prove It Works

**Goal:** Integration tests with real Redis and real Docker containers.

### Test 1: End-to-end resurrection

```python
async def test_end_to_end_resurrection():
    # 1. Start a test container
    # 2. Publish a kill report to Redis
    # 3. Wait for medic-agent to process it
    # 4. Assert container was restarted
    # 5. Assert outcome was recorded in SQLite
    # 6. Assert outcome_type == SUCCESS
```

### Test 2: High-risk denial

```python
async def test_high_risk_denial():
    # 1. Publish a kill report with confidence_score=0.99, severity=critical
    # 2. Assert decision.outcome == DENY
    # 3. Assert container was NOT restarted
    # 4. Assert outcome recorded with original_decision == "deny"
```

### Test 3: Risk scoring accuracy

```python
def test_risk_scoring():
    # Unit test: given specific KillReport + SIEMContext inputs,
    # assert expected risk_score and risk_level outputs
```

### Test 4: Outcome recording

```python
def test_outcome_store_round_trip():
    # Store an outcome, retrieve it, assert fields match
```

### Run with docker-compose

```bash
docker compose up -d redis
pytest tests/ -v
```

---

## What NOT to Build (Ever, Unless Explicitly Needed)

| Feature | Reason |
|---------|--------|
| Multi-cluster leader election | Solve single-cluster first |
| Smith negotiation protocol | Define as API contract doc, not code |
| Veto protocol | Same — protocol spec, not agent feature |
| Edge case manager | Handle the normal case first |
| 7-phase toggle system | One boolean: `auto_approve: true/false` |
| Web dashboard | `GET /stats` is your dashboard |
| CLI interface | `curl localhost:8000/stats` is your CLI |
| Pattern analyzer | A `calibrate()` method is enough |
| Threshold adapter | Same method |
| Approval queue | `POST /approve/{kill_id}` is your queue |
| Grafana/Prometheus | `docker logs` until you have real traffic |
| Kubernetes manifests | Docker Compose until you have real users |

---

## Success Criteria

The reboot is done when you can run this demo:

```bash
# Terminal 1: Start the system
docker compose up

# Terminal 2: Simulate Smith killing a module
redis-cli XADD smith.events.kill_notifications '*' \
  payload '{"kill_id":"demo-1","timestamp":"2026-02-11T12:00:00Z","target_module":"nginx-test","target_instance_id":"inst-001","kill_reason":"anomaly_behavior","severity":"low","confidence_score":0.4,"evidence":["unusual_traffic"],"dependencies":[],"source_agent":"smith"}'

# Terminal 3: Verify
# 1. Container was restarted
docker inspect nginx-test --format '{{.State.StartedAt}}'

# 2. Outcome was recorded
sqlite3 data/outcomes.db "SELECT outcome_type, original_risk_score, time_to_healthy FROM outcomes ORDER BY timestamp DESC LIMIT 1"

# 3. Decision was logged
docker logs medic-agent | grep "demo-1"

# 4. API shows the decision
curl localhost:8000/decisions/recent | python -m json.tool
```

When all four of those commands return real data from a real kill-report-to-resurrection cycle, the reboot is complete.

---

## Implementation Order

```
Phase 0 (Day 1)      → Delete dead code, simplify config, clean file tree
Phase 1 (Day 1-2)    → New main.py — working listen→decide→log loop
Phase 2 (Day 2-3)    → Real DockerResurrector — listen→decide→restart→record loop
Phase 3 (Day 4-5)    → SIEM integration — enrich decisions with threat data
Phase 4 (Day 5)      → Wire outcome_store into risk assessor for calibration
Phase 5 (Day 6)      → Minimal 4-endpoint API
Phase 6 (Day 6)      → Integration tests with real Redis + Docker
```

Each phase ships a working system. No phase depends on a future phase to function. If you stop after Phase 2, you have a useful tool. Everything after Phase 2 makes it smarter.
