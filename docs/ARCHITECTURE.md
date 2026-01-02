# Medic Agent Architecture

Comprehensive architecture documentation for Medic Agent - an autonomous resilience layer for module resurrection management.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Module Structure](#module-structure)
- [Data Flow](#data-flow)
- [Phase-Based Evolution](#phase-based-evolution)
- [Design Patterns](#design-patterns)
- [Integration Points](#integration-points)
- [Deployment Architecture](#deployment-architecture)
- [Security Architecture](#security-architecture)

---

## Overview

Medic Agent is an autonomous resilience system that:

1. **Listens** to kill events from Smith (security agent)
2. **Queries** SIEM for contextual threat intelligence
3. **Decides** whether to resurrect killed modules
4. **Executes** resurrection workflows with monitoring
5. **Learns** from outcomes to improve decision accuracy

### Core Principles

- **Safety First**: Conservative defaults, human oversight for critical decisions
- **Gradual Autonomy**: Phase-based progression from observer to full-auto
- **Explainable Decisions**: All decisions include reasoning chains
- **Adaptive Learning**: Continuous improvement from outcome feedback

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              External Systems                            │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                  │
│  │    Smith    │    │    SIEM     │    │  Dashboard  │                  │
│  │ (Security)  │    │  (Intel)    │    │  (Users)    │                  │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                  │
└─────────┼──────────────────┼──────────────────┼─────────────────────────┘
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Medic Agent                                    │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                        INTERFACES LAYER                          │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │    │
│  │  │   CLI    │  │ Web API  │  │Dashboard │  │  Approval Queue  │ │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                   │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                        INTEGRATION LAYER                         │    │
│  │  ┌───────────────┐  ┌──────────────┐  ┌────────────────────┐   │    │
│  │  │Smith Negotiator│  │Veto Protocol │  │Edge Case Manager  │   │    │
│  │  └───────────────┘  └──────────────┘  └────────────────────┘   │    │
│  │  ┌───────────────┐  ┌──────────────────────────────────────┐   │    │
│  │  │ Self Monitor  │  │        Cluster Manager               │   │    │
│  │  └───────────────┘  └──────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                   │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                          CORE LAYER                              │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐  │    │
│  │  │ Listener │  │ Decision │  │   Risk   │  │ SIEM Interface │  │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────────────┘  │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐  │    │
│  │  │  Models  │  │ Event Bus│  │ Reporting│  │    Metrics     │  │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                   │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                       EXECUTION LAYER                            │    │
│  │  ┌──────────────┐  ┌──────────┐  ┌─────────────────────────┐   │    │
│  │  │ Resurrector  │  │ Monitor  │  │   Auto-Resurrect        │   │    │
│  │  └──────────────┘  └──────────┘  └─────────────────────────┘   │    │
│  │  ┌──────────────────────────────────────────────────────────┐  │    │
│  │  │                    Recommendation                         │  │    │
│  │  └──────────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                   │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                        LEARNING LAYER                            │    │
│  │  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────┐ │    │
│  │  │Outcome Store │  │ Pattern Analyzer │  │ Threshold Adapter │ │    │
│  │  └──────────────┘  └──────────────────┘  └───────────────────┘ │    │
│  │  ┌──────────────────────────────────────────────────────────┐  │    │
│  │  │                    Feedback System                        │  │    │
│  │  └──────────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

### Core Layer (`core/`)

The foundation of Medic Agent, containing essential business logic.

| Module | Purpose |
|--------|---------|
| `models.py` | Data models (KillReport, ResurrectionDecision, etc.) |
| `listener.py` | Smith event bus subscription |
| `siem_interface.py` | SIEM adapter for threat intelligence |
| `decision.py` | Decision engine with strategy pattern |
| `risk.py` | Risk assessment and scoring |
| `event_bus.py` | Internal event pub/sub system |
| `log_decisions.py` | Decision logging and audit trail |
| `reporting.py` | Report generation (daily/weekly) |
| `metrics.py` | Prometheus metrics exporter |
| `errors.py` | Custom exception hierarchy |
| `validation.py` | Input validation and sanitization |
| `logger.py` | Structured logging setup |

### Execution Layer (`execution/`)

Handles resurrection execution and monitoring.

| Module | Purpose |
|--------|---------|
| `resurrector.py` | Resurrection workflow execution |
| `monitor.py` | Post-resurrection health monitoring |
| `auto_resurrect.py` | Automatic resurrection controller |
| `recommendation.py` | Resurrection recommendations |

### Integration Layer (`integration/`)

External system integrations and advanced features.

| Module | Purpose |
|--------|---------|
| `smith_negotiator.py` | Bidirectional Smith communication |
| `veto_protocol.py` | Kill veto protocol with Smith |
| `edge_case_manager.py` | Edge case detection and handling |
| `self_monitor.py` | Agent self-health monitoring |
| `cluster_manager.py` | Multi-cluster coordination |

### Learning Layer (`learning/`)

Adaptive learning and feedback processing.

| Module | Purpose |
|--------|---------|
| `outcome_store.py` | Outcome storage and retrieval |
| `pattern_analyzer.py` | Outcome pattern analysis |
| `threshold_adapter.py` | Adaptive threshold adjustment |
| `feedback.py` | Feedback collection and processing |

### Interfaces Layer (`interfaces/`)

User and external system interfaces.

| Module | Purpose |
|--------|---------|
| `web.py` | FastAPI REST API |
| `dashboard.py` | Web dashboard UI |
| `cli.py` | Command-line interface |
| `approval_queue.py` | Human approval queue |
| `auth.py` | API authentication and RBAC |

---

## Data Flow

### Kill Report Processing

```
Smith Kill Event
       │
       ▼
┌──────────────┐
│   Listener   │ ── Parse & Validate ──▶ KillReport
└──────┬───────┘
       │
       ▼
┌──────────────┐
│SIEM Interface│ ── Query Context ──▶ SIEMContextResponse
└──────┬───────┘
       │
       ▼
┌──────────────┐
│Risk Assessor │ ── Calculate Risk ──▶ RiskLevel, RiskScore
└──────┬───────┘
       │
       ▼
┌──────────────┐
│Decision Engine│ ── Make Decision ──▶ ResurrectionDecision
└──────┬───────┘
       │
       ├──────────────────────────────────────┐
       │                                      │
       ▼                                      ▼
┌──────────────┐                    ┌──────────────┐
│ Auto-Approve │                    │Approval Queue│
│  (Low Risk)  │                    │(Medium/High) │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       │◀─────────── Human Approval ───────┘
       │
       ▼
┌──────────────┐
│ Resurrector  │ ── Execute ──▶ ResurrectionRequest
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Monitor    │ ── Watch Health ──▶ Anomalies
└──────┬───────┘
       │
       ├──────────────────────────────────────┐
       │                                      │
       ▼                                      ▼
┌──────────────┐                    ┌──────────────┐
│   Success    │                    │   Rollback   │
│  (Stable)    │                    │  (Anomaly)   │
└──────┬───────┘                    └──────────────┘
       │
       ▼
┌──────────────┐
│Outcome Store │ ── Record ──▶ OutcomeRecord
└──────┬───────┘
       │
       ▼
┌──────────────┐
│Pattern Analyzer│ ── Analyze ──▶ Insights
└──────┬───────┘
       │
       ▼
┌──────────────┐
│Threshold Adapter│ ── Adjust ──▶ Updated Thresholds
└──────────────┘
```

### Event Bus Flow

```
┌───────────────────────────────────────────────────────────────────┐
│                         Event Bus                                  │
├───────────────────────────────────────────────────────────────────┤
│                                                                    │
│  KILL_RECEIVED ──▶ Decision Engine                                │
│                                                                    │
│  DECISION_MADE ──▶ Approval Queue (if needs review)               │
│               ──▶ Auto-Resurrector (if auto-approved)             │
│               ──▶ WebSocket Clients                               │
│                                                                    │
│  RESURRECTION_STARTED ──▶ Monitor                                 │
│                       ──▶ WebSocket Clients                       │
│                                                                    │
│  RESURRECTION_COMPLETED ──▶ Outcome Store                         │
│                         ──▶ WebSocket Clients                     │
│                                                                    │
│  RESURRECTION_FAILED ──▶ Rollback Handler                         │
│                      ──▶ WebSocket Clients                        │
│                                                                    │
│  ANOMALY_DETECTED ──▶ Edge Case Manager                           │
│                   ──▶ Self Monitor                                │
│                                                                    │
│  THRESHOLD_UPDATED ──▶ Risk Assessor                              │
│                    ──▶ WebSocket Clients                          │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

---

## Phase-Based Evolution

Medic Agent is designed for gradual autonomy through phases:

### Phase 0: Foundation
- Kill report listener
- SIEM query adapter
- Structured logging

### Phase 1: Observer Mode
- Decision logic (no action)
- Decision logging
- Daily reports

### Phase 2: Manual Mode
- Recommendation engine
- Human interface (CLI)
- Resurrection executor
- Post-resurrection monitoring

### Phase 3: Semi-Autonomous
- Risk assessment engine
- Auto-resurrection (low-risk)
- Approval queue (medium/high-risk)
- Internal event bus

### Phase 4: Learning System
- Outcome database
- Pattern analysis
- Adaptive thresholds
- Feedback collection

### Phase 5: Full Autonomous
- Edge case detection
- Smith negotiation/veto
- Self-monitoring
- Advanced automation

### Phase 6: Production Ready
- Complete REST API
- Prometheus metrics
- Error handling
- Circuit breakers

### Phase 7: Deployment
- Docker containerization
- Kubernetes manifests
- CI/CD pipeline
- Multi-cluster support

---

## Design Patterns

### Strategy Pattern (Decision Algorithms)

```python
class DecisionStrategy(ABC):
    @abstractmethod
    def evaluate(self, kill_report, context) -> DecisionOutcome:
        pass

class ConservativeStrategy(DecisionStrategy):
    """Always require human review."""

class BalancedStrategy(DecisionStrategy):
    """Balance auto-approval with review."""

class AggressiveStrategy(DecisionStrategy):
    """Favor auto-approval for low-risk."""
```

### Repository Pattern (Data Access)

```python
class Repository(ABC, Generic[T, ID]):
    async def get(self, id: ID) -> Optional[T]
    async def get_all(self, filters: dict = None) -> List[T]
    async def add(self, entity: T) -> T
    async def update(self, entity: T) -> T
    async def delete(self, id: ID) -> bool
```

### Observer Pattern (Event Handling)

```python
class EventEmitter:
    def on(self, event_type: EventType, handler: Callable) -> None
    def emit(self, event_type: EventType, data: Any) -> None
```

### State Machine (Resurrection Workflow)

```
PENDING → APPROVED → EXECUTING → MONITORING → STABLE → COMPLETED
    ↓         ↓          ↓           ↓
  FAILED    FAILED    FAILED   ANOMALY_DETECTED
                                      ↓
                                ROLLING_BACK
                                      ↓
                                   FAILED
```

### Circuit Breaker (External Services)

```python
class CircuitBreaker:
    states: CLOSED → OPEN → HALF_OPEN → CLOSED
    failure_threshold: int
    recovery_timeout_seconds: int
```

### Pipeline Pattern (Processing Chain)

```python
class Pipeline:
    steps: List[PipelineStep]

    def execute(self, data: T) -> T:
        for step in steps:
            data = step.process(data)
            if not step.should_continue(data):
                break
        return data
```

---

## Integration Points

### Smith Integration

```
Medic Agent ◀──── Kill Notifications ──── Smith
Medic Agent ────▶ Veto Requests ────────▶ Smith
Medic Agent ◀──── Veto Responses ────── Smith
Medic Agent ────▶ Negotiation Requests ─▶ Smith
Medic Agent ◀──── Negotiation Responses ─ Smith
```

**Protocol**: Redis/RabbitMQ/Kafka pub/sub

### SIEM Integration

```
Medic Agent ────▶ Context Query ────────▶ SIEM
Medic Agent ◀──── Context Response ──── SIEM
Medic Agent ────▶ Outcome Report ───────▶ SIEM
```

**Protocol**: REST API with API key authentication

### Dashboard Integration

```
Dashboard ────▶ REST API ────────────────▶ Medic Agent
Dashboard ◀──── JSON Responses ────────── Medic Agent
Dashboard ◀──── WebSocket Events ──────── Medic Agent
```

**Protocol**: HTTP/WebSocket with Bearer token auth

---

## Deployment Architecture

### Single Instance

```
┌─────────────────────────────────────┐
│           Medic Agent               │
│  ┌─────────┐  ┌─────────────────┐  │
│  │ API:8000│  │ Metrics:9090    │  │
│  └─────────┘  └─────────────────┘  │
└─────────────────────────────────────┘
         │              │
         ▼              ▼
    ┌─────────┐   ┌───────────┐
    │  Redis  │   │Prometheus │
    └─────────┘   └───────────┘
```

### Multi-Cluster (HA)

```
┌─────────────────────────────────────────────────────────────────┐
│                      Cluster Store (Redis/etcd)                  │
└─────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Cluster A     │  │   Cluster B     │  │   Cluster C     │
│  (us-east-1)    │  │  (us-west-2)    │  │  (eu-west-1)    │
│                 │  │                 │  │                 │
│ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │
│ │Medic Agent 1│ │  │ │Medic Agent 3│ │  │ │Medic Agent 5│ │
│ │  (Leader)   │ │  │ │ (Follower)  │ │  │ │ (Follower)  │ │
│ └─────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │
│ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │
│ │Medic Agent 2│ │  │ │Medic Agent 4│ │  │ │Medic Agent 6│ │
│ │ (Follower)  │ │  │ │ (Follower)  │ │  │ │ (Follower)  │ │
│ └─────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Kubernetes Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Namespace: medic-agent                       │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │                                                           │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │            Deployment: medic-agent                   │ │   │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │ │   │
│  │  │  │  Pod 1   │  │  Pod 2   │  │  Pod 3   │          │ │   │
│  │  │  └──────────┘  └──────────┘  └──────────┘          │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │                           │                               │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │           Service: medic-agent-svc                   │ │   │
│  │  │            (ClusterIP: 8000, 9090)                   │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │    HorizontalPodAutoscaler (2-10 replicas)         │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │           ConfigMap + Secrets                        │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Authentication Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                      Security Layers                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Layer 1: Network Security                                       │
│  ├── TLS/HTTPS for all communications                           │
│  ├── Network policies in Kubernetes                             │
│  └── Firewall rules limiting access                             │
│                                                                  │
│  Layer 2: API Authentication                                     │
│  ├── Bearer token (API keys)                                    │
│  ├── SHA-256 hashed key storage                                 │
│  └── Constant-time comparison                                   │
│                                                                  │
│  Layer 3: Authorization (RBAC)                                   │
│  ├── Roles: Admin, Operator, Viewer, API                        │
│  ├── Permissions mapped to endpoints                            │
│  └── Audit logging for all actions                              │
│                                                                  │
│  Layer 4: Input Validation                                       │
│  ├── Path traversal prevention                                  │
│  ├── Null byte detection                                        │
│  ├── Character whitelisting                                     │
│  └── Request size limits                                        │
│                                                                  │
│  Layer 5: Security Headers                                       │
│  ├── X-Content-Type-Options: nosniff                            │
│  ├── X-Frame-Options: DENY                                      │
│  ├── Content-Security-Policy                                    │
│  └── Strict-Transport-Security (production)                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Secret Management

| Secret | Storage | Usage |
|--------|---------|-------|
| API Keys | Environment variables | API authentication |
| SIEM Key | Kubernetes Secret | SIEM authentication |
| Redis Password | Kubernetes Secret | Cluster store auth |
| TLS Certificates | ConfigMap/Secret | HTTPS/mTLS |

### Audit Trail

All security-relevant events are logged:

- Authentication attempts (success/failure)
- Authorization decisions
- Resurrection approvals/denials
- Configuration changes
- Threshold adjustments

---

## Directory Structure

```
medic-agent/
├── config/                    # Configuration files
│   ├── medic.yaml            # Main configuration
│   ├── constitution.yaml     # Feature toggles
│   └── medic.production.yaml # Production template
├── core/                      # Core business logic
│   ├── models.py             # Data models
│   ├── listener.py           # Event listener
│   ├── decision.py           # Decision engine
│   ├── risk.py               # Risk assessment
│   └── ...
├── execution/                 # Resurrection execution
│   ├── resurrector.py        # Workflow execution
│   ├── monitor.py            # Health monitoring
│   └── auto_resurrect.py     # Auto-resurrection
├── integration/               # External integrations
│   ├── smith_negotiator.py   # Smith communication
│   ├── veto_protocol.py      # Veto handling
│   └── cluster_manager.py    # Multi-cluster
├── learning/                  # Adaptive learning
│   ├── outcome_store.py      # Outcome storage
│   ├── pattern_analyzer.py   # Pattern analysis
│   └── threshold_adapter.py  # Threshold tuning
├── interfaces/                # User interfaces
│   ├── web.py                # REST API
│   ├── dashboard.py          # Web UI
│   └── auth.py               # Authentication
├── kubernetes/                # K8s manifests
│   ├── deployment.yaml
│   ├── service.yaml
│   └── kustomization.yaml
├── tests/                     # Test suite
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── performance/
├── docs/                      # Documentation
│   ├── API.md
│   ├── CONFIGURATION.md
│   ├── ARCHITECTURE.md
│   └── SPEC_SHEET.md
├── Dockerfile                 # Container build
├── docker-compose.yaml        # Local development
├── requirements.txt           # Python dependencies
└── main.py                    # Entry point
```

---

*Document Version: 1.0*
*Last Updated: 2026-01-02*
