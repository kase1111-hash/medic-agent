# Medic Agent

**Autonomous Resilience Layer for Smith Kill Events**

Medic Agent is an **autonomous security agent** and **self-healing AI system** that monitors kill events from Smith, evaluates their legitimacy through **AI security monitoring** and SIEM integration, and orchestrates resurrection workflows with **adaptive learning** capabilities. As a core component of the **Agent-OS ecosystem**, it provides **cognitive security monitoring** and **agent health monitoring** for distributed AI agent deployments.

Built for **digital sovereignty** and **owned AI infrastructure**, Medic Agent enables teams to maintain full control over their **AI agent security** and **threat detection** workflows.

## Features

### Core Capabilities
- **Kill Report Monitoring**: Real-time subscription to Smith's kill notification feed with **security event management**
- **SIEM Integration**: Contextual **AI threat detection** and threat intelligence queries for informed decision-making
- **Multi-Mode Operation**: Observer, Manual, Semi-Auto, and Full-Auto modes for **controlled AI learning**
- **Risk Assessment**: Advanced risk scoring with configurable thresholds and weights using **cognitive work accounting**
- **Resurrection Workflow**: Automated execution with **agent health monitoring** and rollback capabilities
- **Adaptive Learning**: **Pattern analysis**, outcome tracking, and **threshold adjustment** for continuous improvement

### Advanced Features
- **Smith Collaboration**: Bidirectional **AI negotiation** and veto protocol support with **trust enforcement**
- **Edge Case Detection**: Rapid kills, cascading failures, and flapping module detection using **semantic matching**
- **Self-Monitoring**: **Cognitive firewall** with agent health monitoring and auto-remediation
- **Multi-Cluster Support**: Distributed deployments with leader election for **multi-agent operating system** environments

### Production Ready
- **REST API**: Complete FastAPI-based REST API with OpenAPI documentation for **language-native architecture**
- **WebSocket Support**: Real-time event streaming for dashboards and **AI security audit logs**
- **Web Dashboard**: Built-in monitoring dashboard with live updates and **process legibility**
- **Prometheus Metrics**: Full **observability** with metrics export for **SIEM for AI systems**
- **Security**: API key authentication, RBAC, rate limiting, security headers, and **AI permission system**

## Current Version

**v0.1.0-alpha** - Initial alpha release with all core features implemented

[![Build Status](https://github.com/kase1111-hash/medic-agent/workflows/CI/badge.svg)](https://github.com/kase1111-hash/medic-agent/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)

## Quick Start

### Prerequisites

- Python 3.11+
- Redis (for event bus)
- Docker (optional, for containerized deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/kase1111-hash/medic-agent.git
cd medic-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Copy and customize the configuration files:

```bash
cp config/medic.yaml.example config/medic.yaml
cp config/constitution.yaml.example config/constitution.yaml
```

Key configuration options in `config/medic.yaml`:

```yaml
mode:
  current: "observer"  # observer | manual | semi_auto | full_auto

smith:
  event_bus:
    host: "localhost"
    port: 6379

siem:
  endpoint: "http://localhost:8080/siem"

interfaces:
  web:
    enabled: true
    port: 8000
```

### Running

```bash
# Start in observer mode (default)
python main.py

# Start in specific mode
python main.py --mode manual
python main.py --mode semi_auto
python main.py --mode full_auto

# Enable web interface
python main.py --web --port 8000

# Show version
python main.py --version
```

### Accessing the Dashboard

When the web interface is enabled, access:

- **Dashboard**: http://localhost:8000/dashboard
- **API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | Complete REST API documentation |
| [Configuration Guide](docs/CONFIGURATION.md) | Configuration options and examples |
| [Architecture](docs/ARCHITECTURE.md) | System architecture and design patterns |
| [Specification Sheet](docs/SPEC_SHEET.md) | Technical specifications and data models |
| [Security Policy](SECURITY.md) | Security guidelines and vulnerability reporting |

## Architecture

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
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐  │
│  │   Interfaces    │  │   Integration   │  │      Learning           │  │
│  │  - REST API     │  │  - Smith Veto   │  │  - Outcome Store        │  │
│  │  - WebSocket    │  │  - Negotiation  │  │  - Pattern Analysis     │  │
│  │  - Dashboard    │  │  - Edge Cases   │  │  - Threshold Adapter    │  │
│  │  - CLI          │  │  - Self-Monitor │  │  - Feedback System      │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                          Core Engine                             │    │
│  │  Listener → Decision → Risk Assessment → Resurrection → Monitor │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
medic-agent/
├── core/                    # Core logic modules
│   ├── listener.py          # Smith event subscription
│   ├── siem_interface.py    # SIEM query adapter
│   ├── decision.py          # Decision engine
│   ├── risk.py              # Risk assessment
│   ├── event_bus.py         # Internal event pub/sub
│   ├── errors.py            # Custom exceptions
│   ├── metrics.py           # Prometheus metrics
│   ├── validation.py        # Input validation
│   └── models.py            # Data models
├── execution/               # Resurrection execution
│   ├── resurrector.py       # Resurrection workflow
│   ├── monitor.py           # Post-resurrection monitoring
│   ├── recommendation.py    # Proposal generation
│   └── auto_resurrect.py    # Auto-resurrection logic
├── interfaces/              # User interfaces
│   ├── web.py               # REST API (FastAPI)
│   ├── dashboard.py         # Web dashboard UI
│   ├── auth.py              # Authentication & RBAC
│   ├── cli.py               # Command-line interface
│   └── approval_queue.py    # Human approval queue
├── learning/                # Adaptive learning system
│   ├── outcome_store.py     # Outcome database
│   ├── pattern_analyzer.py  # Pattern detection
│   ├── threshold_adapter.py # Threshold adjustment
│   └── feedback.py          # Feedback collection
├── integration/             # External integrations
│   ├── smith_negotiator.py  # Smith collaboration
│   ├── veto_protocol.py     # Veto handling
│   ├── edge_case_manager.py # Edge case handling
│   ├── self_monitor.py      # Agent health monitoring
│   └── cluster_manager.py   # Multi-cluster support
├── config/                  # Configuration files
│   ├── medic.yaml           # Main configuration
│   ├── constitution.yaml    # Phase toggles & constraints
│   └── medic.production.yaml # Production template
├── tests/                   # Test suite
│   ├── unit/                # Unit tests
│   ├── integration/         # Integration tests
│   ├── security/            # Security tests
│   └── performance/         # Performance tests
├── kubernetes/              # K8s manifests
├── deploy/                  # Deployment configs
├── docs/                    # Documentation
└── main.py                  # Application entry point
```

## Operating Modes

| Mode | Description | Human Review | Auto-Resurrect |
|------|-------------|--------------|----------------|
| **Observer** | Log decisions without action | N/A | No |
| **Manual** | All resurrections require approval | Required | No |
| **Semi-Auto** | Auto-approve low-risk only | Medium/High risk | Low-risk |
| **Full-Auto** | Fully autonomous operation | Critical only | Yes |

## API Endpoints

When the web interface is enabled, the following endpoints are available:

### Health & Status
- `GET /health` - Health check (no auth required)
- `GET /status` - System status

### Queue Management
- `GET /api/v1/queue` - List pending approvals
- `GET /api/v1/queue/{id}` - Get queue item
- `POST /api/v1/queue/{id}/approve` - Approve resurrection
- `POST /api/v1/queue/{id}/deny` - Deny resurrection

### Decisions & Resurrections
- `GET /api/v1/decisions` - List decisions
- `GET /api/v1/resurrections` - List resurrections
- `POST /api/v1/resurrections/{id}/rollback` - Trigger rollback

### Outcomes & Feedback
- `GET /api/v1/outcomes` - List outcomes
- `GET /api/v1/outcomes/stats` - Outcome statistics
- `POST /api/v1/feedback` - Submit feedback

### Configuration & Reports
- `GET /api/v1/config` - Current configuration
- `GET /api/v1/config/thresholds` - Risk thresholds
- `GET /api/v1/reports/daily` - Daily report
- `GET /api/v1/reports/weekly` - Weekly report

### Monitoring & Metrics
- `GET /api/v1/monitors` - Active monitoring sessions
- `GET /api/v1/metrics` - Prometheus metrics

### WebSocket
- `WS /ws` - Real-time event stream

See [API Reference](docs/API.md) for complete documentation.

## Docker Deployment

```bash
# Build image
docker build -t medic-agent:latest .

# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f medic-agent
```

## Kubernetes Deployment

```bash
# Apply manifests
kubectl apply -k kubernetes/

# Check status
kubectl -n medic-agent get pods

# View logs
kubectl -n medic-agent logs -f deployment/medic-agent
```

For production deployment:

```bash
kubectl apply -k kubernetes/overlays/production/
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test categories
pytest tests/unit/ -v          # Unit tests
pytest tests/integration/ -v   # Integration tests
pytest tests/security/ -v      # Security tests
pytest tests/performance/ -v   # Performance tests

# Run fast tests only (skip slow/performance)
pytest -m "not slow and not performance"
```

## Security

### Environment Variables

Required environment variables for production:

```bash
export SIEM_API_KEY="your-siem-api-key"
export MEDIC_ADMIN_API_KEY="your-admin-api-key"
export MEDIC_OPERATOR_API_KEY="your-operator-api-key"
export MEDIC_VIEWER_API_KEY="your-viewer-api-key"
```

### CORS Configuration

Configure allowed origins in `config/medic.yaml`:

```yaml
interfaces:
  web:
    cors_origins:
      - "https://your-dashboard.example.com"
      - "https://admin.example.com"
```

### Security Features

- API key authentication with SHA-256 hashing
- Role-based access control (Admin, Operator, Viewer, API)
- Rate limiting (120 requests/minute)
- Request size limiting (10MB max)
- Security headers (CSP, HSTS, X-Frame-Options)
- Input validation and sanitization
- Constant-time comparison for auth tokens

See [Configuration Guide](docs/CONFIGURATION.md) for security configuration details.

## Monitoring

### Prometheus Metrics

Metrics are exported on port 9090:

| Metric | Type | Description |
|--------|------|-------------|
| `medic_kills_received_total` | Counter | Kill reports received |
| `medic_decisions_total` | Counter | Decisions by outcome |
| `medic_resurrections_total` | Counter | Resurrections attempted |
| `medic_resurrection_duration_seconds` | Histogram | Resurrection duration |
| `medic_errors_total` | Counter | Errors by category |
| `medic_queue_size` | Gauge | Approval queue size |

### Grafana Dashboard

A pre-configured Grafana dashboard is included in `deploy/grafana/`.

## Configuration Reference

See [Configuration Guide](docs/CONFIGURATION.md) for detailed configuration options.

Key configuration files:
- `config/medic.yaml` - Main configuration
- `config/constitution.yaml` - Phase feature toggles and safety constraints
- `config/medic.production.yaml` - Production template

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes and version history.

## License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.

## Support

For issues and feature requests, please use the GitHub issue tracker.

---

## Connected Repositories

Medic Agent is part of a larger ecosystem of AI agent infrastructure and natural language computing projects.

### 🤖 Agent-OS Ecosystem

| Repository | Description |
|------------|-------------|
| [Agent-OS](https://github.com/kase1111-hash/Agent-OS) | Natural-language native operating system for AI agents (NLOS) |
| [synth-mind](https://github.com/kase1111-hash/synth-mind) | NLOS-based agent with psychological modules for emergent continuity and empathy |
| [boundary-daemon](https://github.com/kase1111-hash/boundary-daemon-) | Mandatory trust enforcement layer defining cognition boundaries |
| [memory-vault](https://github.com/kase1111-hash/memory-vault) | Secure, offline-capable, owner-sovereign storage for cognitive artifacts |
| [value-ledger](https://github.com/kase1111-hash/value-ledger) | Economic accounting layer for cognitive work (ideas, effort, novelty) |
| [learning-contracts](https://github.com/kase1111-hash/learning-contracts) | Safety protocols for AI learning and data management |

### 🛡️ Security Infrastructure

| Repository | Description |
|------------|-------------|
| [Boundary-SIEM](https://github.com/kase1111-hash/Boundary-SIEM) | Security Information and Event Management system for AI agents |

### 🔗 NatLangChain Ecosystem

| Repository | Description |
|------------|-------------|
| [NatLangChain](https://github.com/kase1111-hash/NatLangChain) | Prose-first, intent-native blockchain protocol for human intent in natural language |
| [IntentLog](https://github.com/kase1111-hash/IntentLog) | Git for human reasoning - tracks "why" changes happen via prose commits |
| [RRA-Module](https://github.com/kase1111-hash/RRA-Module) | Revenant Repo Agent - converts abandoned repos into autonomous licensing agents |
| [mediator-node](https://github.com/kase1111-hash/mediator-node) | LLM mediation layer for matching, negotiation, and closure proposals |
| [ILR-module](https://github.com/kase1111-hash/ILR-module) | IP & Licensing Reconciliation for dispute resolution |
| [Finite-Intent-Executor](https://github.com/kase1111-hash/Finite-Intent-Executor) | Posthumous execution of predefined intent (Solidity smart contract) |

### 🎮 Game Development

| Repository | Description |
|------------|-------------|
| [Shredsquatch](https://github.com/kase1111-hash/Shredsquatch) | 3D first-person snowboarding infinite runner (SkiFree homage) |
| [Midnight-pulse](https://github.com/kase1111-hash/Midnight-pulse) | Procedurally generated night drive |
| [Long-Home](https://github.com/kase1111-hash/Long-Home) | Godot narrative game project |
