# Medic Agent

**Autonomous Resilience Layer for Smith Kill Events**

Medic Agent is an intelligent system that monitors kill events from Smith, evaluates their legitimacy through SIEM integration, and orchestrates resurrection workflows with adaptive learning capabilities.

## Features

- **Kill Report Monitoring**: Real-time subscription to Smith's kill notification feed
- **SIEM Integration**: Contextual threat intelligence queries for informed decision-making
- **Multi-Mode Operation**: Observer, Manual, Semi-Auto, and Full-Auto modes
- **Risk Assessment**: Advanced risk scoring with configurable thresholds
- **Resurrection Workflow**: Automated execution with monitoring and rollback
- **Adaptive Learning**: Outcome tracking and threshold adjustment
- **Smith Collaboration**: Veto protocol and negotiation support
- **Production Ready**: Prometheus metrics, error handling, circuit breakers

## Current Version

**v0.1.0-alpha** - Initial alpha release with all core features implemented

[![Build Status](https://github.com/kase1111-hash/medic-agent/workflows/CI/badge.svg)](https://github.com/kase1111-hash/medic-agent/actions)
[![License](https://img.shields.io/badge/license-proprietary-red.svg)](LICENSE.md)

> **Note**: This is an alpha release. APIs and configurations may change.

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

## Architecture

```
Smith Kill Notification --> [Medic Listener]
                                 |
                                 v
                          [SIEM Query Adapter]
                                 |
                                 v
                     [Decision Logic Engine]
                                 |
              +------------------+-----------------+
              |                                    |
        [Human Review Interface]           [Auto Resurrection]
              |                                    |
              v                                    v
      [Manual Resurrection Flow]         [Auto Execution + Monitor]
              \__________________________/
                           |
                           v
                 [Outcome Logging + Learning]
```

## Project Structure

```
medic-agent/
├── core/                    # Core logic modules
│   ├── listener.py          # Smith event subscription
│   ├── siem_interface.py    # SIEM query adapter
│   ├── decision.py          # Decision engine
│   ├── risk.py              # Risk assessment
│   ├── errors.py            # Custom exceptions
│   ├── metrics.py           # Prometheus metrics
│   └── models.py            # Data models
├── execution/               # Resurrection execution
│   ├── resurrector.py       # Resurrection workflow
│   ├── monitor.py           # Post-resurrection monitoring
│   ├── recommendation.py    # Proposal generation
│   └── auto_resurrect.py    # Auto-resurrection logic
├── interfaces/              # User interfaces
│   ├── cli.py               # Command-line interface
│   ├── web.py               # REST API (FastAPI)
│   └── approval_queue.py    # Human approval queue
├── learning/                # Adaptive learning system
│   ├── outcome_store.py     # Outcome database
│   ├── pattern_analyzer.py  # Pattern detection
│   └── threshold_adapter.py # Threshold adjustment
├── integration/             # External integrations
│   ├── smith_negotiator.py  # Smith collaboration
│   ├── veto_protocol.py     # Veto handling
│   └── edge_case_manager.py # Edge case handling
├── config/                  # Configuration files
│   ├── medic.yaml           # Main configuration
│   └── constitution.yaml    # Phase toggles
├── tests/                   # Test suite
├── kubernetes/              # K8s manifests
├── deploy/                  # Deployment configs
└── main.py                  # Application entry point
```

## Operating Modes

| Mode | Description | Human Review |
|------|-------------|--------------|
| **Observer** | Log decisions without action | N/A |
| **Manual** | All resurrections require approval | Required |
| **Semi-Auto** | Auto-approve low-risk only | Medium/High risk |
| **Full-Auto** | Fully autonomous operation | Critical only |

## API Endpoints

When running with `--web`, the following endpoints are available:

- `GET /health` - Health check
- `GET /status` - System status
- `GET /api/v1/queue` - Pending approvals
- `POST /api/v1/queue/{id}/approve` - Approve resurrection
- `POST /api/v1/queue/{id}/deny` - Deny resurrection
- `GET /api/v1/decisions` - List decisions
- `GET /api/v1/resurrections` - List resurrections
- `GET /api/v1/metrics` - Prometheus metrics

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

### Before Deployment

1. **Create environment file** with secure credentials:
   ```bash
   cp .env.example .env
   # Edit .env with your SIEM_API_KEY and GRAFANA_PASSWORD
   ```

2. **Configure CORS origins** in `config/medic.yaml`:
   ```yaml
   interfaces:
     web:
       cors_origins:
         - "https://your-dashboard.example.com"
   ```

3. **Use external secrets** in Kubernetes (production):
   ```bash
   kubectl apply -k kubernetes/overlays/production/
   ```

See [CHANGELOG.md](CHANGELOG.md) for security notes and known limitations.

## Configuration Reference

See [docs/SPEC_SHEET.md](docs/SPEC_SHEET.md) for detailed configuration options and API specifications.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes and version history.

## License

This project is proprietary software. See [LICENSE.md](LICENSE.md).

## Support

For issues and feature requests, please use the GitHub issue tracker.
