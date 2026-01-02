# Medic Agent Configuration Guide

Complete guide to configuring Medic Agent for development and production environments.

## Table of Contents

- [Configuration Files](#configuration-files)
- [Operating Modes](#operating-modes)
- [Smith Integration](#smith-integration)
- [SIEM Integration](#siem-integration)
- [Decision Engine](#decision-engine)
- [Risk Assessment](#risk-assessment)
- [Resurrection Settings](#resurrection-settings)
- [Auto-Resurrection](#auto-resurrection)
- [Interfaces](#interfaces)
- [Learning System](#learning-system)
- [Edge Case Handling](#edge-case-handling)
- [Self-Monitoring](#self-monitoring)
- [Multi-Cluster](#multi-cluster)
- [Logging](#logging)
- [Metrics](#metrics)
- [Constitution](#constitution)
- [Environment Variables](#environment-variables)
- [Production Configuration](#production-configuration)

---

## Configuration Files

Medic Agent uses YAML configuration files located in the `config/` directory:

| File | Purpose |
|------|---------|
| `config/medic.yaml` | Main configuration file |
| `config/constitution.yaml` | Phase feature toggles and safety constraints |
| `config/medic.production.yaml` | Production configuration template |

### Loading Configuration

The agent loads configuration in this order:

1. Default values (built-in)
2. `config/medic.yaml` (or path from `MEDIC_CONFIG_PATH`)
3. Environment variable overrides

---

## Operating Modes

The `mode` section controls the agent's operational behavior:

```yaml
mode:
  current: "observer"   # Active operating mode
  fallback: "observer"  # Mode to use on error
```

### Available Modes

| Mode | Description | Auto-Resurrect | Human Review |
|------|-------------|----------------|--------------|
| `observer` | Log decisions, no action | No | N/A |
| `manual` | Require human approval | No | All |
| `semi_auto` | Auto-approve low-risk | Low-risk only | Medium/High |
| `full_auto` | Fully autonomous | Yes | Critical only |

### Mode Progression

```
observer → manual → semi_auto → full_auto
(Phase 1)  (Phase 2)  (Phase 3)   (Phase 5)
```

---

## Smith Integration

Configure connection to Smith's event bus:

```yaml
smith:
  event_bus:
    type: "redis"                              # redis | rabbitmq | kafka | mock
    host: "localhost"
    port: 6379
    topic: "smith.events.kill_notifications"
    response_topic: "medic.responses"
    consumer_group: "medic-agent"
```

### Veto Protocol (Phase 5)

Enable Medic to veto Smith's kill decisions:

```yaml
  veto_protocol:
    enabled: true
    timeout_seconds: 30          # Max wait for veto processing
    max_vetos_per_hour: 10       # Rate limit vetoes
    cooldown_seconds: 300        # Cooldown between vetoes for same module
    min_fp_for_veto: 3           # Min false positives to trigger veto
    max_risk_for_veto: 0.3       # Max risk score for veto eligibility
    require_human: false         # Require human approval for vetoes
```

### Smith Negotiation (Phase 5)

Enable bidirectional negotiation with Smith:

```yaml
  negotiation:
    enabled: true
    request_topic: "medic.to_smith"
    response_topic: "smith.to_medic"
    timeout_seconds: 30
```

---

## SIEM Integration

Configure SIEM adapter for threat intelligence:

```yaml
siem:
  adapter: "rest"               # rest | grpc | mock
  endpoint: "http://localhost:8080/siem"
  auth:
    type: "api_key"
    key_env: "SIEM_API_KEY"     # Environment variable containing API key
  timeout_seconds: 30
  retry:
    max_attempts: 3
    backoff_seconds: 2
```

### Authentication Types

- `api_key`: Bearer token authentication (recommended)
- `basic`: HTTP Basic authentication
- `none`: No authentication (mock/testing only)

---

## Decision Engine

Configure decision-making behavior:

```yaml
decision:
  default_timeout_minutes: 60    # Decision validity window
  confidence_threshold: 0.7      # Minimum confidence for decisions
  auto_approve:
    enabled: false               # Enable auto-approval
    max_risk_level: "low"        # Maximum risk level for auto-approval
    min_confidence: 0.85         # Minimum confidence for auto-approval
```

---

## Risk Assessment

Configure risk scoring thresholds and factor weights:

```yaml
risk:
  thresholds:
    minimal: 0.2    # Score 0.0-0.2
    low: 0.4        # Score 0.2-0.4
    medium: 0.6     # Score 0.4-0.6
    high: 0.8       # Score 0.6-0.8
    # Critical: Score 0.8-1.0

  weights:
    smith_confidence: 0.30       # Smith's kill confidence
    siem_risk_score: 0.25        # SIEM threat score
    false_positive_history: 0.20 # Historical FP rate
    module_criticality: 0.15     # Business criticality
    time_of_day: 0.10            # Time-based risk adjustment
```

### Risk Calculation

```
risk_score = Σ(factor_value × factor_weight)
```

All weights should sum to 1.0.

---

## Resurrection Settings

Configure resurrection execution:

```yaml
resurrection:
  monitoring_duration_minutes: 30    # Post-resurrection monitoring
  health_check_interval_seconds: 30  # Health check frequency
  max_retry_attempts: 2              # Max resurrection retries
  rollback:
    enabled: true
    auto_trigger_on_anomaly: true    # Auto-rollback on anomalies
    anomaly_threshold: 0.7           # Anomaly score to trigger rollback
```

---

## Auto-Resurrection

Configure automatic resurrection (Phase 3+):

```yaml
auto_resurrection:
  enabled: true
  max_per_hour: 10                   # Global rate limit
  max_per_module_per_hour: 3         # Per-module rate limit
  cooldown_seconds: 300              # Cooldown between same-module resurrections
  min_confidence: 0.85               # Minimum confidence required
  max_risk_score: 0.3                # Maximum risk score allowed
  require_health_check: true         # Require health check before completion
  monitoring_duration_minutes: 30    # Post-resurrection monitoring
```

---

## Interfaces

### CLI Interface

```yaml
interfaces:
  cli:
    enabled: true    # Enable CLI for manual approvals
```

### Web Interface

```yaml
  web:
    enabled: false
    port: 8000
    host: "0.0.0.0"
    cors_origins: []               # Allowed CORS origins (empty = same-origin only)
    rate_limit_per_minute: 120     # API rate limit
    max_request_size_bytes: 10485760  # 10MB max request body
```

**Production CORS Configuration:**

```yaml
    cors_origins:
      - "https://medic-dashboard.example.com"
      - "https://admin.example.com"
```

### Approval Queue

```yaml
  approval_queue:
    max_pending: 100      # Maximum pending items
    timeout_hours: 24     # Item expiration time
```

---

## Learning System

Configure adaptive learning (Phase 4+):

```yaml
learning:
  enabled: true
  database:
    type: "sqlite"              # sqlite | postgres | memory
    path: "data/outcomes.db"

  analysis:
    schedule: "daily"           # daily | weekly
    min_samples: 50             # Minimum samples for analysis
    time_window_days: 30        # Analysis window
    false_positive_threshold: 0.3
    success_rate_threshold: 0.7
    auto_approve_accuracy_threshold: 0.9

  threshold_adjustment:
    enabled: false              # Require explicit approval
    require_approval: true      # Human approval for changes
    max_adjustment_percent: 10  # Maximum threshold change
    cooldown_hours: 24          # Cooldown between adjustments
    target_accuracy: 0.95       # Target decision accuracy

  feedback:
    auto_collect: true          # Auto-collect from monitoring
    require_confirmation: false # Auto-process simple feedback
```

---

## Edge Case Handling

Configure edge case detection (Phase 5):

```yaml
edge_cases:
  # Rapid kills - same module killed multiple times quickly
  rapid_kill_threshold: 3
  rapid_kill_window_seconds: 60

  # Cascading failures - multiple related kills
  cascade_threshold: 5
  cascade_window_seconds: 120

  # Flapping - module repeatedly killed and resurrected
  flap_threshold: 4
  flap_window_minutes: 30

  # System-wide anomalies
  system_anomaly_threshold: 10

  # Response actions
  auto_pause_on_critical: true   # Pause auto-resurrection on critical
  auto_escalate: true            # Escalate to human operators
```

---

## Self-Monitoring

Configure self-monitoring (Phase 5):

```yaml
self_monitoring:
  enabled: true
  check_interval_seconds: 60
  history_window_minutes: 60

  # Latency thresholds
  latency_warning_ms: 500
  latency_critical_ms: 2000

  # Error rate thresholds
  error_rate_warning: 0.05      # 5% error rate
  error_rate_critical: 0.15     # 15% error rate

  # Queue depth thresholds
  queue_warning: 50
  queue_critical: 100

  # Memory thresholds
  memory_warning_percent: 70.0
  memory_critical_percent: 90.0

  # Auto-remediation
  auto_remediate: true
```

---

## Multi-Cluster

Configure multi-cluster deployments (Phase 7):

```yaml
cluster:
  enabled: false
  id: "cluster-001"                    # Unique cluster ID
  name: "medic-us-east-1"              # Human-readable name
  endpoint: "http://medic.us-east-1.example.com:8000"
  region: "us-east-1"
  zone: "us-east-1a"

  store:
    type: "memory"                     # memory | redis | etcd

    # Redis configuration
    redis:
      host: "redis.example.com"
      port: 6379
      db: 1
      password_env: "CLUSTER_REDIS_PASSWORD"

    # etcd configuration
    etcd:
      endpoints:
        - "https://etcd1.example.com:2379"
        - "https://etcd2.example.com:2379"
      cert_file: "/etc/medic/etcd-client.crt"
      key_file: "/etc/medic/etcd-client.key"

  sync:
    decisions: true        # Sync decisions across clusters
    thresholds: true       # Sync thresholds from leader
    outcomes: false        # Sync outcome data

  election:
    ttl_seconds: 30        # Leader lock TTL
    retry_interval_seconds: 15
```

---

## Logging

Configure structured logging:

```yaml
logging:
  level: "INFO"            # DEBUG | INFO | WARNING | ERROR | CRITICAL
  format: "text"           # json | text (use json for production)
  outputs:
    - type: "console"
    - type: "file"
      path: "logs/medic.log"
      rotation: "daily"
      retention_days: 30

  structured_fields:       # Fields to include in structured logs
    - "kill_id"
    - "decision_id"
    - "request_id"
```

### Log Levels

| Level | Use Case |
|-------|----------|
| `DEBUG` | Development debugging |
| `INFO` | Normal operations |
| `WARNING` | Recoverable issues |
| `ERROR` | Errors requiring attention |
| `CRITICAL` | System failures |

---

## Metrics

Configure Prometheus metrics export:

```yaml
metrics:
  enabled: true
  exporter: "prometheus"
  port: 9090
  labels:
    environment: "production"
    service: "medic-agent"
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `medic_kills_received_total` | Counter | Kill reports received |
| `medic_decisions_total` | Counter | Decisions made by outcome |
| `medic_resurrections_total` | Counter | Resurrections attempted |
| `medic_resurrection_duration_seconds` | Histogram | Resurrection duration |
| `medic_errors_total` | Counter | Errors by category |
| `medic_queue_size` | Gauge | Approval queue size |
| `medic_active_resurrections` | Gauge | In-progress resurrections |

---

## Constitution

The constitution file (`config/constitution.yaml`) controls feature toggles and safety constraints.

### Phase Feature Toggles

```yaml
phases:
  phase_0_foundation:
    enabled: true
    features:
      kill_listener: true
      siem_query: true
      structured_logging: true

  phase_1_observer:
    enabled: true
    features:
      decision_logic: true
      decision_logging: true
      daily_reports: true

  # ... additional phases
```

### Safety Constraints

```yaml
constraints:
  max_auto_resurrections_per_hour: 10
  require_human_review_for_critical: true
  blacklisted_modules: []
  always_require_approval:
    - "auth-service"
    - "payment-processor"
    - "data-pipeline"
    - "secrets-manager"
  min_resurrection_confidence: 0.6
  max_auto_resurrect_risk: 0.4
  resurrection_cooldown_seconds: 300
```

### Escalation Rules

```yaml
escalation:
  repeated_kill_threshold: 3
  repeated_kill_window_minutes: 60
  on_resurrection_failure: true
  notify:
    - type: "log"
      level: "warning"
    # - type: "slack"
    #   channel: "#medic-alerts"
    # - type: "pagerduty"
    #   service_key_env: "PAGERDUTY_KEY"
```

---

## Environment Variables

### Required Variables

| Variable | Description |
|----------|-------------|
| `MEDIC_CONFIG_PATH` | Path to configuration file |
| `SIEM_API_KEY` | SIEM API authentication key |
| `SMITH_EVENT_BUS_URL` | Smith event bus connection URL |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MEDIC_ENV` | Environment (development/production) | development |
| `MEDIC_LOG_LEVEL` | Log level override | INFO |
| `MEDIC_MODE` | Operating mode override | (from config) |
| `MEDIC_METRICS_PORT` | Metrics port override | 9090 |

### Authentication Variables

| Variable | Description |
|----------|-------------|
| `MEDIC_ADMIN_API_KEY` | Admin API key |
| `MEDIC_OPERATOR_API_KEY` | Operator API key |
| `MEDIC_VIEWER_API_KEY` | Viewer API key |
| `CLUSTER_REDIS_PASSWORD` | Redis password for cluster store |

---

## Production Configuration

### Key Differences from Development

1. **Mode**: Use `semi_auto` (not `observer`)
2. **Logging**: Use `json` format for log aggregation
3. **CLI**: Disable (use web API instead)
4. **Web**: Enable with proper CORS origins
5. **Cluster**: Enable for HA deployments

### Production Checklist

- [ ] Set `MEDIC_ENV=production`
- [ ] Configure proper CORS origins
- [ ] Set all required API keys as environment variables
- [ ] Enable JSON logging format
- [ ] Configure Prometheus metrics scraping
- [ ] Set up alerting for critical metrics
- [ ] Configure multi-cluster if deploying to multiple regions
- [ ] Review and customize safety constraints

### Sample Production Configuration

See `config/medic.production.yaml` for a complete production template.

---

## Configuration Validation

The agent validates configuration on startup. Invalid configuration will:

1. Log detailed error messages
2. Fall back to safe defaults where possible
3. Exit with error code if critical settings are missing

### Validation Rules

- All weights must sum to 1.0
- Thresholds must be in ascending order
- Rate limits must be positive integers
- Required environment variables must be set
- File paths must be writable

---

*Document Version: 1.0*
*Last Updated: 2026-01-02*
