# Changelog

All notable changes to the Medic Agent project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2026-01-02

### Added

#### Core Features
- **Kill Report Listener**: Real-time subscription to Smith kill notification feed via Redis Streams
- **SIEM Integration**: REST-based adapter for threat intelligence queries with retry logic
- **Decision Engine**: Risk-based evaluation with configurable thresholds and weights
- **Risk Assessment**: Multi-factor risk scoring (Smith confidence, SIEM score, false positive history, module criticality)

#### Operating Modes
- **Observer Mode**: Log-only mode for monitoring without action
- **Manual Mode**: All resurrections require human approval
- **Semi-Auto Mode**: Automatic approval for low-risk cases
- **Full-Auto Mode**: Fully autonomous operation with critical module protection

#### Resurrection System
- **Resurrection Executor**: Workflow execution with health checks
- **Post-Resurrection Monitoring**: Anomaly detection and automatic rollback
- **Approval Queue**: Human review interface for pending decisions

#### Learning System
- **Outcome Store**: SQLite-based storage for resurrection outcomes
- **Pattern Analyzer**: Detection of patterns in kill/resurrection data
- **Threshold Adapter**: Adaptive adjustment of decision thresholds

#### Smith Integration
- **Smith Negotiator**: Communication protocol for resurrection proposals
- **Veto Protocol**: Handling of Smith's resurrection vetoes
- **Edge Case Manager**: Handling of cascading kills, rapid kills, module flapping

#### Interfaces
- **CLI Interface**: Command-line tool for operators
- **REST API**: FastAPI-based API for programmatic access
- **Prometheus Metrics**: Full observability with custom metrics

#### Production Features
- **Structured Logging**: JSON-formatted logs with trace correlation
- **Error Handling**: Custom exception hierarchy with circuit breaker pattern
- **Self-Monitoring**: Internal health checks and auto-remediation

#### Security Enhancements
- **CORS Protection**: Restrictive CORS with configurable origins
- **Rate Limiting**: API rate limiting infrastructure
- **Secret Management**: External secrets support (Vault, AWS Secrets Manager, etc.)
- **Input Validation**: Protection against injection attacks

#### Deployment
- **Docker**: Multi-stage production build with non-root user
- **Kubernetes**: Complete manifests with PDB, NetworkPolicy, HPA support
- **Kustomize Overlays**: Separate development and production configurations
- **CI/CD**: GitHub Actions workflow with linting, testing, security scanning

#### Testing
- **Unit Tests**: Core logic, models, risk assessment
- **Integration Tests**: End-to-end workflow testing
- **Security Tests**: Input validation, injection prevention, API security
- **Performance Tests**: Throughput and latency benchmarks

### Security Notes

- SIEM API keys should be provided via environment variables, not config files
- Grafana and other service passwords must be set explicitly (no defaults)
- CORS origins must be configured for production deployments
- Kubernetes secrets should use external-secrets operator in production

### Known Limitations

- Async tests require `pytest-asyncio` package
- Some validation edge cases are handled permissively
- Learning system threshold adjustments require manual approval

### Migration Notes

This is the initial alpha release. No migration required.

---

## [Unreleased]

### Planned for 0.2.0
- Enhanced machine learning for decision patterns
- Multi-cluster support
- WebSocket-based real-time updates
- Advanced reporting dashboard

---

[0.1.0-alpha]: https://github.com/kase1111-hash/medic-agent/releases/tag/v0.1.0-alpha
[Unreleased]: https://github.com/kase1111-hash/medic-agent/compare/v0.1.0-alpha...HEAD
