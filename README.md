🧠 Medic Agent – Repository Specification Sheet

Repository Name: medic-agent
Parent Organization: github.com/kase1111-hash

Purpose: Autonomous resilience layer that listens to Smith kill reports, evaluates legitimacy, and manages resurrection workflows with adaptive learning.

1. Repository Overview
Component	Description	Phase Introduced
core/	Core logic for message listening, SIEM querying, and decision evaluation.	Phase 0–1
interfaces/	CLI/Web UI for human review and manual approval workflows.	Phase 2
execution/	Resurrection, monitoring, and rollback management.	Phase 2
learning/	Outcome logging, pattern analysis, and adaptive thresholds.	Phase 4
integration/	Smith protocol bindings, SIEM adapters, and human override APIs.	Phase 3–5
tests/	Unit and integration tests for each subsystem.	Continuous
docs/	Phase documentation, quick-start guides, architecture diagrams.	Continuous
2. System Architecture

Core Flow Diagram:

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

3. Phase-Based Feature Breakdown
🩸 Phase 0 — Foundation

Goal: Get Medic listening, parsing, and logging kill reports.

Module	File	Description
Message Listener	core/listener.py	Subscribes to Smith kill feed, parses KILL_REPORT.
SIEM Adapter	core/siem_interface.py	Queries SIEM, parses CONTEXT_RESPONSE.
Logging	core/logger.py	Structured logging to disk and console.

Integration Points:

Connects to Smith’s event bus (smith.events.kill_notifications)

Queries SIEM via REST or gRPC (siem/query endpoint)

🧩 Phase 1 — Observer Mode

Goal: Decision logic without action.

Module	File	Description
Decision Logic	core/decision.py	Implements should_resurrect()
Decision Logging	core/log_decisions.py	Logs what Medic would have done.
Reporting	core/reporting.py	Generates daily summaries (CSV + JSON).

Artifacts:

observer.log (raw decisions)

reports/daily_summary.json

⚙️ Phase 2 — Manual Resurrection Mode

Goal: Human-approved resurrection workflow.

Module	File	Description
Recommendation Engine	execution/recommendation.py	Generates structured resurrection proposals.
Human Interface	interfaces/cli.py or interfaces/web.py	Allows human review, approval, or denial.
Resurrection Executor	execution/resurrector.py	Handles restore, monitor, and rollback.
Monitoring Engine	execution/monitor.py	Observes resurrected modules for anomalies.

Integration Points:

CLI / Web API under /approval

Uses internal event bus for state change tracking

🧮 Phase 3 — Semi-Autonomous Mode

Goal: Automated decisions for low-risk cases.

Module	File	Description
Risk Assessment	core/risk.py	Implements assess_risk() scoring function.
Auto-Resurrection	execution/auto_resurrect.py	Executes low-risk revivals automatically.
Approval Queue	interfaces/approval_queue.py	Routes medium-risk recommendations to human queue.

Integration Points:

Internal message broker (Redis/RabbitMQ)

smith.veto pre-resurrection notice protocol (Phase 5 compatibility)

🧬 Phase 4 — Learning System

Goal: Self-improving decision thresholds via outcome analytics.

Module	File	Description
Outcome Database	learning/outcomes_db.py	SQLite or lightweight Postgres for outcome storage.
Pattern Analysis	learning/analyze.py	Weekly analysis and pattern detection.
Adaptive Thresholds	learning/thresholds.py	Adjusts decision criteria dynamically.

Artifacts:

outcomes.db

smith_feedback_report.json

🧠 Phase 5 — Full Autonomous Mode

Goal: Fully autonomous, self-healing, self-evaluating system.

Module	File	Description
Edge Case Manager	integration/edge_cases.py	Handles mass kills, dependency chains.
Smith Collaboration	integration/smith_negotiation.py	Negotiation and veto handling.
Self-Monitoring	core/self_monitor.py	Evaluates Medic’s performance and confidence decay.

Integration Points:

Bi-directional API with Smith core

Threat-level feedback loop to SIEM

4. Repository Structure (Proposed)
medic-agent/
├── core/
│   ├── listener.py
│   ├── siem_interface.py
│   ├── decision.py
│   ├── risk.py
│   ├── logger.py
│   └── self_monitor.py
├── execution/
│   ├── resurrector.py
│   ├── monitor.py
│   ├── recommendation.py
│   └── auto_resurrect.py
├── interfaces/
│   ├── cli.py
│   ├── web.py
│   └── approval_queue.py
├── learning/
│   ├── outcomes_db.py
│   ├── analyze.py
│   └── thresholds.py
├── integration/
│   ├── edge_cases.py
│   ├── smith_negotiation.py
│   └── siem_adapters/
├── tests/
│   ├── test_decision.py
│   ├── test_resurrector.py
│   └── test_learning.py
├── docs/
│   ├── QUICKSTART.md
│   ├── ARCHITECTURE.md
│   └── API_REFERENCE.md
└── main.py

5. Technology Stack
Component	Tech
Language	Python 3.11+
Database	SQLite (upgrade path: PostgreSQL)
APIs	FastAPI or Flask
Message Broker	Redis Streams (optional)
Testing	Pytest
Logging	Python logging + JSON structured logs
Learning	Pandas + Scikit-learn (for pattern detection, Phase 4+)
6. Integration Roadmap (Weeks 1–9)
Week	Milestone	Deliverables
1	Phase 0 – Foundation	Listener + SIEM adapter + basic logging
2	Phase 1 – Observer Mode	Decision logic + daily summaries
3–4	Phase 2 – Manual Mode	CLI approval + resurrection + monitoring
5–6	Phase 3 – Semi-Auto	Auto resurrection + risk assessment
7–8	Phase 4 – Learning	Outcome tracking + adaptive thresholds
9+	Phase 5 – Full Auto	Smith negotiation + self-monitoring
7. Success Metrics
Stage	KPI	Target
MVP (Week 4)	Human-approved resurrections	≥5 successful
Semi-Auto (Week 6)	Auto-resurrection success rate	≥80%
Full Auto (Week 9)	Self-healing performance	≥85% sustained
Learning Phase	Improvement in false-positive detection	≥25%
8. Deliverables

README.md — Overview and usage instructions

docs/ARCHITECTURE.md — Internal architecture and decision flow diagrams

medic_agent.py — Entry point for all runtime phases

Unit & Integration Tests — Minimum 80% coverage target

Configurable constitution.yaml — Phase feature toggles for controlled rollout
