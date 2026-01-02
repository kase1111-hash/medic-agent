# Medic Agent - Technical Specification Sheet

## 1. Executive Summary

**Project Name:** Medic Agent
**Purpose:** Autonomous resilience layer that monitors kill events from Smith, evaluates their legitimacy, and orchestrates resurrection workflows with adaptive learning capabilities.

**Core Capabilities:**
- Listen and parse Smith kill notifications
- Query SIEM for contextual threat intelligence
- Make resurrection decisions (observer → manual → semi-auto → full-auto)
- Execute and monitor resurrection workflows
- Learn from outcomes to improve decision accuracy

---

## 2. Data Models & Type Definitions

### 2.1 Kill Report (Inbound from Smith)

```python
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, List

class KillReason(Enum):
    THREAT_DETECTED = "threat_detected"
    ANOMALY_BEHAVIOR = "anomaly_behavior"
    POLICY_VIOLATION = "policy_violation"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DEPENDENCY_CASCADE = "dependency_cascade"
    MANUAL_OVERRIDE = "manual_override"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class KillReport:
    """Inbound message from Smith's kill notification feed."""
    kill_id: str                      # Unique identifier (UUID)
    timestamp: datetime               # When the kill occurred
    target_module: str                # Module/process that was killed
    target_instance_id: str           # Specific instance identifier
    kill_reason: KillReason           # Categorized reason for kill
    severity: Severity                # Assessed threat severity
    confidence_score: float           # Smith's confidence (0.0-1.0)
    evidence: List[str]               # Supporting evidence references
    dependencies: List[str]           # Affected downstream modules
    source_agent: str                 # Smith instance that issued kill
    metadata: dict                    # Additional context data
```

### 2.2 SIEM Context Response

```python
@dataclass
class ThreatIndicator:
    """Individual threat indicator from SIEM."""
    indicator_type: str               # IP, hash, domain, behavior, etc.
    value: str                        # The actual indicator value
    threat_score: float               # 0.0-1.0 normalized score
    source: str                       # Intel source name
    last_seen: datetime               # Most recent observation
    tags: List[str]                   # Classification tags

@dataclass
class SIEMContextResponse:
    """Enriched context from SIEM query."""
    query_id: str                     # Correlation ID
    kill_id: str                      # Reference to original kill
    timestamp: datetime               # Query execution time
    threat_indicators: List[ThreatIndicator]
    historical_behavior: dict         # Past behavior patterns
    false_positive_history: int       # Prior FP count for this module
    network_context: dict             # Related network activity
    user_context: Optional[dict]      # Associated user activity
    risk_score: float                 # Aggregated risk (0.0-1.0)
    recommendation: str               # SIEM's initial recommendation
```

### 2.3 Resurrection Decision

```python
class DecisionOutcome(Enum):
    APPROVE_AUTO = "approve_auto"           # Auto-resurrect (low risk)
    APPROVE_MANUAL = "approve_manual"       # Approved by human
    PENDING_REVIEW = "pending_review"       # Awaiting human review
    DENY = "deny"                           # Do not resurrect
    DEFER = "defer"                         # Need more information

class RiskLevel(Enum):
    MINIMAL = "minimal"       # Score 0.0-0.2
    LOW = "low"               # Score 0.2-0.4
    MEDIUM = "medium"         # Score 0.4-0.6
    HIGH = "high"             # Score 0.6-0.8
    CRITICAL = "critical"     # Score 0.8-1.0

@dataclass
class ResurrectionDecision:
    """Decision output from the decision engine."""
    decision_id: str                  # Unique decision identifier
    kill_id: str                      # Reference to kill report
    timestamp: datetime               # When decision was made
    outcome: DecisionOutcome          # The decision result
    risk_level: RiskLevel             # Assessed risk level
    risk_score: float                 # Numeric risk (0.0-1.0)
    confidence: float                 # Decision confidence (0.0-1.0)
    reasoning: List[str]              # Human-readable reasoning chain
    recommended_action: str           # Specific action recommendation
    requires_human_review: bool       # Flag for human queue
    auto_approve_eligible: bool       # Eligible for auto-resurrection
    constraints: List[str]            # Conditions for resurrection
    timeout_minutes: int              # Decision validity window
```

### 2.4 Resurrection Request

```python
class ResurrectionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"

@dataclass
class ResurrectionRequest:
    """Execution request for resurrection workflow."""
    request_id: str                   # Unique request identifier
    decision_id: str                  # Reference to decision
    kill_id: str                      # Reference to original kill
    target_module: str                # Module to resurrect
    target_instance_id: str           # Instance to restore
    status: ResurrectionStatus        # Current workflow status
    created_at: datetime              # Request creation time
    approved_at: Optional[datetime]   # When approved
    approved_by: Optional[str]        # "auto" or user identifier
    executed_at: Optional[datetime]   # Execution start time
    completed_at: Optional[datetime]  # Completion time
    rollback_reason: Optional[str]    # If rolled back, why
    monitoring_duration_minutes: int  # Post-resurrection watch period
    health_checks: List[str]          # Health check endpoints
```

### 2.5 Outcome Record (For Learning)

```python
class OutcomeResult(Enum):
    SUCCESS = "success"               # Resurrection successful, stable
    PARTIAL_SUCCESS = "partial"       # Some issues but acceptable
    FAILURE = "failure"               # Resurrection failed
    RE_KILLED = "re_killed"           # Smith killed it again
    ROLLBACK = "rollback"             # Had to rollback

@dataclass
class OutcomeRecord:
    """Learning system outcome for analysis."""
    outcome_id: str                   # Unique outcome identifier
    request_id: str                   # Reference to resurrection request
    decision_id: str                  # Reference to decision
    kill_id: str                      # Reference to original kill
    result: OutcomeResult             # Final outcome
    recorded_at: datetime             # When outcome was recorded
    time_to_stable: Optional[int]     # Seconds until stable (if success)
    post_resurrection_metrics: dict   # Performance/behavior metrics
    smith_feedback: Optional[str]     # Any feedback from Smith
    human_feedback: Optional[str]     # Human operator notes
    lessons_learned: List[str]        # Extracted insights
    should_adjust_threshold: bool     # Flag for threshold tuning
```

---

## 3. Module Interfaces & Contracts

### 3.1 Core Module Interfaces

#### Listener Interface (`core/listener.py`)

```python
from abc import ABC, abstractmethod
from typing import AsyncIterator, Callable

class KillReportListener(ABC):
    """Interface for listening to Smith kill notifications."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to Smith event bus."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully disconnect from event bus."""
        pass

    @abstractmethod
    async def listen(self) -> AsyncIterator[KillReport]:
        """Yield incoming kill reports as async iterator."""
        pass

    @abstractmethod
    def register_handler(self, handler: Callable[[KillReport], None]) -> None:
        """Register a callback handler for incoming reports."""
        pass

    @abstractmethod
    async def acknowledge(self, kill_id: str) -> bool:
        """Acknowledge processing of a kill report."""
        pass
```

#### SIEM Interface (`core/siem_interface.py`)

```python
class SIEMAdapter(ABC):
    """Interface for SIEM query operations."""

    @abstractmethod
    async def query_context(self, kill_report: KillReport) -> SIEMContextResponse:
        """Query SIEM for context about a kill event."""
        pass

    @abstractmethod
    async def get_historical_data(
        self,
        module: str,
        days: int = 30
    ) -> List[dict]:
        """Retrieve historical behavior data for a module."""
        pass

    @abstractmethod
    async def report_outcome(self, outcome: OutcomeRecord) -> bool:
        """Report resurrection outcome back to SIEM."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify SIEM connectivity."""
        pass
```

#### Decision Engine Interface (`core/decision.py`)

```python
class DecisionEngine(ABC):
    """Interface for resurrection decision logic."""

    @abstractmethod
    def should_resurrect(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse
    ) -> ResurrectionDecision:
        """Evaluate whether to resurrect a killed module."""
        pass

    @abstractmethod
    def get_decision_factors(self) -> List[str]:
        """Return list of factors considered in decisions."""
        pass

    @abstractmethod
    def explain_decision(self, decision: ResurrectionDecision) -> str:
        """Generate human-readable explanation of decision."""
        pass
```

#### Risk Assessment Interface (`core/risk.py`)

```python
class RiskAssessor(ABC):
    """Interface for risk scoring operations."""

    @abstractmethod
    def assess_risk(
        self,
        kill_report: KillReport,
        siem_context: SIEMContextResponse
    ) -> tuple[RiskLevel, float]:
        """Calculate risk level and numeric score."""
        pass

    @abstractmethod
    def get_risk_factors(
        self,
        kill_report: KillReport
    ) -> dict[str, float]:
        """Return breakdown of individual risk factors."""
        pass

    @abstractmethod
    def update_thresholds(self, adjustments: dict) -> None:
        """Update risk thresholds based on learning."""
        pass
```

### 3.2 Execution Module Interfaces

#### Resurrector Interface (`execution/resurrector.py`)

```python
class Resurrector(ABC):
    """Interface for resurrection execution."""

    @abstractmethod
    async def resurrect(self, request: ResurrectionRequest) -> bool:
        """Execute resurrection workflow."""
        pass

    @abstractmethod
    async def rollback(self, request_id: str, reason: str) -> bool:
        """Rollback a resurrection."""
        pass

    @abstractmethod
    async def get_status(self, request_id: str) -> ResurrectionStatus:
        """Get current status of a resurrection request."""
        pass

    @abstractmethod
    def can_resurrect(self, target_module: str) -> bool:
        """Check if a module is eligible for resurrection."""
        pass
```

#### Monitor Interface (`execution/monitor.py`)

```python
class ResurrectionMonitor(ABC):
    """Interface for post-resurrection monitoring."""

    @abstractmethod
    async def start_monitoring(
        self,
        request: ResurrectionRequest,
        duration_minutes: int
    ) -> str:
        """Start monitoring a resurrected module. Returns monitor_id."""
        pass

    @abstractmethod
    async def stop_monitoring(self, monitor_id: str) -> dict:
        """Stop monitoring and return collected metrics."""
        pass

    @abstractmethod
    async def check_health(self, target_module: str) -> bool:
        """Perform health check on module."""
        pass

    @abstractmethod
    async def get_anomalies(self, monitor_id: str) -> List[dict]:
        """Get detected anomalies during monitoring."""
        pass

    @abstractmethod
    def should_rollback(self, monitor_id: str) -> tuple[bool, str]:
        """Evaluate if rollback is needed. Returns (should_rollback, reason)."""
        pass
```

### 3.3 Interface Module Contracts

#### Approval Queue Interface (`interfaces/approval_queue.py`)

```python
class ApprovalQueue(ABC):
    """Interface for human approval workflow."""

    @abstractmethod
    async def enqueue(self, decision: ResurrectionDecision) -> str:
        """Add decision to approval queue. Returns queue_item_id."""
        pass

    @abstractmethod
    async def dequeue(self, queue_item_id: str) -> Optional[ResurrectionDecision]:
        """Remove and return item from queue."""
        pass

    @abstractmethod
    async def approve(
        self,
        queue_item_id: str,
        approver: str,
        notes: Optional[str] = None
    ) -> ResurrectionRequest:
        """Approve a queued decision."""
        pass

    @abstractmethod
    async def deny(
        self,
        queue_item_id: str,
        denier: str,
        reason: str
    ) -> None:
        """Deny a queued decision."""
        pass

    @abstractmethod
    async def list_pending(self, limit: int = 50) -> List[ResurrectionDecision]:
        """List pending items in queue."""
        pass

    @abstractmethod
    async def get_stats(self) -> dict:
        """Get queue statistics."""
        pass
```

### 3.4 Learning Module Interfaces

#### Outcome Database Interface (`learning/outcomes_db.py`)

```python
class OutcomeDatabase(ABC):
    """Interface for outcome storage and retrieval."""

    @abstractmethod
    async def store_outcome(self, outcome: OutcomeRecord) -> bool:
        """Store an outcome record."""
        pass

    @abstractmethod
    async def get_outcomes(
        self,
        filters: dict,
        limit: int = 100
    ) -> List[OutcomeRecord]:
        """Retrieve outcomes matching filters."""
        pass

    @abstractmethod
    async def get_module_history(
        self,
        module: str,
        days: int = 90
    ) -> List[OutcomeRecord]:
        """Get outcome history for a specific module."""
        pass

    @abstractmethod
    async def get_success_rate(
        self,
        module: Optional[str] = None,
        days: int = 30
    ) -> float:
        """Calculate success rate for resurrections."""
        pass
```

#### Threshold Manager Interface (`learning/thresholds.py`)

```python
class ThresholdManager(ABC):
    """Interface for adaptive threshold management."""

    @abstractmethod
    def get_thresholds(self) -> dict:
        """Get current threshold configuration."""
        pass

    @abstractmethod
    def update_threshold(self, key: str, value: float) -> bool:
        """Update a specific threshold value."""
        pass

    @abstractmethod
    def calculate_adjustments(
        self,
        outcomes: List[OutcomeRecord]
    ) -> dict[str, float]:
        """Calculate recommended threshold adjustments."""
        pass

    @abstractmethod
    def apply_adjustments(self, adjustments: dict[str, float]) -> None:
        """Apply threshold adjustments."""
        pass

    @abstractmethod
    def get_adjustment_history(self, limit: int = 50) -> List[dict]:
        """Get history of threshold adjustments."""
        pass
```

---

## 4. Message Formats & Protocols

### 4.1 Smith Event Bus Protocol

**Topic:** `smith.events.kill_notifications`

**Message Format (JSON):**
```json
{
  "version": "1.0",
  "message_type": "KILL_REPORT",
  "payload": {
    "kill_id": "uuid-string",
    "timestamp": "ISO-8601",
    "target_module": "string",
    "target_instance_id": "string",
    "kill_reason": "enum:KillReason",
    "severity": "enum:Severity",
    "confidence_score": 0.0-1.0,
    "evidence": ["string"],
    "dependencies": ["string"],
    "source_agent": "string",
    "metadata": {}
  },
  "correlation_id": "uuid-string",
  "reply_to": "medic.responses"
}
```

### 4.2 SIEM Query Protocol

**Endpoint:** `POST /siem/query`

**Request:**
```json
{
  "query_type": "kill_context",
  "kill_id": "uuid-string",
  "target_module": "string",
  "target_instance_id": "string",
  "timestamp": "ISO-8601",
  "include_historical": true,
  "historical_days": 30
}
```

**Response:**
```json
{
  "query_id": "uuid-string",
  "kill_id": "uuid-string",
  "timestamp": "ISO-8601",
  "threat_indicators": [
    {
      "indicator_type": "string",
      "value": "string",
      "threat_score": 0.0-1.0,
      "source": "string",
      "last_seen": "ISO-8601",
      "tags": ["string"]
    }
  ],
  "historical_behavior": {},
  "false_positive_history": 0,
  "network_context": {},
  "user_context": {},
  "risk_score": 0.0-1.0,
  "recommendation": "string"
}
```

### 4.3 Internal Event Bus Messages

**Resurrection Request Event:**
```json
{
  "event_type": "resurrection.requested",
  "request_id": "uuid-string",
  "decision_id": "uuid-string",
  "target_module": "string",
  "timestamp": "ISO-8601"
}
```

**Status Update Event:**
```json
{
  "event_type": "resurrection.status_changed",
  "request_id": "uuid-string",
  "previous_status": "enum:ResurrectionStatus",
  "new_status": "enum:ResurrectionStatus",
  "timestamp": "ISO-8601",
  "metadata": {}
}
```

### 4.4 Smith Veto Protocol (Phase 5)

**Pre-Resurrection Notice:**
```json
{
  "message_type": "PRE_RESURRECTION_NOTICE",
  "request_id": "uuid-string",
  "kill_id": "uuid-string",
  "target_module": "string",
  "proposed_action": "resurrect",
  "risk_assessment": {
    "level": "enum:RiskLevel",
    "score": 0.0-1.0,
    "factors": {}
  },
  "timeout_seconds": 30,
  "correlation_id": "uuid-string"
}
```

**Smith Veto Response:**
```json
{
  "message_type": "RESURRECTION_VETO",
  "request_id": "uuid-string",
  "decision": "approve|veto|defer",
  "reason": "string",
  "new_evidence": [],
  "counter_proposal": {},
  "timestamp": "ISO-8601"
}
```

---

## 5. Configuration Schema

### 5.1 Main Configuration (`config/medic.yaml`)

```yaml
# Medic Agent Configuration
version: "1.0"

# Operating mode
mode:
  current: "observer"  # observer | manual | semi_auto | full_auto
  fallback: "observer"

# Smith connection settings
smith:
  event_bus:
    type: "redis"  # redis | rabbitmq | kafka
    host: "localhost"
    port: 6379
    topic: "smith.events.kill_notifications"
    response_topic: "medic.responses"
  veto_protocol:
    enabled: false
    timeout_seconds: 30

# SIEM integration
siem:
  adapter: "rest"  # rest | grpc
  endpoint: "http://localhost:8080/siem"
  auth:
    type: "api_key"
    key_env: "SIEM_API_KEY"
  timeout_seconds: 30
  retry:
    max_attempts: 3
    backoff_seconds: 2

# Decision engine settings
decision:
  default_timeout_minutes: 60
  confidence_threshold: 0.7
  auto_approve:
    enabled: false
    max_risk_level: "low"
    min_confidence: 0.85

# Risk assessment thresholds
risk:
  thresholds:
    minimal: 0.2
    low: 0.4
    medium: 0.6
    high: 0.8
  weights:
    smith_confidence: 0.3
    siem_risk_score: 0.25
    false_positive_history: 0.2
    module_criticality: 0.15
    time_of_day: 0.1

# Resurrection settings
resurrection:
  monitoring_duration_minutes: 30
  health_check_interval_seconds: 30
  max_retry_attempts: 2
  rollback:
    enabled: true
    auto_trigger_on_anomaly: true
    anomaly_threshold: 0.7

# Human review interface
interfaces:
  cli:
    enabled: true
  web:
    enabled: false
    port: 8000
    host: "0.0.0.0"
  approval_queue:
    max_pending: 100
    timeout_hours: 24

# Learning system
learning:
  enabled: false
  database:
    type: "sqlite"  # sqlite | postgres
    path: "data/outcomes.db"
  analysis:
    schedule: "weekly"  # daily | weekly
    min_samples: 50
  threshold_adjustment:
    enabled: false
    max_adjustment_percent: 10

# Logging configuration
logging:
  level: "INFO"
  format: "json"  # json | text
  outputs:
    - type: "console"
    - type: "file"
      path: "logs/medic.log"
      rotation: "daily"
      retention_days: 30
  structured_fields:
    - "kill_id"
    - "decision_id"
    - "request_id"

# Monitoring and metrics
metrics:
  enabled: true
  exporter: "prometheus"
  port: 9090
  labels:
    environment: "production"
    service: "medic-agent"
```

### 5.2 Constitution File (`config/constitution.yaml`)

```yaml
# Medic Agent Constitution
# Phase feature toggles for controlled rollout

version: "1.0"

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

  phase_2_manual:
    enabled: false
    features:
      recommendation_engine: true
      human_interface: true
      resurrection_executor: true
      post_resurrection_monitor: true

  phase_3_semi_auto:
    enabled: false
    features:
      risk_assessment: true
      auto_resurrection: true
      approval_queue: true

  phase_4_learning:
    enabled: false
    features:
      outcome_database: true
      pattern_analysis: true
      adaptive_thresholds: true

  phase_5_full_auto:
    enabled: false
    features:
      edge_case_manager: true
      smith_negotiation: true
      self_monitoring: true

# Safety constraints
constraints:
  max_auto_resurrections_per_hour: 10
  require_human_review_for_critical: true
  blacklisted_modules: []
  always_require_approval:
    - "auth-service"
    - "payment-processor"
    - "data-pipeline"
```

---

## 6. Error Handling Patterns

### 6.1 Error Categories

```python
from enum import Enum

class ErrorCategory(Enum):
    CONNECTION = "connection"       # Network/connectivity issues
    TIMEOUT = "timeout"             # Operation timeout
    VALIDATION = "validation"       # Data validation failures
    AUTHORIZATION = "authorization" # Permission/auth issues
    RATE_LIMIT = "rate_limit"       # Rate limiting hit
    INTERNAL = "internal"           # Internal processing errors
    EXTERNAL = "external"           # External service errors
    CONFIGURATION = "configuration" # Config/setup issues
```

### 6.2 Custom Exception Hierarchy

```python
class MedicError(Exception):
    """Base exception for Medic Agent."""
    def __init__(self, message: str, category: ErrorCategory, recoverable: bool = True):
        self.message = message
        self.category = category
        self.recoverable = recoverable
        super().__init__(self.message)

class SmithConnectionError(MedicError):
    """Failed to connect to Smith event bus."""
    def __init__(self, message: str):
        super().__init__(message, ErrorCategory.CONNECTION, recoverable=True)

class SIEMQueryError(MedicError):
    """SIEM query failed."""
    def __init__(self, message: str, query_id: str = None):
        self.query_id = query_id
        super().__init__(message, ErrorCategory.EXTERNAL, recoverable=True)

class DecisionError(MedicError):
    """Decision engine failure."""
    def __init__(self, message: str, kill_id: str):
        self.kill_id = kill_id
        super().__init__(message, ErrorCategory.INTERNAL, recoverable=False)

class ResurrectionError(MedicError):
    """Resurrection workflow failure."""
    def __init__(self, message: str, request_id: str, should_rollback: bool = False):
        self.request_id = request_id
        self.should_rollback = should_rollback
        super().__init__(message, ErrorCategory.INTERNAL, recoverable=True)

class ValidationError(MedicError):
    """Data validation failure."""
    def __init__(self, message: str, field: str, value: any):
        self.field = field
        self.value = value
        super().__init__(message, ErrorCategory.VALIDATION, recoverable=False)
```

### 6.3 Retry Policy

```python
from dataclasses import dataclass
from typing import Callable, TypeVar

T = TypeVar('T')

@dataclass
class RetryPolicy:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    exponential_base: float = 2.0
    jitter: bool = True
    retryable_categories: list[ErrorCategory] = None

    def __post_init__(self):
        if self.retryable_categories is None:
            self.retryable_categories = [
                ErrorCategory.CONNECTION,
                ErrorCategory.TIMEOUT,
                ErrorCategory.RATE_LIMIT,
            ]

async def with_retry(
    operation: Callable[[], T],
    policy: RetryPolicy,
    on_retry: Callable[[Exception, int], None] = None
) -> T:
    """Execute operation with retry policy."""
    # Implementation pattern for retry logic
    pass
```

### 6.4 Circuit Breaker Pattern

```python
from enum import Enum
from datetime import datetime, timedelta

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery

@dataclass
class CircuitBreaker:
    """Circuit breaker for external service calls."""
    name: str
    failure_threshold: int = 5
    recovery_timeout_seconds: int = 60
    half_open_max_calls: int = 3

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: datetime = None
    half_open_calls: int = 0

    def can_execute(self) -> bool:
        """Check if request can proceed."""
        pass

    def record_success(self) -> None:
        """Record successful call."""
        pass

    def record_failure(self) -> None:
        """Record failed call."""
        pass
```

---

## 7. Testing Strategy

### 7.1 Test Categories

| Category | Scope | Coverage Target | Tools |
|----------|-------|-----------------|-------|
| Unit | Individual functions/classes | 80%+ | pytest |
| Integration | Module interactions | 70%+ | pytest + fixtures |
| Contract | Interface compliance | 100% | pytest + mocks |
| E2E | Full workflow | Key paths | pytest + docker |
| Performance | Load/stress | Critical paths | locust |

### 7.2 Test File Structure

```
tests/
├── unit/
│   ├── core/
│   │   ├── test_listener.py
│   │   ├── test_siem_interface.py
│   │   ├── test_decision.py
│   │   └── test_risk.py
│   ├── execution/
│   │   ├── test_resurrector.py
│   │   └── test_monitor.py
│   └── learning/
│       ├── test_outcomes_db.py
│       └── test_thresholds.py
├── integration/
│   ├── test_smith_medic_flow.py
│   ├── test_siem_integration.py
│   └── test_resurrection_workflow.py
├── e2e/
│   ├── test_observer_mode.py
│   ├── test_manual_mode.py
│   └── test_semi_auto_mode.py
├── fixtures/
│   ├── kill_reports.py
│   ├── siem_responses.py
│   └── mock_services.py
└── conftest.py
```

### 7.3 Test Fixtures Pattern

```python
# tests/fixtures/kill_reports.py
import pytest
from datetime import datetime
from core.models import KillReport, KillReason, Severity

@pytest.fixture
def sample_kill_report():
    """Standard kill report for testing."""
    return KillReport(
        kill_id="test-kill-001",
        timestamp=datetime.utcnow(),
        target_module="test-service",
        target_instance_id="instance-001",
        kill_reason=KillReason.ANOMALY_BEHAVIOR,
        severity=Severity.MEDIUM,
        confidence_score=0.75,
        evidence=["log-entry-001", "metric-anomaly-002"],
        dependencies=["downstream-a", "downstream-b"],
        source_agent="smith-01",
        metadata={"region": "us-east-1"}
    )

@pytest.fixture
def low_risk_kill_report(sample_kill_report):
    """Kill report that should result in low risk assessment."""
    sample_kill_report.severity = Severity.LOW
    sample_kill_report.confidence_score = 0.5
    return sample_kill_report

@pytest.fixture
def critical_kill_report(sample_kill_report):
    """Kill report for critical threat."""
    sample_kill_report.severity = Severity.CRITICAL
    sample_kill_report.confidence_score = 0.95
    sample_kill_report.kill_reason = KillReason.THREAT_DETECTED
    return sample_kill_report
```

### 7.4 Mocking Patterns

```python
# tests/fixtures/mock_services.py
from unittest.mock import AsyncMock, MagicMock
import pytest

@pytest.fixture
def mock_siem_adapter():
    """Mock SIEM adapter for testing."""
    adapter = AsyncMock()
    adapter.query_context.return_value = SIEMContextResponse(
        query_id="query-001",
        kill_id="kill-001",
        timestamp=datetime.utcnow(),
        threat_indicators=[],
        historical_behavior={},
        false_positive_history=2,
        network_context={},
        user_context=None,
        risk_score=0.3,
        recommendation="low_risk"
    )
    adapter.health_check.return_value = True
    return adapter

@pytest.fixture
def mock_smith_listener():
    """Mock Smith event listener."""
    listener = AsyncMock()
    listener.connect.return_value = None
    listener.disconnect.return_value = None
    listener.acknowledge.return_value = True
    return listener
```

---

## 8. Design Patterns

### 8.1 Repository Pattern (Data Access)

```python
from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Optional, List

T = TypeVar('T')
ID = TypeVar('ID')

class Repository(ABC, Generic[T, ID]):
    """Generic repository interface."""

    @abstractmethod
    async def get(self, id: ID) -> Optional[T]:
        pass

    @abstractmethod
    async def get_all(self, filters: dict = None) -> List[T]:
        pass

    @abstractmethod
    async def add(self, entity: T) -> T:
        pass

    @abstractmethod
    async def update(self, entity: T) -> T:
        pass

    @abstractmethod
    async def delete(self, id: ID) -> bool:
        pass
```

### 8.2 Strategy Pattern (Decision Algorithms)

```python
from abc import ABC, abstractmethod

class DecisionStrategy(ABC):
    """Strategy interface for decision algorithms."""

    @abstractmethod
    def evaluate(
        self,
        kill_report: KillReport,
        context: SIEMContextResponse
    ) -> DecisionOutcome:
        pass

class ConservativeStrategy(DecisionStrategy):
    """Always require human review."""
    def evaluate(self, kill_report, context) -> DecisionOutcome:
        return DecisionOutcome.PENDING_REVIEW

class BalancedStrategy(DecisionStrategy):
    """Balance auto-approval with human review."""
    pass

class AggressiveStrategy(DecisionStrategy):
    """Favor auto-approval for low-risk cases."""
    pass
```

### 8.3 Observer Pattern (Event Handling)

```python
from abc import ABC, abstractmethod
from typing import List, Callable
from enum import Enum

class EventType(Enum):
    KILL_RECEIVED = "kill_received"
    DECISION_MADE = "decision_made"
    RESURRECTION_STARTED = "resurrection_started"
    RESURRECTION_COMPLETED = "resurrection_completed"
    RESURRECTION_FAILED = "resurrection_failed"
    ROLLBACK_TRIGGERED = "rollback_triggered"

class EventEmitter:
    """Central event emitter for internal events."""

    def __init__(self):
        self._listeners: dict[EventType, List[Callable]] = {}

    def on(self, event_type: EventType, handler: Callable) -> None:
        """Register event handler."""
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(handler)

    def emit(self, event_type: EventType, data: any) -> None:
        """Emit event to all registered handlers."""
        for handler in self._listeners.get(event_type, []):
            handler(data)
```

### 8.4 Pipeline Pattern (Processing Chain)

```python
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

T = TypeVar('T')

class PipelineStep(ABC, Generic[T]):
    """Single step in processing pipeline."""

    @abstractmethod
    def process(self, data: T) -> T:
        pass

    @abstractmethod
    def should_continue(self, data: T) -> bool:
        pass

class Pipeline(Generic[T]):
    """Processing pipeline executor."""

    def __init__(self):
        self._steps: List[PipelineStep[T]] = []

    def add_step(self, step: PipelineStep[T]) -> 'Pipeline[T]':
        self._steps.append(step)
        return self

    def execute(self, data: T) -> T:
        result = data
        for step in self._steps:
            result = step.process(result)
            if not step.should_continue(result):
                break
        return result
```

### 8.5 State Machine Pattern (Resurrection Workflow)

```python
from enum import Enum, auto
from typing import Dict, Set, Callable

class WorkflowState(Enum):
    PENDING = auto()
    APPROVED = auto()
    EXECUTING = auto()
    MONITORING = auto()
    STABLE = auto()
    ANOMALY_DETECTED = auto()
    ROLLING_BACK = auto()
    COMPLETED = auto()
    FAILED = auto()

class WorkflowStateMachine:
    """State machine for resurrection workflow."""

    TRANSITIONS: Dict[WorkflowState, Set[WorkflowState]] = {
        WorkflowState.PENDING: {WorkflowState.APPROVED, WorkflowState.FAILED},
        WorkflowState.APPROVED: {WorkflowState.EXECUTING, WorkflowState.FAILED},
        WorkflowState.EXECUTING: {WorkflowState.MONITORING, WorkflowState.FAILED},
        WorkflowState.MONITORING: {
            WorkflowState.STABLE,
            WorkflowState.ANOMALY_DETECTED
        },
        WorkflowState.STABLE: {WorkflowState.COMPLETED},
        WorkflowState.ANOMALY_DETECTED: {
            WorkflowState.ROLLING_BACK,
            WorkflowState.STABLE
        },
        WorkflowState.ROLLING_BACK: {WorkflowState.FAILED},
    }

    def __init__(self, initial_state: WorkflowState = WorkflowState.PENDING):
        self._state = initial_state
        self._on_transition: List[Callable] = []

    @property
    def state(self) -> WorkflowState:
        return self._state

    def can_transition(self, to_state: WorkflowState) -> bool:
        return to_state in self.TRANSITIONS.get(self._state, set())

    def transition(self, to_state: WorkflowState) -> bool:
        if not self.can_transition(to_state):
            return False
        old_state = self._state
        self._state = to_state
        for callback in self._on_transition:
            callback(old_state, to_state)
        return True
```

---

## 9. API Endpoints (Phase 2+)

### 9.1 REST API Structure

```
/api/v1/
├── /health                    GET     Health check
├── /status                    GET     System status
├── /decisions
│   ├── /                      GET     List recent decisions
│   └── /{decision_id}         GET     Get specific decision
├── /queue
│   ├── /                      GET     List pending approvals
│   ├── /{item_id}/approve     POST    Approve resurrection
│   └── /{item_id}/deny        POST    Deny resurrection
├── /resurrections
│   ├── /                      GET     List resurrection requests
│   ├── /{request_id}          GET     Get request details
│   ├── /{request_id}/status   GET     Get current status
│   └── /{request_id}/rollback POST    Trigger rollback
├── /outcomes
│   ├── /                      GET     List outcomes
│   └── /stats                 GET     Outcome statistics
├── /config
│   ├── /                      GET     Current configuration
│   ├── /thresholds            GET     Current thresholds
│   └── /thresholds            PUT     Update thresholds
└── /reports
    ├── /daily                 GET     Daily summary report
    └── /weekly                GET     Weekly analysis report
```

### 9.2 Response Format

```json
{
  "success": true,
  "data": {},
  "meta": {
    "timestamp": "ISO-8601",
    "request_id": "uuid",
    "version": "1.0"
  },
  "errors": []
}
```

---

## 10. Logging Standards

### 10.1 Log Levels

| Level | Usage |
|-------|-------|
| DEBUG | Detailed debugging information |
| INFO | Normal operational events |
| WARNING | Unexpected but handled situations |
| ERROR | Errors that need attention |
| CRITICAL | System failures requiring immediate action |

### 10.2 Structured Log Format

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "INFO",
  "logger": "medic.core.decision",
  "message": "Resurrection decision made",
  "context": {
    "kill_id": "uuid",
    "decision_id": "uuid",
    "outcome": "approve_auto",
    "risk_level": "low",
    "confidence": 0.87
  },
  "trace_id": "uuid",
  "span_id": "uuid"
}
```

### 10.3 Audit Log Events

Critical events requiring audit trail:
- Kill report received
- Decision made (all outcomes)
- Human approval/denial
- Resurrection executed
- Rollback triggered
- Threshold adjustment
- Configuration change

---

## 11. Security Considerations

### 11.1 Authentication & Authorization

- API key authentication for SIEM integration
- Role-based access control for human interface
- Audit logging for all approval actions
- Secrets stored in environment variables or vault

### 11.2 Input Validation

- Validate all incoming kill reports
- Sanitize SIEM response data
- Rate limiting on API endpoints
- Input size limits

### 11.3 Secure Defaults

- Observer mode as default
- Human review required for critical modules
- Auto-resurrection disabled by default
- All communications over TLS

---

## 12. Performance Requirements

| Metric | Target | Critical |
|--------|--------|----------|
| Kill report processing latency | < 100ms | < 500ms |
| SIEM query timeout | < 5s | < 30s |
| Decision latency | < 50ms | < 200ms |
| Resurrection execution | < 30s | < 2min |
| API response time (P99) | < 100ms | < 500ms |
| Event bus throughput | 1000/s | 100/s |

---

## 13. Deployment Considerations

### 13.1 Environment Variables

```bash
# Required
MEDIC_CONFIG_PATH=/etc/medic/medic.yaml
SIEM_API_KEY=<secret>
SMITH_EVENT_BUS_URL=redis://localhost:6379

# Optional
MEDIC_LOG_LEVEL=INFO
MEDIC_MODE=observer
MEDIC_METRICS_PORT=9090
```

### 13.2 Health Checks

```python
# Health check response
{
  "status": "healthy",  # healthy | degraded | unhealthy
  "checks": {
    "smith_connection": "ok",
    "siem_connection": "ok",
    "database": "ok",
    "queue": "ok"
  },
  "version": "1.0.0",
  "uptime_seconds": 3600
}
```

---

## 14. Implementation Priority

### Phase 0 (Foundation) - Week 1
1. `core/listener.py` - Smith event subscription
2. `core/siem_interface.py` - SIEM query adapter
3. `core/logger.py` - Structured logging
4. Configuration loading

### Phase 1 (Observer) - Week 2
1. `core/decision.py` - Decision logic
2. `core/log_decisions.py` - Decision logging
3. `core/reporting.py` - Daily summaries
4. Unit tests for core modules

### Phase 2 (Manual) - Weeks 3-4
1. `execution/resurrector.py` - Resurrection execution
2. `execution/monitor.py` - Post-resurrection monitoring
3. `interfaces/cli.py` - CLI approval interface
4. Integration tests

### Phase 3+ (Semi-Auto through Full Auto) - Weeks 5-9
1. Risk assessment engine
2. Auto-resurrection logic
3. Learning system
4. Smith negotiation protocol

---

*Document Version: 1.0*
*Last Updated: 2024-01-15*
*Maintainer: Medic Agent Development Team*
