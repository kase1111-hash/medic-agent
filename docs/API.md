# Medic Agent API Reference

Complete REST API documentation for Medic Agent v0.1.0-alpha.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Response Format](#response-format)
- [Endpoints](#endpoints)
  - [Health & Status](#health--status)
  - [Queue Management](#queue-management)
  - [Decisions](#decisions)
  - [Resurrections](#resurrections)
  - [Outcomes](#outcomes)
  - [Feedback](#feedback)
  - [Configuration](#configuration)
  - [Reports](#reports)
  - [Monitoring](#monitoring)
  - [Metrics](#metrics)
  - [WebSocket](#websocket)
- [Error Codes](#error-codes)

---

## Overview

The Medic Agent API is a FastAPI-based REST API for managing resurrection approval workflows. It provides endpoints for queue management, decision tracking, resurrection execution, outcome reporting, and system configuration.

**Base URL:** `http://localhost:8000`

**API Version:** `v1`

**OpenAPI Documentation:**
- Swagger UI: `/docs`
- ReDoc: `/redoc`

---

## Authentication

The API uses Bearer token authentication with API keys. In production mode, all endpoints except `/health` require authentication.

### Request Headers

```http
Authorization: Bearer <api_key>
```

### API Key Roles

| Role | Description |
|------|-------------|
| `admin` | Full access to all endpoints |
| `operator` | Can approve/deny resurrections and manage monitors |
| `viewer` | Read-only access to all endpoints |
| `api` | Service account for programmatic access |

### Permissions

| Permission | Description |
|------------|-------------|
| `queue:view` | View approval queue |
| `queue:approve` | Approve resurrection requests |
| `queue:deny` | Deny resurrection requests |
| `decisions:view` | View decision history |
| `resurrections:view` | View resurrection requests |
| `resurrections:rollback` | Trigger rollbacks |
| `outcomes:view` | View outcome records |
| `outcomes:feedback` | Submit feedback |
| `config:view` | View configuration |
| `config:update` | Update configuration |
| `config:thresholds` | Update risk thresholds |
| `reports:view` | View reports |
| `monitors:view` | View monitoring sessions |
| `monitors:stop` | Stop monitoring sessions |

### Environment Variables

```bash
MEDIC_ADMIN_API_KEY=<admin_key>
MEDIC_OPERATOR_API_KEY=<operator_key>
MEDIC_VIEWER_API_KEY=<viewer_key>
```

---

## Rate Limiting

The API implements rate limiting of **120 requests per minute** per client IP.

When rate limited, you'll receive:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{
  "detail": "Rate limit exceeded. Please try again later."
}
```

---

## Response Format

All successful responses follow a standard format:

```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "timestamp": "2026-01-02T12:00:00.000000",
    "version": "0.1.0-alpha"
  },
  "errors": []
}
```

Error responses:

```json
{
  "success": false,
  "data": null,
  "meta": {
    "timestamp": "2026-01-02T12:00:00.000000",
    "version": "0.1.0-alpha"
  },
  "errors": ["Error message"]
}
```

---

## Endpoints

### Health & Status

#### GET /health

Check system health. No authentication required.

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2026-01-02T12:00:00.000000",
  "checks": {
    "queue": "ok",
    "resurrector": "ok",
    "monitor": "ok",
    "outcome_store": "ok",
    "decision_logger": "ok"
  },
  "version": "0.1.0-alpha",
  "uptime_seconds": 3600.0
}
```

---

#### GET /status

Get comprehensive system status.

**Required Permission:** `queue:view`

**Response:**

```json
{
  "success": true,
  "data": {
    "mode": "observer",
    "queue": {
      "pending": 5,
      "approved": 42,
      "denied": 3,
      "total": 50
    },
    "uptime_seconds": 3600.0,
    "timestamp": "2026-01-02T12:00:00.000000",
    "authenticated_as": "admin",
    "resurrector": { ... },
    "monitor": { ... },
    "outcomes": { ... }
  },
  "meta": { ... },
  "errors": []
}
```

---

### Queue Management

#### GET /api/v1/queue

List items in the approval queue.

**Required Permission:** `queue:view`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Maximum items to return (1-100) |
| `status_filter` | string | null | Filter by status |

**Response:**

```json
{
  "success": true,
  "data": {
    "items": [
      {
        "item_id": "queue-001",
        "target_module": "auth-service",
        "risk_level": "medium",
        "created_at": "2026-01-02T12:00:00.000000",
        "expires_at": "2026-01-03T12:00:00.000000",
        "status": "pending"
      }
    ],
    "count": 1
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/queue/{item_id}

Get a specific queue item.

**Required Permission:** `queue:view`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `item_id` | string | Queue item ID |

**Response:**

```json
{
  "success": true,
  "data": {
    "item_id": "queue-001",
    "target_module": "auth-service",
    "kill_id": "kill-001",
    "risk_level": "medium",
    "risk_score": 0.45,
    "confidence": 0.85,
    "reasoning": ["Low severity", "No threat indicators"],
    "created_at": "2026-01-02T12:00:00.000000",
    "status": "pending"
  },
  "meta": { ... },
  "errors": []
}
```

---

#### POST /api/v1/queue/{item_id}/approve

Approve a resurrection proposal.

**Required Permission:** `queue:approve`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `item_id` | string | Queue item ID |

**Request Body:**

```json
{
  "approver": "admin@example.com",
  "notes": "Approved after security review"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "status": "approved",
    "request_id": "res-001",
    "approved_by": "admin@example.com",
    "approved_at": "2026-01-02T12:00:00.000000",
    "resurrection": {
      "status": "completed",
      "success": true
    },
    "monitor_id": "mon-001"
  },
  "meta": { ... },
  "errors": []
}
```

---

#### POST /api/v1/queue/{item_id}/deny

Deny a resurrection proposal.

**Required Permission:** `queue:deny`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `item_id` | string | Queue item ID |

**Request Body:**

```json
{
  "denier": "admin@example.com",
  "reason": "High-risk module with active threats"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "status": "denied",
    "denied_by": "admin@example.com",
    "reason": "High-risk module with active threats",
    "denied_at": "2026-01-02T12:00:00.000000"
  },
  "meta": { ... },
  "errors": []
}
```

---

### Decisions

#### GET /api/v1/decisions

List recent resurrection decisions.

**Required Permission:** `decisions:view`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Maximum decisions to return (1-100) |
| `offset` | integer | 0 | Pagination offset |
| `outcome` | string | null | Filter by outcome type |

**Response:**

```json
{
  "success": true,
  "data": {
    "decisions": [
      {
        "decision_id": "dec-001",
        "kill_id": "kill-001",
        "outcome": "approve_auto",
        "risk_level": "low",
        "risk_score": 0.25,
        "confidence": 0.92,
        "reasoning": ["Low severity", "High FP history"],
        "timestamp": "2026-01-02T12:00:00.000000"
      }
    ],
    "count": 1,
    "limit": 50,
    "offset": 0
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/decisions/{decision_id}

Get a specific decision.

**Required Permission:** `decisions:view`

**Response:**

```json
{
  "success": true,
  "data": {
    "decision_id": "dec-001",
    "kill_id": "kill-001",
    "outcome": "approve_auto",
    "risk_level": "low",
    "risk_score": 0.25,
    "confidence": 0.92,
    "reasoning": ["Low severity", "High FP history"],
    "recommended_action": "Auto-resurrect with monitoring",
    "requires_human_review": false,
    "auto_approve_eligible": true,
    "constraints": [],
    "timeout_minutes": 60,
    "timestamp": "2026-01-02T12:00:00.000000"
  },
  "meta": { ... },
  "errors": []
}
```

---

### Resurrections

#### GET /api/v1/resurrections

List resurrection requests.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Maximum requests to return (1-100) |
| `status` | string | null | Filter by status |

**Response:**

```json
{
  "success": true,
  "data": {
    "total": 100,
    "completed": 85,
    "failed": 10,
    "in_progress": 5
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/resurrections/{request_id}

Get resurrection request details.

**Response:**

```json
{
  "success": true,
  "data": {
    "request_id": "res-001",
    "decision_id": "dec-001",
    "kill_id": "kill-001",
    "target_module": "auth-service",
    "target_instance_id": "instance-001",
    "status": "completed",
    "created_at": "2026-01-02T12:00:00.000000",
    "approved_at": "2026-01-02T12:01:00.000000",
    "approved_by": "auto",
    "completed_at": "2026-01-02T12:02:00.000000"
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/resurrections/{request_id}/status

Get resurrection request status.

**Response:**

```json
{
  "success": true,
  "data": {
    "request_id": "res-001",
    "status": "completed"
  },
  "meta": { ... },
  "errors": []
}
```

---

#### POST /api/v1/resurrections/{request_id}/rollback

Trigger rollback of a resurrection.

**Request Body:**

```json
{
  "reason": "Module showing unstable behavior"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "status": "rolled_back",
    "request_id": "res-001",
    "reason": "Module showing unstable behavior",
    "timestamp": "2026-01-02T12:00:00.000000"
  },
  "meta": { ... },
  "errors": []
}
```

---

### Outcomes

#### GET /api/v1/outcomes

List resurrection outcomes.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 100 | Maximum outcomes to return (1-500) |
| `module` | string | null | Filter by module name |
| `outcome_type` | string | null | Filter by outcome type |

**Response:**

```json
{
  "success": true,
  "data": {
    "outcomes": [
      {
        "outcome_id": "out-001",
        "request_id": "res-001",
        "target_module": "auth-service",
        "outcome_type": "success",
        "recorded_at": "2026-01-02T12:00:00.000000"
      }
    ],
    "count": 1
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/outcomes/stats

Get outcome statistics.

**Response:**

```json
{
  "success": true,
  "data": {
    "total": 100,
    "successful": 85,
    "failed": 10,
    "rolled_back": 5,
    "success_rate": 0.85
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/outcomes/{outcome_id}

Get a specific outcome.

**Response:**

```json
{
  "success": true,
  "data": {
    "outcome_id": "out-001",
    "request_id": "res-001",
    "decision_id": "dec-001",
    "kill_id": "kill-001",
    "outcome_type": "success",
    "target_module": "auth-service",
    "time_to_stable": 120,
    "recorded_at": "2026-01-02T12:00:00.000000"
  },
  "meta": { ... },
  "errors": []
}
```

---

### Feedback

#### POST /api/v1/feedback

Submit feedback for an outcome.

**Request Body:**

```json
{
  "outcome_id": "out-001",
  "feedback_type": "accuracy",
  "value": true,
  "submitted_by": "operator@example.com",
  "comment": "Decision was correct"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "feedback_id": "fb-001",
    "status": "submitted"
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/feedback/stats

Get feedback statistics.

**Response:**

```json
{
  "success": true,
  "data": {
    "total_feedback": 50,
    "positive": 45,
    "negative": 5,
    "accuracy_rate": 0.9
  },
  "meta": { ... },
  "errors": []
}
```

---

### Configuration

#### GET /api/v1/config

Get current configuration (sanitized - no secrets).

**Response:**

```json
{
  "success": true,
  "data": {
    "mode": {
      "current": "observer",
      "fallback": "observer"
    },
    "decision": {
      "default_timeout_minutes": 60,
      "confidence_threshold": 0.7
    },
    "risk": {
      "thresholds": { ... },
      "weights": { ... }
    },
    "resurrection": {
      "monitoring_duration_minutes": 30
    },
    "learning": {
      "enabled": false
    }
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/config/thresholds

Get current risk thresholds.

**Response:**

```json
{
  "success": true,
  "data": {
    "thresholds": {
      "minimal": 0.2,
      "low": 0.4,
      "medium": 0.6,
      "high": 0.8
    },
    "weights": {
      "smith_confidence": 0.3,
      "siem_risk_score": 0.25,
      "false_positive_history": 0.2,
      "module_criticality": 0.15,
      "time_of_day": 0.1
    }
  },
  "meta": { ... },
  "errors": []
}
```

---

#### PUT /api/v1/config/thresholds

Update a risk threshold.

**Request Body:**

```json
{
  "key": "minimal",
  "value": 0.25,
  "reason": "Adjusting based on recent outcomes"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "status": "updated",
    "key": "minimal",
    "new_value": 0.25
  },
  "meta": { ... },
  "errors": []
}
```

---

### Reports

#### GET /api/v1/reports/daily

Get daily summary report.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `date` | string | today | Date in YYYY-MM-DD format |

**Response:**

```json
{
  "success": true,
  "data": {
    "date": "2026-01-02",
    "kills_received": 50,
    "decisions_made": 50,
    "resurrections_attempted": 45,
    "resurrections_successful": 40,
    "success_rate": 0.89,
    "by_outcome": {
      "approve_auto": 30,
      "approve_manual": 10,
      "deny": 5,
      "pending_review": 5
    }
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/reports/weekly

Get weekly analysis report.

**Response:**

```json
{
  "success": true,
  "data": {
    "week_start": "2025-12-27",
    "week_end": "2026-01-02",
    "total_kills": 350,
    "total_resurrections": 300,
    "success_rate": 0.87,
    "trends": { ... },
    "top_modules": [ ... ],
    "recommendations": [ ... ]
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/reports/module/{module_name}

Get report for a specific module.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `module_name` | string | Module name |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | integer | 30 | Number of days to analyze (1-90) |

**Response:**

```json
{
  "success": true,
  "data": {
    "module": "auth-service",
    "period_days": 30,
    "kill_count": 15,
    "resurrection_count": 12,
    "success_rate": 0.92,
    "average_risk_score": 0.35,
    "false_positive_rate": 0.4
  },
  "meta": { ... },
  "errors": []
}
```

---

### Monitoring

#### GET /api/v1/monitors

List active monitoring sessions.

**Response:**

```json
{
  "success": true,
  "data": {
    "monitors": [
      {
        "monitor_id": "mon-001",
        "request_id": "res-001",
        "target_module": "auth-service",
        "started_at": "2026-01-02T12:00:00.000000",
        "duration_minutes": 30,
        "status": "active"
      }
    ],
    "count": 1
  },
  "meta": { ... },
  "errors": []
}
```

---

#### GET /api/v1/monitors/{monitor_id}

Get monitoring session details.

**Response:**

```json
{
  "success": true,
  "data": {
    "monitor_id": "mon-001",
    "request_id": "res-001",
    "target_module": "auth-service",
    "started_at": "2026-01-02T12:00:00.000000",
    "duration_minutes": 30,
    "status": "active",
    "anomalies": [
      {
        "type": "latency_spike",
        "severity": "medium",
        "detected_at": "2026-01-02T12:05:00.000000"
      }
    ]
  },
  "meta": { ... },
  "errors": []
}
```

---

#### POST /api/v1/monitors/{monitor_id}/stop

Stop a monitoring session.

**Response:**

```json
{
  "success": true,
  "data": {
    "monitor_id": "mon-001",
    "status": "stopped",
    "final_metrics": { ... }
  },
  "meta": { ... },
  "errors": []
}
```

---

### Metrics

#### GET /api/v1/metrics

Get Prometheus-style metrics.

**Response:**

```json
{
  "success": true,
  "data": {
    "kills_received_total": 1000,
    "decisions_total": 1000,
    "resurrections_total": 850,
    "resurrection_success_total": 800,
    "errors_total": 50,
    "queue_size": 5,
    "active_resurrections": 2
  },
  "meta": { ... },
  "errors": []
}
```

---

### WebSocket

#### WS /ws

Real-time event stream via WebSocket.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `client_id` | string | auto-generated | Unique client identifier |
| `topics` | string | all | Comma-separated topics to subscribe to |

**Available Topics:**

- `queue` - Queue updates
- `decisions` - Decision events
- `resurrections` - Resurrection events
- `monitors` - Monitor events
- `thresholds` - Threshold updates
- `system` - System status
- `all` - All events

**Connection:**

```javascript
const ws = new WebSocket('ws://localhost:8000/ws?topics=queue,decisions');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data.type, data.data);
};
```

**Event Types:**

| Event | Description |
|-------|-------------|
| `connected` | Connection established |
| `heartbeat` | Keep-alive ping (every 30s) |
| `queue_item_added` | New item in queue |
| `queue_item_approved` | Item approved |
| `queue_item_denied` | Item denied |
| `decision_made` | Decision completed |
| `resurrection_started` | Resurrection started |
| `resurrection_completed` | Resurrection completed |
| `resurrection_failed` | Resurrection failed |
| `resurrection_rolled_back` | Rollback triggered |
| `monitor_started` | Monitoring started |
| `monitor_anomaly` | Anomaly detected |
| `monitor_completed` | Monitoring completed |
| `threshold_updated` | Threshold changed |
| `system_status` | System status update |

**Message Format:**

```json
{
  "type": "queue_item_added",
  "data": {
    "item_id": "queue-001",
    "target_module": "auth-service",
    "risk_level": "medium"
  },
  "timestamp": "2026-01-02T12:00:00.000000"
}
```

**Client Commands:**

Subscribe to additional topics:
```json
{"action": "subscribe", "topics": ["monitors"]}
```

Unsubscribe from topics:
```json
{"action": "unsubscribe", "topics": ["queue"]}
```

Ping/pong:
```json
{"action": "ping"}
```

Get current status:
```json
{"action": "get_status"}
```

---

#### GET /api/v1/websocket/clients

Get information about connected WebSocket clients.

**Response:**

```json
{
  "success": true,
  "data": {
    "clients": [
      {
        "client_id": "abc123",
        "connected_at": "2026-01-02T12:00:00.000000",
        "topics": ["all"]
      }
    ],
    "count": 1
  },
  "meta": { ... },
  "errors": []
}
```

---

#### POST /api/v1/websocket/broadcast

Broadcast a message to WebSocket clients.

**Request Body:**

```json
{
  "event_type": "system_status",
  "data": {"status": "maintenance"},
  "topic": "system"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "status": "broadcast_sent",
    "recipients": 5,
    "event_type": "system_status",
    "topic": "system"
  },
  "meta": { ... },
  "errors": []
}
```

---

## Error Codes

| HTTP Status | Description |
|-------------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Missing or invalid API key |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 413 | Request Too Large - Body exceeds 10MB |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |

---

## Security Headers

All responses include security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
```

In production mode:
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## Dashboard

A web-based dashboard is available at:

- `/dashboard` - Full dashboard UI
- `/` - Redirects to dashboard

The dashboard provides:
- Real-time system status
- Queue management
- Decision and outcome visualization
- Threshold monitoring
- WebSocket-powered live updates

---

*Document Version: 1.0*
*API Version: v1*
*Last Updated: 2026-01-02*
