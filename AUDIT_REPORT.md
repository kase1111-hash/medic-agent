# Medic Agent - Software Audit Report

**Audit Date:** 2026-01-28
**Auditor:** Claude (AI Software Audit)
**Version Audited:** v0.1.0-alpha
**Branch:** claude/audit-software-correctness-W6bgj

---

## Executive Summary

The Medic Agent is an **autonomous resilience system** designed to monitor "kill" events from a security agent called Smith, evaluate whether killed modules should be resurrected, and orchestrate the resurrection workflow. After a comprehensive audit of ~18K lines of Python code across 5 logical layers, **the software is well-architected and demonstrates professional software engineering practices**. However, several issues ranging from minor to moderate severity were identified.

### Overall Assessment: **GOOD** with Minor Issues

| Category | Rating | Notes |
|----------|--------|-------|
| Code Quality | **B+** | Clean architecture, good separation of concerns |
| Security | **B+** | Strong validation, minor timing leak in auth |
| Correctness | **B** | Logic is sound, some edge cases need attention |
| Test Coverage | **A-** | Comprehensive tests, 36 test files |
| Configuration | **A** | Secure defaults, environment-based secrets |
| Documentation | **A** | Extensive docs (~6K lines across 18 files) |
| Deployment | **A-** | Docker, K8s manifests, proper non-root user |

---

## Detailed Findings

### 1. CRITICAL Issues (0 Found)

No critical security vulnerabilities or showstopper bugs were identified.

---

### 2. HIGH Priority Issues (2 Found)

#### H1: Potential Race Condition in Resurrector (`execution/resurrector.py:251`)

**Issue:** In `ModuleResurrector.resurrect()`, the active request is deleted in the `finally` block:
```python
finally:
    self._results[request.request_id] = result
    del self._active_requests[request.request_id]
```

If another thread or async task deletes the request before this runs, a `KeyError` will be raised.

**Impact:** Could cause unhandled exceptions during concurrent resurrection attempts.

**Recommendation:** Use `dict.pop()` with a default value:
```python
self._active_requests.pop(request.request_id, None)
```

---

#### H2: API Key Validation Timing Leak (`interfaces/auth.py:213-225`)

**Issue:** The `validate_key()` method returns early when a key is found but invalid (expired/disabled), which can leak timing information about whether a key exists vs. doesn't exist.

```python
def validate_key(self, key_plain: str) -> Optional[APIKey]:
    key_hash = self._hash_key(key_plain)
    for api_key in self._keys.values():
        if self._constant_time_compare(key_hash, api_key.key_hash):
            if api_key.is_valid():  # Early return if invalid
                api_key.last_used = datetime.now(timezone.utc)
                return api_key
            else:
                return None  # Faster return than hash mismatch
    return None
```

**Impact:** Attackers could potentially determine if a key hash exists in the system even if expired.

**Recommendation:** Always iterate through all keys before returning to maintain constant time.

---

### 3. MEDIUM Priority Issues (5 Found)

#### M1: Kubernetes Resurrector Assumes ReplicaSet Exists (`execution/resurrector.py:487-492`)

**Issue:** `KubernetesResurrector.resurrect()` directly deletes pods assuming a controller (Deployment/ReplicaSet) will recreate them. If the module is managed differently (e.g., standalone pod), deletion is permanent.

**Impact:** Could permanently delete pods without recreation.

**Recommendation:** Verify pod has an `ownerReference` before deletion, or use rolling restart for Deployments.

---

#### M2: Mock Executor Uses `random.random()` (`execution/resurrector.py:410-411`)

**Issue:** The default executor includes a health check that randomly fails 10% of the time:
```python
return {"healthy": random.random() > 0.1}
```

While this is fine for testing, if someone accidentally uses the default executor in production, it could cause spurious failures.

**Impact:** Unreliable health checks if mock executor is used in production.

**Recommendation:** Add explicit check to prevent mock executor in production environment.

---

#### M3: SQLite Outcome Store Thread Safety (`learning/outcome_store.py:226-238`)

**Issue:** While thread-local storage is used for connections, there's no protection against concurrent writes from different threads that could cause database locking issues.

**Impact:** Potential "database is locked" errors under high concurrency.

**Recommendation:** Consider using a connection pool or adding retry logic for `sqlite3.OperationalError`.

---

#### M4: Confidence Score Validation Overengineered (`core/validation.py:316-331`)

**Issue:** The `validate_confidence_score()` function uses `hmac.compare_digest()` for a simple float range check, claiming it prevents timing attacks. However, knowing whether a score is in range doesn't leak sensitive information.

**Impact:** No security impact, but adds unnecessary complexity and potential confusion.

**Recommendation:** Simplify to standard comparison or document the actual threat model.

---

#### M5: SIEMContextResponse Accepts Invalid Risk Scores (`core/models.py:239`)

**Issue:** `SIEMContextResponse.from_dict()` accepts any float for `risk_score` without validation:
```python
risk_score=float(data.get("risk_score", 0.5)),
```

Values outside 0.0-1.0 could cause unexpected behavior in risk calculations.

**Impact:** Invalid data from SIEM could propagate through the system.

**Recommendation:** Add validation in `__post_init__` or during deserialization.

---

### 4. LOW Priority Issues (6 Found)

#### L1: Import Inside Function (`execution/resurrector.py:192, 256, 410`)

Several functions have imports inside them (`import uuid`, `import random`). While functional, this is not idiomatic Python.

---

#### L2: Hardcoded Mock Health Check Timeout (`execution/resurrector.py:400`)

The mock executor has a hardcoded 0.5 second sleep that isn't configurable.

---

#### L3: Missing Type Hints in Some Functions

Some older functions lack type hints, making the codebase inconsistent.

---

#### L4: Logger Uses F-Strings in Some Places (`core/errors.py:491-492`)

Some logging statements use f-strings instead of lazy formatting:
```python
logger.warning(f"Failed to get module history: {e}")
```

This evaluates the string even if the log level doesn't output it.

---

#### L5: `ValidationError` Defined Twice (`core/validation.py:30`, `core/errors.py:157`)

There are two `ValidationError` classes that could conflict if both are imported.

---

#### L6: No Database Migration Strategy

The SQLite schema is created inline. No migration strategy exists for schema changes.

---

### 5. Positive Findings

#### Security Strengths

1. **Input Validation**: Comprehensive validation in `core/validation.py`:
   - Path traversal prevention (checks for `..`, `/`, `\`)
   - Null byte detection
   - Character whitelist enforcement
   - Length limits (255 chars for names, 100KB for metadata)
   - Evidence list size limits (100 items, 10KB each)

2. **Authentication**: Well-implemented RBAC in `interfaces/auth.py`:
   - SHA-256 hashed API keys
   - Constant-time comparison (though with minor timing leak noted)
   - Role-based permissions (Admin, Operator, Viewer, API)
   - Session management with expiry

3. **Web Security**: Strong middleware in `interfaces/web.py`:
   - CORS validation (rejects wildcard in production, requires HTTPS)
   - Security headers (X-Content-Type-Options, X-Frame-Options, CSP, HSTS)
   - Rate limiting (120 req/min default)
   - Request size limiting (10MB max)
   - Error sanitization in production

4. **SIEM API Key Handling**: Keys must come from environment variables, not config files

5. **Production Safeguards**:
   - Authentication required in production
   - Explicit checks for placeholder API keys
   - HTTPS-only CORS origins in production

#### Architecture Strengths

1. **Clean Separation**: 5 distinct layers (Core, Execution, Interfaces, Learning, Integration)

2. **Strategy Pattern**: Multiple decision engine strategies (conservative, balanced, aggressive)

3. **Circuit Breaker**: Proper implementation for external service resilience

4. **Retry with Backoff**: Exponential backoff with jitter for transient failures

5. **Observer Pattern**: Internal event bus for decoupled components

6. **Phase-Based Rollout**: 7 phases from observer-only to full autonomous mode

#### Test Coverage Strengths

- 36 test files covering unit, integration, security, and performance
- Security-specific tests for injection, path traversal, input validation
- Fixtures for consistent test data
- Async test support

#### Configuration Strengths

- Secure defaults (observer mode, auth required)
- Environment-based secrets
- Constitution file for safety constraints
- Always-require-approval list for critical modules

---

## Fitness for Purpose Assessment

### Intended Purpose
The Medic Agent is designed to:
1. Monitor kill events from Smith (security agent)
2. Query SIEM for threat context
3. Make AI-driven resurrection decisions
4. Execute resurrection workflows
5. Learn from outcomes

### Capability Assessment

| Capability | Status | Notes |
|------------|--------|-------|
| Kill Event Listening | **Implemented** | Redis, RabbitMQ, Kafka support |
| SIEM Integration | **Implemented** | REST adapter with circuit breaker |
| Decision Logic | **Implemented** | Multi-factor risk assessment |
| Risk Assessment | **Implemented** | Weighted scoring, configurable thresholds |
| Resurrection Execution | **Implemented** | Multiple methods (restart, snapshot, redeploy) |
| Health Monitoring | **Implemented** | Post-resurrection anomaly detection |
| Learning System | **Implemented** | Outcome tracking, pattern analysis |
| Human Review Queue | **Implemented** | Approval workflow, timeout handling |
| Web API | **Implemented** | Full REST API with WebSocket |
| Multi-Cluster | **Partial** | Framework present, leader election works |
| Veto Protocol | **Implemented** | Rate-limited veto capability |

### Gaps Identified

1. **No Real AI/ML Model**: The "AI-driven decision" is rule-based weighted scoring, not actual machine learning. This is fine for V1 but may limit adaptive learning.

2. **Mock Executors Only**: The actual resurrection executors are mocks or require Kubernetes. No native Docker Swarm, ECS, or bare-metal support.

3. **Single SIEM Adapter**: Only REST adapter implemented. No native Splunk, Elastic, or vendor-specific adapters.

---

## Recommendations

### Immediate Actions (Before Production)

1. **Fix race condition** in `ModuleResurrector` (H1)
2. **Fix timing leak** in API key validation (H2)
3. **Add validation** for `SIEMContextResponse.risk_score` (M5)

### Short-Term Improvements

1. Implement retry logic for SQLite under contention
2. Add environment check to prevent mock executor in production
3. Consolidate the two `ValidationError` classes
4. Add database migration tooling

### Long-Term Considerations

1. Consider actual ML model for pattern analysis
2. Add vendor-specific SIEM adapters
3. Implement more orchestration backends beyond Kubernetes
4. Add comprehensive integration tests with real Smith/SIEM

---

## Conclusion

The Medic Agent is a **well-engineered system** that demonstrates professional software development practices. The codebase is clean, well-documented, and has comprehensive test coverage. Security has been thoughtfully addressed with input validation, authentication, and production safeguards.

The issues identified are relatively minor and do not pose immediate production risks when deployed with the default "observer" mode. However, **the high-priority issues (H1, H2) should be addressed before running in semi-auto or full-auto modes** where the system makes autonomous decisions.

**The software is fit for its intended purpose** of providing an autonomous resilience layer, with the caveat that the "AI" decision-making is currently rule-based rather than true machine learning. This is appropriate for a v0.1.0-alpha release.

---

*Report generated as part of software audit on branch `claude/audit-software-correctness-W6bgj`*
