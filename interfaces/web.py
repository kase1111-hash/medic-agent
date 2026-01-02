"""
Medic Agent Web API

FastAPI-based REST API for resurrection approval workflows.
Provides complete endpoints for queue management, decisions, outcomes,
configuration, and reporting.

Phase 6: Production Readiness - Complete REST API implementation.
Security: Implements API key authentication and RBAC.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import defaultdict
import time
import os

from core.logger import get_logger

logger = get_logger("interfaces.web")


class RateLimiter:
    """Simple in-memory rate limiter for API endpoints."""

    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        """Check if a request from client_id is allowed."""
        now = time.time()
        minute_ago = now - 60

        # Clean old requests
        self.requests[client_id] = [
            ts for ts in self.requests[client_id] if ts > minute_ago
        ]

        if len(self.requests[client_id]) >= self.requests_per_minute:
            return False

        self.requests[client_id].append(now)
        return True


# Global rate limiter instance
_rate_limiter = RateLimiter(requests_per_minute=120)

# Try to import FastAPI, but don't fail if not installed
try:
    from fastapi import FastAPI, HTTPException, Query, Body, Path, Request, Depends, Security
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from starlette.middleware.base import BaseHTTPMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.warning("FastAPI not installed. Web interface unavailable.")

# Import authentication module
try:
    from interfaces.auth import (
        verify_api_key, require_permission, require_role,
        Permission, Role, APIKey, get_api_key_store
    )
    AUTH_AVAILABLE = FASTAPI_AVAILABLE
except ImportError:
    AUTH_AVAILABLE = False
    if FASTAPI_AVAILABLE:
        logger.warning("Auth module not available, API will run without authentication!")


# Pydantic models for request/response validation
if FASTAPI_AVAILABLE:
    class ApprovalRequest(BaseModel):
        """Request body for approval."""
        approver: str
        notes: Optional[str] = None

    class DenialRequest(BaseModel):
        """Request body for denial."""
        denier: str
        reason: str

    class HealthResponse(BaseModel):
        """Health check response."""
        status: str
        timestamp: str
        checks: Dict[str, str]
        version: str
        uptime_seconds: Optional[float] = None

    class APIResponse(BaseModel):
        """Standard API response wrapper."""
        success: bool
        data: Any
        meta: Dict[str, Any]
        errors: List[str] = Field(default_factory=list)

    class ThresholdUpdate(BaseModel):
        """Request body for threshold updates."""
        key: str
        value: float
        reason: Optional[str] = None

    class FeedbackRequest(BaseModel):
        """Request body for feedback submission."""
        outcome_id: str
        feedback_type: str
        value: Any
        submitted_by: str
        comment: Optional[str] = None


class WebAPI:
    """
    FastAPI-based web interface for Medic Agent.

    Provides complete REST API per spec section 9.1:
    - Health and status endpoints
    - Queue management (list, approve, deny)
    - Decision history
    - Resurrection tracking
    - Outcome reporting
    - Configuration management
    - Reports generation
    """

    def __init__(
        self,
        approval_queue: Any,
        resurrector: Optional[Any] = None,
        monitor: Optional[Any] = None,
        decision_logger: Optional[Any] = None,
        outcome_store: Optional[Any] = None,
        report_generator: Optional[Any] = None,
        feedback_processor: Optional[Any] = None,
        threshold_adapter: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required for the web interface. Install with: pip install fastapi uvicorn")

        self.queue = approval_queue
        self.resurrector = resurrector
        self.monitor = monitor
        self.decision_logger = decision_logger
        self.outcome_store = outcome_store
        self.report_generator = report_generator
        self.feedback_processor = feedback_processor
        self.threshold_adapter = threshold_adapter
        self.config = config or {}
        self._start_time = datetime.utcnow()

        self.app = FastAPI(
            title="Medic Agent API",
            description="REST API for resurrection approval workflows and system management",
            version="0.1.0-alpha",
            docs_url="/docs",
            redoc_url="/redoc",
        )

        # Check for authentication in production
        environment = self.config.get("environment", os.environ.get("MEDIC_ENV", "development"))
        if not AUTH_AVAILABLE and environment == "production":
            logger.critical("CRITICAL: Authentication not available in production!")
            raise RuntimeError("Cannot run in production without authentication")

        if not AUTH_AVAILABLE:
            logger.warning(
                "⚠️  API RUNNING WITHOUT AUTHENTICATION - NOT FOR PRODUCTION USE ⚠️"
            )

        # Add CORS middleware
        # SECURITY: In production, configure specific origins via cors_origins config
        cors_origins = self.config.get("cors_origins", [])
        if not cors_origins:
            # Default to restrictive policy - only same-origin requests allowed
            cors_origins = []

        # Validate CORS configuration in production
        if environment == "production":
            if "*" in cors_origins:
                logger.critical("WILDCARD CORS IN PRODUCTION - SECURITY RISK!")
                raise ValueError("Wildcard CORS not allowed in production")
            # Ensure all origins use HTTPS in production
            for origin in cors_origins:
                if not origin.startswith("https://"):
                    logger.error(f"Non-HTTPS CORS origin in production: {origin}")
                    raise ValueError(f"Only HTTPS origins allowed in production, got: {origin}")

        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
        )

        # Add rate limiting middleware
        self._add_rate_limiting_middleware()

        # Add security headers middleware
        self._add_security_headers_middleware()

        self._setup_routes()

    def _add_rate_limiting_middleware(self) -> None:
        """Add rate limiting middleware."""
        if not FASTAPI_AVAILABLE:
            return

        class RateLimitMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next):
                # Skip rate limiting for health check
                if request.url.path == "/health":
                    return await call_next(request)

                # Use client IP as identifier
                client_id = request.client.host if request.client else "unknown"

                # Check rate limit
                if not _rate_limiter.is_allowed(client_id):
                    logger.warning(f"Rate limit exceeded for {client_id}")
                    raise HTTPException(
                        status_code=429,
                        detail="Rate limit exceeded. Please try again later.",
                        headers={"Retry-After": "60"},
                    )

                response = await call_next(request)
                return response

        self.app.add_middleware(RateLimitMiddleware)
        logger.info("Rate limiting middleware enabled")

    def _add_security_headers_middleware(self) -> None:
        """Add security headers to all responses."""
        if not FASTAPI_AVAILABLE:
            return

        @self.app.middleware("http")
        async def add_security_headers(request: Request, call_next):
            response = await call_next(request)

            # Security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

            # HSTS in production
            environment = self.config.get("environment", os.environ.get("MEDIC_ENV", "development"))
            if environment == "production":
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

            # Content Security Policy
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"

            return response

        logger.info("Security headers middleware enabled")

    def _wrap_response(self, data: Any, errors: Optional[List[str]] = None) -> Dict[str, Any]:
        """Wrap response in standard format."""
        return {
            "success": not errors,
            "data": data,
            "meta": {
                "timestamp": datetime.utcnow().isoformat(),
                "version": "0.1.0-alpha",
            },
            "errors": errors or [],
        }

    def _setup_routes(self) -> None:
        """Set up API routes."""
        app = self.app

        # ==================== Health & Status ====================

        @app.get("/health", response_model=HealthResponse, tags=["Health"])
        async def health_check():
            """
            Check system health.

            Returns health status of all components.
            """
            checks = {"queue": "ok"}

            if self.resurrector:
                checks["resurrector"] = "ok"
            if self.monitor:
                checks["monitor"] = "ok"
            if self.outcome_store:
                checks["outcome_store"] = "ok"
            if self.decision_logger:
                checks["decision_logger"] = "ok"

            uptime = (datetime.utcnow() - self._start_time).total_seconds()

            return HealthResponse(
                status="healthy",
                timestamp=datetime.utcnow().isoformat(),
                checks=checks,
                version="6.0.0",
                uptime_seconds=round(uptime, 1),
            )

        # Status endpoint - requires authentication in production
        if AUTH_AVAILABLE:
            @app.get("/status", tags=["Health"], dependencies=[Depends(require_permission(Permission.VIEW_QUEUE))])
            async def get_status(current_user: APIKey = Security(verify_api_key)):
                """Get comprehensive system status. Requires authentication."""
                stats = await self.queue.get_stats()

                status = {
                    "mode": self.config.get("mode", "observer"),
                    "queue": stats,
                    "uptime_seconds": round((datetime.utcnow() - self._start_time).total_seconds(), 1),
                    "timestamp": datetime.utcnow().isoformat(),
                    "authenticated_as": current_user.key_id,
                }

                if self.resurrector:
                    status["resurrector"] = self.resurrector.get_statistics()

                if self.monitor:
                    status["monitor"] = self.monitor.get_statistics()

                if self.outcome_store:
                    try:
                        status["outcomes"] = self.outcome_store.get_statistics().to_dict()
                    except Exception:
                        status["outcomes"] = {"error": "unavailable"}

                return self._wrap_response(status)
        else:
            @app.get("/status", tags=["Health"])
            async def get_status():
                """Get comprehensive system status. ⚠️  NO AUTHENTICATION."""
                stats = await self.queue.get_stats()

                status = {
                    "mode": self.config.get("mode", "observer"),
                    "queue": stats,
                    "uptime_seconds": round((datetime.utcnow() - self._start_time).total_seconds(), 1),
                    "timestamp": datetime.utcnow().isoformat(),
                    "warning": "API running without authentication - not for production!",
                }

                if self.resurrector:
                    status["resurrector"] = self.resurrector.get_statistics()

                if self.monitor:
                    status["monitor"] = self.monitor.get_statistics()

                if self.outcome_store:
                    try:
                        status["outcomes"] = self.outcome_store.get_statistics().to_dict()
                    except Exception:
                        status["outcomes"] = {"error": "unavailable"}

                return self._wrap_response(status)

        # ==================== Queue Endpoints ====================

        if AUTH_AVAILABLE:
            @app.get("/api/v1/queue", tags=["Queue"], dependencies=[Depends(require_permission(Permission.VIEW_QUEUE))])
            async def list_queue(
                limit: int = Query(50, ge=1, le=100, description="Maximum items to return"),
                status_filter: Optional[str] = Query(None, description="Filter by status"),
            ):
                """List items in the approval queue. Requires VIEW_QUEUE permission."""
                items = await self.queue.list_pending(limit=limit)
                return self._wrap_response({
                    "items": [item.to_dict() for item in items],
                    "count": len(items),
                })

            @app.get("/api/v1/queue/{item_id}", tags=["Queue"], dependencies=[Depends(require_permission(Permission.VIEW_QUEUE))])
            async def get_queue_item(item_id: str = Path(..., description="Queue item ID")):
                """Get a specific queue item. Requires VIEW_QUEUE permission."""
            item = await self.queue.get_item(item_id)
            if not item:
                raise HTTPException(status_code=404, detail="Item not found")
            return self._wrap_response(item.to_dict())

        @app.post("/api/v1/queue/{item_id}/approve", tags=["Queue"])
        async def approve_item(
            item_id: str = Path(..., description="Queue item ID"),
            request: ApprovalRequest = Body(...),
        ):
            """Approve a resurrection proposal."""
            try:
                resurrection_request = await self.queue.approve(
                    item_id,
                    request.approver,
                    request.notes,
                )

                result = {
                    "status": "approved",
                    "request_id": resurrection_request.request_id,
                    "approved_by": request.approver,
                    "approved_at": datetime.utcnow().isoformat(),
                }

                # Execute resurrection if resurrector is available
                if self.resurrector:
                    res_result = await self.resurrector.resurrect(resurrection_request)
                    result["resurrection"] = res_result.to_dict()

                    # Start monitoring if available and resurrection succeeded
                    if self.monitor and res_result.success:
                        monitor_id = await self.monitor.start_monitoring(
                            resurrection_request,
                            duration_minutes=30,
                        )
                        result["monitor_id"] = monitor_id

                return self._wrap_response(result)

            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        @app.post("/api/v1/queue/{item_id}/deny", tags=["Queue"])
        async def deny_item(
            item_id: str = Path(..., description="Queue item ID"),
            request: DenialRequest = Body(...),
        ):
            """Deny a resurrection proposal."""
            try:
                await self.queue.deny(item_id, request.denier, request.reason)
                return self._wrap_response({
                    "status": "denied",
                    "denied_by": request.denier,
                    "reason": request.reason,
                    "denied_at": datetime.utcnow().isoformat(),
                })
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        # ==================== Decisions Endpoints ====================

        @app.get("/api/v1/decisions", tags=["Decisions"])
        async def list_decisions(
            limit: int = Query(50, ge=1, le=100),
            offset: int = Query(0, ge=0),
            outcome: Optional[str] = Query(None, description="Filter by outcome"),
        ):
            """List recent resurrection decisions."""
            if not self.decision_logger:
                return self._wrap_response({"decisions": [], "count": 0, "total": 0})

            try:
                decisions = self.decision_logger.get_recent_decisions(limit=limit)
                if outcome:
                    decisions = [d for d in decisions if d.outcome.value == outcome]

                return self._wrap_response({
                    "decisions": [d.to_dict() for d in decisions],
                    "count": len(decisions),
                    "limit": limit,
                    "offset": offset,
                })
            except Exception as e:
                logger.error(f"Error listing decisions: {e}")
                return self._wrap_response({"decisions": [], "count": 0}, errors=[str(e)])

        @app.get("/api/v1/decisions/{decision_id}", tags=["Decisions"])
        async def get_decision(decision_id: str = Path(..., description="Decision ID")):
            """Get a specific decision."""
            if not self.decision_logger:
                raise HTTPException(status_code=404, detail="Decision logger not available")

            decision = self.decision_logger.get_decision(decision_id)
            if not decision:
                raise HTTPException(status_code=404, detail="Decision not found")

            return self._wrap_response(decision.to_dict())

        # ==================== Resurrections Endpoints ====================

        @app.get("/api/v1/resurrections", tags=["Resurrections"])
        async def list_resurrections(
            limit: int = Query(50, ge=1, le=100),
            status: Optional[str] = Query(None, description="Filter by status"),
        ):
            """List resurrection requests."""
            if not self.resurrector:
                return self._wrap_response({"resurrections": [], "count": 0})

            stats = self.resurrector.get_statistics()
            return self._wrap_response(stats)

        @app.get("/api/v1/resurrections/{request_id}", tags=["Resurrections"])
        async def get_resurrection(request_id: str = Path(..., description="Request ID")):
            """Get resurrection request details."""
            if not self.resurrector:
                raise HTTPException(status_code=404, detail="Resurrector not available")

            request = self.resurrector.get_request(request_id)
            if not request:
                raise HTTPException(status_code=404, detail="Request not found")

            return self._wrap_response(request.to_dict())

        @app.get("/api/v1/resurrections/{request_id}/status", tags=["Resurrections"])
        async def get_resurrection_status(request_id: str = Path(..., description="Request ID")):
            """Get resurrection request status."""
            if not self.resurrector:
                raise HTTPException(status_code=404, detail="Resurrector not available")

            status = await self.resurrector.get_status(request_id)
            if not status:
                raise HTTPException(status_code=404, detail="Request not found")

            return self._wrap_response({"request_id": request_id, "status": status.value})

        @app.post("/api/v1/resurrections/{request_id}/rollback", tags=["Resurrections"])
        async def rollback_resurrection(
            request_id: str = Path(..., description="Request ID"),
            reason: str = Body(..., embed=True),
        ):
            """Trigger rollback of a resurrection."""
            if not self.resurrector:
                raise HTTPException(status_code=404, detail="Resurrector not available")

            success = await self.resurrector.rollback(request_id, reason)
            if not success:
                raise HTTPException(status_code=400, detail="Rollback failed")

            return self._wrap_response({
                "status": "rolled_back",
                "request_id": request_id,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat(),
            })

        # ==================== Outcomes Endpoints ====================

        @app.get("/api/v1/outcomes", tags=["Outcomes"])
        async def list_outcomes(
            limit: int = Query(100, ge=1, le=500),
            module: Optional[str] = Query(None, description="Filter by module"),
            outcome_type: Optional[str] = Query(None, description="Filter by outcome type"),
        ):
            """List resurrection outcomes."""
            if not self.outcome_store:
                return self._wrap_response({"outcomes": [], "count": 0})

            try:
                outcomes = self.outcome_store.get_recent_outcomes(limit=limit)

                if module:
                    outcomes = [o for o in outcomes if o.target_module == module]
                if outcome_type:
                    outcomes = [o for o in outcomes if o.outcome_type.value == outcome_type]

                return self._wrap_response({
                    "outcomes": [o.to_dict() for o in outcomes],
                    "count": len(outcomes),
                })
            except Exception as e:
                logger.error(f"Error listing outcomes: {e}")
                return self._wrap_response({"outcomes": [], "count": 0}, errors=[str(e)])

        @app.get("/api/v1/outcomes/stats", tags=["Outcomes"])
        async def get_outcome_stats():
            """Get outcome statistics."""
            if not self.outcome_store:
                return self._wrap_response({"error": "Outcome store not available"})

            try:
                stats = self.outcome_store.get_statistics()
                return self._wrap_response(stats.to_dict())
            except Exception as e:
                logger.error(f"Error getting outcome stats: {e}")
                return self._wrap_response({}, errors=[str(e)])

        @app.get("/api/v1/outcomes/{outcome_id}", tags=["Outcomes"])
        async def get_outcome(outcome_id: str = Path(..., description="Outcome ID")):
            """Get a specific outcome."""
            if not self.outcome_store:
                raise HTTPException(status_code=404, detail="Outcome store not available")

            outcome = self.outcome_store.get_outcome(outcome_id)
            if not outcome:
                raise HTTPException(status_code=404, detail="Outcome not found")

            return self._wrap_response(outcome.to_dict())

        # ==================== Feedback Endpoints ====================

        @app.post("/api/v1/feedback", tags=["Feedback"])
        async def submit_feedback(request: FeedbackRequest = Body(...)):
            """Submit feedback for an outcome."""
            if not self.feedback_processor:
                raise HTTPException(status_code=404, detail="Feedback processor not available")

            try:
                from learning.feedback import FeedbackType
                feedback = self.feedback_processor.submit_feedback(
                    outcome_id=request.outcome_id,
                    feedback_type=FeedbackType(request.feedback_type),
                    value=request.value,
                    submitted_by=request.submitted_by,
                    comment=request.comment,
                )
                return self._wrap_response({
                    "feedback_id": feedback.feedback_id,
                    "status": "submitted",
                })
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        @app.get("/api/v1/feedback/stats", tags=["Feedback"])
        async def get_feedback_stats():
            """Get feedback statistics."""
            if not self.feedback_processor:
                return self._wrap_response({"error": "Feedback processor not available"})

            stats = self.feedback_processor.get_statistics()
            return self._wrap_response(stats.to_dict())

        # ==================== Configuration Endpoints ====================

        @app.get("/api/v1/config", tags=["Configuration"])
        async def get_config():
            """Get current configuration (sanitized)."""
            # Return sanitized config (no secrets)
            safe_config = {
                "mode": self.config.get("mode", {}),
                "decision": self.config.get("decision", {}),
                "risk": self.config.get("risk", {}),
                "resurrection": self.config.get("resurrection", {}),
                "learning": {
                    "enabled": self.config.get("learning", {}).get("enabled", False),
                },
            }
            return self._wrap_response(safe_config)

        @app.get("/api/v1/config/thresholds", tags=["Configuration"])
        async def get_thresholds():
            """Get current risk thresholds."""
            if self.threshold_adapter:
                thresholds = self.threshold_adapter.get_current_thresholds()
                return self._wrap_response(thresholds.to_dict())

            risk_config = self.config.get("risk", {})
            return self._wrap_response({
                "thresholds": risk_config.get("thresholds", {}),
                "weights": risk_config.get("weights", {}),
            })

        @app.put("/api/v1/config/thresholds", tags=["Configuration"])
        async def update_threshold(update: ThresholdUpdate = Body(...)):
            """Update a risk threshold."""
            if not self.threshold_adapter:
                raise HTTPException(status_code=404, detail="Threshold adapter not available")

            try:
                self.threshold_adapter.manual_update(
                    update.key,
                    update.value,
                    reason=update.reason or "API update",
                )
                return self._wrap_response({
                    "status": "updated",
                    "key": update.key,
                    "new_value": update.value,
                })
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        # ==================== Reports Endpoints ====================

        @app.get("/api/v1/reports/daily", tags=["Reports"])
        async def get_daily_report(date: Optional[str] = Query(None, description="Date (YYYY-MM-DD)")):
            """Get daily summary report."""
            if not self.report_generator:
                raise HTTPException(status_code=404, detail="Report generator not available")

            try:
                if date:
                    from datetime import datetime as dt
                    report_date = dt.strptime(date, "%Y-%m-%d").date()
                    summary = self.report_generator.generate_daily_summary(report_date)
                else:
                    summary = self.report_generator.generate_daily_summary()

                return self._wrap_response(summary.to_dict())
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")

        @app.get("/api/v1/reports/weekly", tags=["Reports"])
        async def get_weekly_report():
            """Get weekly analysis report."""
            if not self.report_generator:
                raise HTTPException(status_code=404, detail="Report generator not available")

            try:
                report = self.report_generator.generate_weekly_report()
                return self._wrap_response(report.to_dict())
            except Exception as e:
                logger.error(f"Error generating weekly report: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/v1/reports/module/{module_name}", tags=["Reports"])
        async def get_module_report(
            module_name: str = Path(..., description="Module name"),
            days: int = Query(30, ge=1, le=90),
        ):
            """Get report for a specific module."""
            if not self.report_generator:
                raise HTTPException(status_code=404, detail="Report generator not available")

            try:
                report = self.report_generator.generate_module_report(module_name, days=days)
                return self._wrap_response(report.to_dict())
            except Exception as e:
                logger.error(f"Error generating module report: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ==================== Monitor Endpoints ====================

        @app.get("/api/v1/monitors", tags=["Monitoring"])
        async def list_monitors():
            """List active monitoring sessions."""
            if not self.monitor:
                return self._wrap_response({"monitors": [], "count": 0})

            sessions = self.monitor.get_active_sessions()
            return self._wrap_response({
                "monitors": [s.to_dict() for s in sessions],
                "count": len(sessions),
            })

        @app.get("/api/v1/monitors/{monitor_id}", tags=["Monitoring"])
        async def get_monitor(monitor_id: str = Path(..., description="Monitor ID")):
            """Get monitoring session details."""
            if not self.monitor:
                raise HTTPException(status_code=404, detail="Monitor not available")

            session = self.monitor.get_session(monitor_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")

            result = session.to_dict()
            result["anomalies"] = [a.to_dict() for a in session.anomalies]
            return self._wrap_response(result)

        @app.post("/api/v1/monitors/{monitor_id}/stop", tags=["Monitoring"])
        async def stop_monitor(monitor_id: str = Path(..., description="Monitor ID")):
            """Stop a monitoring session."""
            if not self.monitor:
                raise HTTPException(status_code=404, detail="Monitor not available")

            result = await self.monitor.stop_monitoring(monitor_id)
            return self._wrap_response(result)

        # ==================== Metrics Endpoint ====================

        @app.get("/api/v1/metrics", tags=["Metrics"])
        async def get_metrics():
            """Get Prometheus metrics."""
            try:
                from core.metrics import get_metrics
                metrics = get_metrics()
                if metrics:
                    return self._wrap_response(metrics.get_internal_metrics())
                return self._wrap_response({})
            except ImportError:
                return self._wrap_response({"error": "Metrics not available"})


def create_web_app(
    approval_queue: Any,
    config: Dict[str, Any],
    resurrector: Optional[Any] = None,
    monitor: Optional[Any] = None,
    decision_logger: Optional[Any] = None,
    outcome_store: Optional[Any] = None,
    report_generator: Optional[Any] = None,
    feedback_processor: Optional[Any] = None,
    threshold_adapter: Optional[Any] = None,
) -> Optional[Any]:
    """Factory function to create web application."""
    if not FASTAPI_AVAILABLE:
        logger.warning("FastAPI not available, web interface disabled")
        return None

    web_config = config.get("interfaces", {}).get("web", {})

    if not web_config.get("enabled", False):
        return None

    api = WebAPI(
        approval_queue=approval_queue,
        resurrector=resurrector,
        monitor=monitor,
        decision_logger=decision_logger,
        outcome_store=outcome_store,
        report_generator=report_generator,
        feedback_processor=feedback_processor,
        threshold_adapter=threshold_adapter,
        config={**web_config, **config},
    )

    return api.app


async def run_web_server(
    app: Any,
    host: str = "0.0.0.0",
    port: int = 8000,
) -> None:
    """Run the web server."""
    try:
        import uvicorn
        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()
    except ImportError:
        logger.error("uvicorn not installed. Install with: pip install uvicorn")
        raise
