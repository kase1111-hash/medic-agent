"""
Medic Agent Web API

FastAPI-based REST API for resurrection approval workflows.
Provides endpoints for queue management and monitoring.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from core.logger import get_logger

logger = get_logger("interfaces.web")

# Try to import FastAPI, but don't fail if not installed
try:
    from fastapi import FastAPI, HTTPException, Query, Body
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.warning("FastAPI not installed. Web interface unavailable.")


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


class WebAPI:
    """
    FastAPI-based web interface for Medic Agent.

    Provides REST endpoints for:
    - Queue management (list, approve, deny)
    - Status and statistics
    - Health checks
    """

    def __init__(
        self,
        approval_queue: Any,
        resurrector: Optional[Any] = None,
        monitor: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required for the web interface. Install with: pip install fastapi uvicorn")

        self.queue = approval_queue
        self.resurrector = resurrector
        self.monitor = monitor
        self.config = config or {}

        self.app = FastAPI(
            title="Medic Agent API",
            description="REST API for resurrection approval workflows",
            version="1.0.0",
        )

        self._setup_routes()

    def _setup_routes(self) -> None:
        """Set up API routes."""
        app = self.app

        # Health check
        @app.get("/health", response_model=HealthResponse)
        async def health_check():
            """Check system health."""
            checks = {
                "queue": "ok",
            }

            if self.resurrector:
                checks["resurrector"] = "ok"
            if self.monitor:
                checks["monitor"] = "ok"

            return HealthResponse(
                status="healthy",
                timestamp=datetime.utcnow().isoformat(),
                checks=checks,
                version="1.0.0",
            )

        # Status
        @app.get("/status")
        async def get_status():
            """Get system status."""
            stats = await self.queue.get_stats()

            status = {
                "mode": "manual",
                "queue": stats,
                "timestamp": datetime.utcnow().isoformat(),
            }

            if self.resurrector:
                status["resurrector"] = self.resurrector.get_statistics()

            if self.monitor:
                status["monitor"] = self.monitor.get_statistics()

            return status

        # Queue endpoints
        @app.get("/api/v1/queue")
        async def list_queue(
            limit: int = Query(50, ge=1, le=100),
            status_filter: Optional[str] = Query(None),
        ):
            """List items in the approval queue."""
            items = await self.queue.list_pending(limit=limit)
            return {
                "items": [item.to_dict() for item in items],
                "count": len(items),
            }

        @app.get("/api/v1/queue/{item_id}")
        async def get_queue_item(item_id: str):
            """Get a specific queue item."""
            item = await self.queue.get_item(item_id)
            if not item:
                raise HTTPException(status_code=404, detail="Item not found")
            return item.to_dict()

        @app.post("/api/v1/queue/{item_id}/approve")
        async def approve_item(item_id: str, request: ApprovalRequest):
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
                    "message": "Proposal approved",
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

                return result

            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        @app.post("/api/v1/queue/{item_id}/deny")
        async def deny_item(item_id: str, request: DenialRequest):
            """Deny a resurrection proposal."""
            try:
                await self.queue.deny(item_id, request.denier, request.reason)
                return {
                    "status": "denied",
                    "message": "Proposal denied",
                }
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        # Stats endpoint
        @app.get("/api/v1/stats")
        async def get_stats():
            """Get queue statistics."""
            return await self.queue.get_stats()

        # Decisions endpoints
        @app.get("/api/v1/decisions")
        async def list_decisions(limit: int = Query(50, ge=1, le=100)):
            """List recent decisions."""
            # This would integrate with the decision logger
            return {"decisions": [], "count": 0}

        # Resurrections endpoints
        @app.get("/api/v1/resurrections")
        async def list_resurrections():
            """List resurrection requests."""
            if not self.resurrector:
                return {"resurrections": [], "count": 0}
            return self.resurrector.get_statistics()

        @app.get("/api/v1/resurrections/{request_id}/status")
        async def get_resurrection_status(request_id: str):
            """Get resurrection request status."""
            if not self.resurrector:
                raise HTTPException(status_code=404, detail="Resurrector not available")

            status = await self.resurrector.get_status(request_id)
            if not status:
                raise HTTPException(status_code=404, detail="Request not found")

            return {"request_id": request_id, "status": status.value}

        @app.post("/api/v1/resurrections/{request_id}/rollback")
        async def rollback_resurrection(
            request_id: str,
            reason: str = Body(..., embed=True),
        ):
            """Trigger rollback of a resurrection."""
            if not self.resurrector:
                raise HTTPException(status_code=404, detail="Resurrector not available")

            success = await self.resurrector.rollback(request_id, reason)
            if not success:
                raise HTTPException(status_code=400, detail="Rollback failed")

            return {"status": "rolled_back", "reason": reason}

        # Monitor endpoints
        @app.get("/api/v1/monitors")
        async def list_monitors():
            """List active monitoring sessions."""
            if not self.monitor:
                return {"monitors": [], "count": 0}

            sessions = self.monitor.get_active_sessions()
            return {
                "monitors": [s.to_dict() for s in sessions],
                "count": len(sessions),
            }

        @app.get("/api/v1/monitors/{monitor_id}")
        async def get_monitor(monitor_id: str):
            """Get monitoring session details."""
            if not self.monitor:
                raise HTTPException(status_code=404, detail="Monitor not available")

            session = self.monitor.get_session(monitor_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")

            result = session.to_dict()
            result["anomalies"] = [a.to_dict() for a in session.anomalies]
            return result

        @app.post("/api/v1/monitors/{monitor_id}/stop")
        async def stop_monitor(monitor_id: str):
            """Stop a monitoring session."""
            if not self.monitor:
                raise HTTPException(status_code=404, detail="Monitor not available")

            result = await self.monitor.stop_monitoring(monitor_id)
            return result


def create_web_app(
    approval_queue: Any,
    config: Dict[str, Any],
    resurrector: Optional[Any] = None,
    monitor: Optional[Any] = None,
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
        config=web_config,
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
