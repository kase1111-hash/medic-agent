"""
Integration Tests - Web Interface

End-to-end tests for the web API and WebSocket functionality.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import json

# Mock starlette WebSocketState before importing
import sys
from unittest.mock import MagicMock as MockMagicMock

if "starlette.websockets" not in sys.modules:
    mock_module = MockMagicMock()
    mock_module.WebSocketState = MockMagicMock()
    mock_module.WebSocketState.CONNECTED = "connected"
    mock_module.WebSocketState.DISCONNECTED = "disconnected"
    sys.modules["starlette.websockets"] = mock_module

from core.models import (
    KillReport,
    KillReason,
    Severity,
    DecisionOutcome,
    RiskLevel,
    ResurrectionRequest,
)
from core.decision import create_decision_engine
from core.risk import create_risk_assessor
from core.siem_interface import SIEMContextResponse
from execution.resurrector import create_resurrector, ResurrectionStatus
from execution.recommendation import create_recommendation_engine
from interfaces.approval_queue import create_approval_queue


# Skip tests if FastAPI/Starlette not available
try:
    from fastapi.testclient import TestClient
    from interfaces.web import WebAPI, WebSocketManager, get_ws_manager
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


@pytest.fixture
def web_config():
    """Web interface configuration for testing."""
    return {
        "mode": {
            "current": "semi_auto",
            "fallback": "observer",
        },
        "interfaces": {
            "web": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 8000,
                "cors_origins": [],
                "rate_limit_per_minute": 120,
            },
            "approval_queue": {
                "max_pending": 100,
                "timeout_hours": 24,
            },
        },
        "decision": {
            "default_timeout_minutes": 60,
            "confidence_threshold": 0.7,
            "auto_approve": {
                "enabled": True,
                "max_risk_level": "low",
                "min_confidence": 0.85,
            },
        },
        "risk": {
            "thresholds": {
                "minimal": 0.2,
                "low": 0.4,
                "medium": 0.6,
                "high": 0.8,
            },
            "weights": {
                "smith_confidence": 0.3,
                "siem_risk_score": 0.25,
                "false_positive_history": 0.2,
                "module_criticality": 0.15,
                "time_of_day": 0.1,
            },
        },
        "resurrection": {
            "monitoring_duration_minutes": 30,
            "health_check_interval_seconds": 30,
            "max_retry_attempts": 2,
        },
    }


@pytest.fixture
def sample_kill_report():
    """Sample kill report for testing."""
    return KillReport(
        kill_id="web-test-001",
        timestamp=datetime.now(timezone.utc),
        target_module="test-service",
        target_instance_id="test-001",
        kill_reason=KillReason.RESOURCE_EXHAUSTION,
        severity=Severity.LOW,
        confidence_score=0.5,
        evidence=["memory-spike"],
        dependencies=[],
        source_agent="smith-01",
        metadata={},
    )


@pytest.fixture
def sample_siem_context():
    """Sample SIEM context for testing."""
    return SIEMContextResponse(
        query_id="web-query-001",
        kill_id="web-test-001",
        timestamp=datetime.now(timezone.utc),
        threat_indicators=[],
        historical_behavior={"stability_score": 0.95},
        false_positive_history=5,
        network_context={},
        user_context=None,
        risk_score=0.15,
        recommendation="low_risk",
    )


@pytest.fixture
def approval_queue(web_config):
    """Create approval queue for testing."""
    return create_approval_queue(web_config)


@pytest.fixture
def decision_engine(web_config):
    """Create decision engine for testing."""
    return create_decision_engine(web_config)


@pytest.fixture
def recommendation_engine(web_config):
    """Create recommendation engine for testing."""
    return create_recommendation_engine(web_config, decision_logger=None)


@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
class TestWebAPIEndpoints:
    """Test WebAPI REST endpoints."""

    @pytest.fixture
    def web_api(self, web_config, approval_queue):
        """Create WebAPI instance for testing."""
        return WebAPI(
            config=web_config,
            approval_queue=approval_queue,
            mode_getter=lambda: "semi_auto",
            mode_setter=lambda m: None,
        )

    @pytest.fixture
    def client(self, web_api):
        """Create test client for WebAPI."""
        return TestClient(web_api.app)

    def test_health_endpoint(self, client):
        """Test /health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data

    def test_status_endpoint(self, client):
        """Test /api/v1/status endpoint."""
        response = client.get("/api/v1/status")
        assert response.status_code == 200
        data = response.json()
        assert "mode" in data
        assert "queue_depth" in data
        assert "health" in data

    def test_queue_list_empty(self, client):
        """Test /api/v1/queue endpoint with empty queue."""
        response = client.get("/api/v1/queue")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert len(data["items"]) == 0

    def test_mode_get(self, client):
        """Test GET /api/v1/mode endpoint."""
        response = client.get("/api/v1/mode")
        assert response.status_code == 200
        data = response.json()
        assert "current" in data
        assert data["current"] == "semi_auto"

    def test_mode_set(self, client):
        """Test POST /api/v1/mode endpoint."""
        response = client.post("/api/v1/mode", json={"mode": "observer"})
        assert response.status_code == 200
        data = response.json()
        assert "success" in data

    def test_mode_set_invalid(self, client):
        """Test POST /api/v1/mode with invalid mode."""
        response = client.post("/api/v1/mode", json={"mode": "invalid_mode"})
        assert response.status_code in (400, 422)

    def test_thresholds_get(self, client):
        """Test GET /api/v1/thresholds endpoint."""
        response = client.get("/api/v1/thresholds")
        assert response.status_code == 200
        data = response.json()
        # Should return current thresholds or empty dict
        assert isinstance(data, dict)


@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
class TestWebAPIQueueOperations:
    """Test queue-related API operations."""

    @pytest.fixture
    def web_api(self, web_config, approval_queue):
        """Create WebAPI instance for testing."""
        return WebAPI(
            config=web_config,
            approval_queue=approval_queue,
            mode_getter=lambda: "semi_auto",
            mode_setter=lambda m: None,
        )

    @pytest.fixture
    def client(self, web_api):
        """Create test client for WebAPI."""
        return TestClient(web_api.app)

    @pytest.mark.asyncio
    async def test_queue_item_lifecycle(
        self,
        web_config,
        approval_queue,
        decision_engine,
        recommendation_engine,
        sample_kill_report,
        sample_siem_context,
    ):
        """Test the complete lifecycle of a queue item via API."""
        # Create a proposal and enqueue it
        decision = decision_engine.should_resurrect(
            sample_kill_report,
            sample_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            sample_kill_report,
            sample_siem_context,
            decision,
        )

        item_id = await approval_queue.enqueue(proposal)
        assert item_id is not None

        # Create API and test client
        web_api = WebAPI(
            config=web_config,
            approval_queue=approval_queue,
            mode_getter=lambda: "semi_auto",
            mode_setter=lambda m: None,
        )
        client = TestClient(web_api.app)

        # Verify item appears in queue
        response = client.get("/api/v1/queue")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) >= 1

        # Get specific item
        response = client.get(f"/api/v1/queue/{item_id}")
        assert response.status_code == 200
        item_data = response.json()
        assert item_data["item_id"] == item_id

    @pytest.mark.asyncio
    async def test_approve_queue_item(
        self,
        web_config,
        approval_queue,
        decision_engine,
        recommendation_engine,
        sample_kill_report,
        sample_siem_context,
    ):
        """Test approving a queue item via API."""
        # Enqueue a proposal
        decision = decision_engine.should_resurrect(
            sample_kill_report,
            sample_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            sample_kill_report,
            sample_siem_context,
            decision,
        )

        item_id = await approval_queue.enqueue(proposal)

        # Create API and approve
        web_api = WebAPI(
            config=web_config,
            approval_queue=approval_queue,
            mode_getter=lambda: "semi_auto",
            mode_setter=lambda m: None,
        )
        client = TestClient(web_api.app)

        response = client.post(
            f"/api/v1/queue/{item_id}/approve",
            json={"approver": "test-user", "notes": "Approved via API test"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "request" in data

    @pytest.mark.asyncio
    async def test_deny_queue_item(
        self,
        web_config,
        approval_queue,
        decision_engine,
        recommendation_engine,
        sample_kill_report,
        sample_siem_context,
    ):
        """Test denying a queue item via API."""
        # Enqueue a proposal
        decision = decision_engine.should_resurrect(
            sample_kill_report,
            sample_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            sample_kill_report,
            sample_siem_context,
            decision,
        )

        item_id = await approval_queue.enqueue(proposal)

        # Create API and deny
        web_api = WebAPI(
            config=web_config,
            approval_queue=approval_queue,
            mode_getter=lambda: "semi_auto",
            mode_setter=lambda m: None,
        )
        client = TestClient(web_api.app)

        response = client.post(
            f"/api/v1/queue/{item_id}/deny",
            json={"denier": "test-user", "reason": "Denied via API test"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
class TestWebSocketManager:
    """Test WebSocket manager functionality."""

    @pytest.fixture
    def ws_manager(self):
        """Create fresh WebSocketManager."""
        return WebSocketManager()

    @pytest.fixture
    def mock_websocket(self):
        """Create mock WebSocket."""
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()
        ws.client_state = "connected"
        return ws

    @pytest.mark.asyncio
    async def test_multiple_clients_broadcast(self, ws_manager):
        """Test broadcasting to multiple connected clients."""
        from interfaces.web import WebSocketEventType

        # Connect multiple clients
        clients = []
        for i in range(5):
            ws = AsyncMock()
            ws.accept = AsyncMock()
            ws.send_json = AsyncMock()
            ws.client_state = "connected"
            await ws_manager.connect(ws, f"client-{i}", ["all"])
            clients.append(ws)

        assert ws_manager.get_connection_count() == 5

        # Broadcast
        sent_count = await ws_manager.broadcast(
            WebSocketEventType.SYSTEM_STATUS,
            {"status": "healthy"},
        )

        assert sent_count == 5
        for client in clients:
            client.send_json.assert_called()

    @pytest.mark.asyncio
    async def test_topic_isolation(self, ws_manager):
        """Test that topic subscriptions are properly isolated."""
        from interfaces.web import WebSocketEventType

        # Client 1 subscribes to queue only
        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.send_json = AsyncMock()
        ws1.client_state = "connected"
        await ws_manager.connect(ws1, "queue-client", ["queue"])

        # Client 2 subscribes to decisions only
        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        ws2.send_json = AsyncMock()
        ws2.client_state = "connected"
        await ws_manager.connect(ws2, "decision-client", ["decisions"])

        # Broadcast to queue topic
        await ws_manager.broadcast(
            WebSocketEventType.QUEUE_ITEM_ADDED,
            {"item_id": "test"},
            topic="queue",
        )

        # Only queue client should receive
        ws1.send_json.assert_called()
        assert ws2.send_json.call_count == 0

        # Reset mock
        ws1.send_json.reset_mock()

        # Broadcast to decisions topic
        await ws_manager.broadcast(
            WebSocketEventType.DECISION_MADE,
            {"decision_id": "test"},
            topic="decisions",
        )

        # Only decision client should receive
        ws2.send_json.assert_called()
        assert ws1.send_json.call_count == 0

    @pytest.mark.asyncio
    async def test_client_disconnect_cleanup(self, ws_manager, mock_websocket):
        """Test that disconnected clients are properly cleaned up."""
        await ws_manager.connect(mock_websocket, "test-client")
        assert ws_manager.get_connection_count() == 1

        await ws_manager.disconnect("test-client")
        assert ws_manager.get_connection_count() == 0

        # Sending should fail gracefully
        result = await ws_manager.send_to_client("test-client", {"test": True})
        assert result is False


@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
class TestWebAPIWithResurrection:
    """Test WebAPI with resurrection execution."""

    @pytest.fixture
    def resurrector(self, web_config):
        """Create resurrector for testing."""
        return create_resurrector(web_config)

    @pytest.mark.asyncio
    async def test_approve_and_resurrect_flow(
        self,
        web_config,
        approval_queue,
        decision_engine,
        recommendation_engine,
        resurrector,
        sample_kill_report,
        sample_siem_context,
    ):
        """Test the complete flow from queue approval to resurrection."""
        # Create decision and proposal
        decision = decision_engine.should_resurrect(
            sample_kill_report,
            sample_siem_context,
        )

        proposal = recommendation_engine.generate_proposal(
            sample_kill_report,
            sample_siem_context,
            decision,
        )

        # Enqueue
        item_id = await approval_queue.enqueue(proposal)

        # Approve
        request = await approval_queue.approve(
            item_id,
            approver="integration-test",
            notes="Approved for integration test",
        )

        assert request is not None
        assert request.approved_by == "integration-test"

        # Execute resurrection
        result = await resurrector.resurrect(request)

        assert result is not None
        assert result.request_id == request.request_id


class TestWebSocketEventIntegration:
    """Test WebSocket event broadcasting integration."""

    @pytest.mark.asyncio
    async def test_broadcast_helpers_work(self):
        """Test that broadcast helper functions work correctly."""
        from interfaces.web import (
            get_ws_manager,
            broadcast_queue_update,
            broadcast_decision,
            broadcast_system_status,
        )

        # Reset the global manager
        import interfaces.web as web_module
        web_module._ws_manager = None

        ws_manager = get_ws_manager()

        # Connect a client
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.client_state = "connected"
        await ws_manager.connect(ws, "integration-client", ["all"])

        # Test broadcast_queue_update
        sent = await broadcast_queue_update(
            item_id="int-item-001",
            action="added",
            data={"target_module": "test-service"},
        )
        assert sent == 1

        # Test broadcast_decision
        sent = await broadcast_decision(
            decision_id="int-dec-001",
            outcome="approve",
            data={"risk_level": "low"},
        )
        assert sent == 1

        # Test broadcast_system_status
        sent = await broadcast_system_status({
            "mode": "semi_auto",
            "queue_depth": 0,
            "health": "healthy",
        })
        assert sent == 1

        # Verify all messages were sent
        assert ws.send_json.call_count >= 3

        # Cleanup
        web_module._ws_manager = None


class TestDashboardIntegration:
    """Test dashboard integration with WebAPI."""

    @pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
    def test_dashboard_route_returns_html(self, web_config, approval_queue):
        """Test that dashboard route returns HTML content."""
        web_api = WebAPI(
            config=web_config,
            approval_queue=approval_queue,
            mode_getter=lambda: "semi_auto",
            mode_setter=lambda m: None,
        )
        client = TestClient(web_api.app)

        response = client.get("/dashboard")
        # Should return 200 or redirect
        assert response.status_code in (200, 302, 307)

        if response.status_code == 200:
            assert "text/html" in response.headers.get("content-type", "")


class TestConcurrentOperations:
    """Test concurrent API operations."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
    async def test_concurrent_queue_operations(
        self,
        web_config,
        approval_queue,
        decision_engine,
        recommendation_engine,
        sample_kill_report,
        sample_siem_context,
    ):
        """Test multiple concurrent queue operations."""
        # Create multiple proposals
        proposals = []
        for i in range(5):
            kill_report = KillReport(
                kill_id=f"concurrent-test-{i}",
                timestamp=datetime.now(timezone.utc),
                target_module=f"service-{i}",
                target_instance_id=f"instance-{i}",
                kill_reason=KillReason.RESOURCE_EXHAUSTION,
                severity=Severity.LOW,
                confidence_score=0.5,
                evidence=["test"],
                dependencies=[],
                source_agent="smith-01",
                metadata={},
            )

            siem_context = SIEMContextResponse(
                query_id=f"query-{i}",
                kill_id=f"concurrent-test-{i}",
                timestamp=datetime.now(timezone.utc),
                threat_indicators=[],
                historical_behavior={},
                false_positive_history=5,
                network_context={},
                user_context=None,
                risk_score=0.1,
                recommendation="low_risk",
            )

            decision = decision_engine.should_resurrect(kill_report, siem_context)
            proposal = recommendation_engine.generate_proposal(
                kill_report, siem_context, decision
            )
            proposals.append(proposal)

        # Enqueue all concurrently
        tasks = [approval_queue.enqueue(p) for p in proposals]
        item_ids = await asyncio.gather(*tasks)

        assert len(item_ids) == 5
        assert all(item_id is not None for item_id in item_ids)

        # Verify all items in queue
        pending = await approval_queue.list_pending(limit=10)
        assert len(pending) >= 5
