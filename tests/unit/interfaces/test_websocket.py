"""
Unit tests for WebSocket functionality.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, MagicMock, patch
import json

# Mock starlette WebSocketState before importing web module
from unittest.mock import MagicMock
import sys

# Create mock for starlette.websockets if not available
if "starlette.websockets" not in sys.modules:
    mock_module = MagicMock()
    mock_module.WebSocketState = MagicMock()
    mock_module.WebSocketState.CONNECTED = "connected"
    sys.modules["starlette.websockets"] = mock_module

from interfaces.web import (
    WebSocketEventType,
    WebSocketManager,
    get_ws_manager,
    broadcast_queue_update,
    broadcast_decision,
    broadcast_resurrection_event,
    broadcast_monitor_event,
    broadcast_threshold_update,
    broadcast_system_status,
)


class TestWebSocketEventType:
    """Tests for WebSocketEventType enum."""

    def test_event_types_exist(self):
        """Test that all expected event types exist."""
        assert WebSocketEventType.QUEUE_UPDATE.value == "queue_update"
        assert WebSocketEventType.QUEUE_ITEM_ADDED.value == "queue_item_added"
        assert WebSocketEventType.DECISION_MADE.value == "decision_made"
        assert WebSocketEventType.RESURRECTION_STARTED.value == "resurrection_started"
        assert WebSocketEventType.HEARTBEAT.value == "heartbeat"

    def test_event_type_is_string_enum(self):
        """Test that event types are string enums."""
        assert isinstance(WebSocketEventType.QUEUE_UPDATE.value, str)
        assert str(WebSocketEventType.QUEUE_UPDATE) == "WebSocketEventType.QUEUE_UPDATE"


class TestWebSocketManager:
    """Tests for WebSocketManager class."""

    @pytest.fixture
    def ws_manager(self):
        """Create a fresh WebSocketManager."""
        return WebSocketManager()

    @pytest.fixture
    def mock_websocket(self):
        """Create a mock WebSocket."""
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()
        ws.client_state = "connected"
        return ws

    def test_initialization(self, ws_manager):
        """Test WebSocketManager initialization."""
        assert ws_manager.get_connection_count() == 0
        assert ws_manager.get_client_info() == []

    @pytest.mark.asyncio
    async def test_connect(self, ws_manager, mock_websocket):
        """Test connecting a WebSocket client."""
        await ws_manager.connect(mock_websocket, "client-001")

        assert ws_manager.get_connection_count() == 1

        client_info = ws_manager.get_client_info()
        assert len(client_info) == 1
        assert client_info[0]["client_id"] == "client-001"

        mock_websocket.accept.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_with_topics(self, ws_manager, mock_websocket):
        """Test connecting with specific topics."""
        await ws_manager.connect(mock_websocket, "client-001", ["queue", "decisions"])

        client_info = ws_manager.get_client_info()
        assert "queue" in client_info[0]["topics"]
        assert "decisions" in client_info[0]["topics"]

    @pytest.mark.asyncio
    async def test_disconnect(self, ws_manager, mock_websocket):
        """Test disconnecting a client."""
        await ws_manager.connect(mock_websocket, "client-001")
        assert ws_manager.get_connection_count() == 1

        await ws_manager.disconnect("client-001")
        assert ws_manager.get_connection_count() == 0

    @pytest.mark.asyncio
    async def test_subscribe(self, ws_manager, mock_websocket):
        """Test subscribing to topics."""
        await ws_manager.connect(mock_websocket, "client-001", ["all"])

        await ws_manager.subscribe("client-001", ["queue", "decisions"])

        client_info = ws_manager.get_client_info()
        topics = client_info[0]["topics"]
        assert "queue" in topics
        assert "decisions" in topics

    @pytest.mark.asyncio
    async def test_unsubscribe(self, ws_manager, mock_websocket):
        """Test unsubscribing from topics."""
        await ws_manager.connect(mock_websocket, "client-001", ["queue", "decisions"])

        await ws_manager.unsubscribe("client-001", ["queue"])

        client_info = ws_manager.get_client_info()
        topics = client_info[0]["topics"]
        assert "queue" not in topics
        assert "decisions" in topics

    @pytest.mark.asyncio
    async def test_send_to_client(self, ws_manager, mock_websocket):
        """Test sending a message to a specific client."""
        await ws_manager.connect(mock_websocket, "client-001")

        message = {"type": "test", "data": "hello"}
        result = await ws_manager.send_to_client("client-001", message)

        assert result is True
        mock_websocket.send_json.assert_called_with(message)

    @pytest.mark.asyncio
    async def test_send_to_nonexistent_client(self, ws_manager):
        """Test sending to a client that doesn't exist."""
        result = await ws_manager.send_to_client("nonexistent", {"test": True})
        assert result is False

    @pytest.mark.asyncio
    async def test_broadcast_to_all(self, ws_manager):
        """Test broadcasting to all clients."""
        # Connect multiple clients
        for i in range(3):
            ws = AsyncMock()
            ws.accept = AsyncMock()
            ws.send_json = AsyncMock()
            ws.client_state = "connected"
            await ws_manager.connect(ws, f"client-{i}")

        sent_count = await ws_manager.broadcast(
            WebSocketEventType.SYSTEM_STATUS,
            {"status": "healthy"},
        )

        assert sent_count == 3

    @pytest.mark.asyncio
    async def test_broadcast_to_topic(self, ws_manager):
        """Test broadcasting to a specific topic."""
        # Client subscribed to queue
        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.send_json = AsyncMock()
        ws1.client_state = "connected"
        await ws_manager.connect(ws1, "client-1", ["queue"])

        # Client subscribed to decisions
        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        ws2.send_json = AsyncMock()
        ws2.client_state = "connected"
        await ws_manager.connect(ws2, "client-2", ["decisions"])

        # Broadcast to queue topic
        sent_count = await ws_manager.broadcast(
            WebSocketEventType.QUEUE_ITEM_ADDED,
            {"item_id": "item-001"},
            topic="queue",
        )

        # Only client-1 should receive it
        assert sent_count == 1
        ws1.send_json.assert_called()

    @pytest.mark.asyncio
    async def test_broadcast_includes_all_subscribers(self, ws_manager):
        """Test that 'all' topic subscribers receive all broadcasts."""
        # Client subscribed to 'all'
        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.send_json = AsyncMock()
        ws1.client_state = "connected"
        await ws_manager.connect(ws1, "client-1", ["all"])

        # Client subscribed to 'queue'
        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        ws2.send_json = AsyncMock()
        ws2.client_state = "connected"
        await ws_manager.connect(ws2, "client-2", ["queue"])

        # Broadcast to queue topic
        sent_count = await ws_manager.broadcast(
            WebSocketEventType.QUEUE_ITEM_ADDED,
            {"item_id": "item-001"},
            topic="queue",
        )

        # Both should receive it
        assert sent_count == 2

    @pytest.mark.asyncio
    async def test_reconnect_same_client_id(self, ws_manager):
        """Test that reconnecting with same ID closes old connection."""
        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.send_json = AsyncMock()
        ws1.close = AsyncMock()
        ws1.client_state = "connected"

        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        ws2.send_json = AsyncMock()
        ws2.client_state = "connected"

        await ws_manager.connect(ws1, "client-001")
        await ws_manager.connect(ws2, "client-001")

        # Old connection should be closed
        ws1.close.assert_called_once()

        # Only one connection should exist
        assert ws_manager.get_connection_count() == 1


class TestBroadcastHelpers:
    """Tests for broadcast helper functions."""

    @pytest.fixture
    def reset_ws_manager(self):
        """Reset the global WebSocket manager before each test."""
        import interfaces.web as web_module
        web_module._ws_manager = None
        yield
        web_module._ws_manager = None

    @pytest.mark.asyncio
    async def test_broadcast_queue_update(self, reset_ws_manager):
        """Test broadcast_queue_update helper."""
        ws_manager = get_ws_manager()

        # Connect a client
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.client_state = "connected"
        await ws_manager.connect(ws, "client-001", ["queue"])

        sent = await broadcast_queue_update(
            item_id="item-001",
            action="added",
            data={"target_module": "test-service"},
        )

        assert sent == 1
        ws.send_json.assert_called()

        # Verify message structure
        call_args = ws.send_json.call_args[0][0]
        assert call_args["type"] == "queue_item_added"
        assert call_args["data"]["item_id"] == "item-001"
        assert call_args["data"]["action"] == "added"

    @pytest.mark.asyncio
    async def test_broadcast_decision(self, reset_ws_manager):
        """Test broadcast_decision helper."""
        ws_manager = get_ws_manager()

        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.client_state = "connected"
        await ws_manager.connect(ws, "client-001", ["decisions"])

        sent = await broadcast_decision(
            decision_id="dec-001",
            outcome="approve",
            data={"risk_level": "low"},
        )

        assert sent == 1

        call_args = ws.send_json.call_args[0][0]
        assert call_args["type"] == "decision_made"
        assert call_args["data"]["decision_id"] == "dec-001"
        assert call_args["data"]["outcome"] == "approve"

    @pytest.mark.asyncio
    async def test_broadcast_resurrection_event(self, reset_ws_manager):
        """Test broadcast_resurrection_event helper."""
        ws_manager = get_ws_manager()

        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.client_state = "connected"
        await ws_manager.connect(ws, "client-001", ["resurrections"])

        sent = await broadcast_resurrection_event(
            request_id="req-001",
            status="completed",
            data={"target_module": "test-service"},
        )

        assert sent == 1

        call_args = ws.send_json.call_args[0][0]
        assert call_args["type"] == "resurrection_completed"

    @pytest.mark.asyncio
    async def test_broadcast_monitor_event(self, reset_ws_manager):
        """Test broadcast_monitor_event helper."""
        ws_manager = get_ws_manager()

        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.client_state = "connected"
        await ws_manager.connect(ws, "client-001", ["monitors"])

        sent = await broadcast_monitor_event(
            monitor_id="mon-001",
            event="anomaly",
            data={"severity": "high"},
        )

        assert sent == 1

        call_args = ws.send_json.call_args[0][0]
        assert call_args["type"] == "monitor_anomaly"

    @pytest.mark.asyncio
    async def test_broadcast_threshold_update(self, reset_ws_manager):
        """Test broadcast_threshold_update helper."""
        ws_manager = get_ws_manager()

        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.client_state = "connected"
        await ws_manager.connect(ws, "client-001", ["thresholds"])

        sent = await broadcast_threshold_update(
            key="auto_approve_threshold",
            old_value=0.7,
            new_value=0.8,
            reason="Manual adjustment",
        )

        assert sent == 1

        call_args = ws.send_json.call_args[0][0]
        assert call_args["type"] == "threshold_updated"
        assert call_args["data"]["key"] == "auto_approve_threshold"
        assert call_args["data"]["old_value"] == 0.7
        assert call_args["data"]["new_value"] == 0.8

    @pytest.mark.asyncio
    async def test_broadcast_system_status(self, reset_ws_manager):
        """Test broadcast_system_status helper."""
        ws_manager = get_ws_manager()

        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        ws.client_state = "connected"
        await ws_manager.connect(ws, "client-001", ["system"])

        sent = await broadcast_system_status({
            "mode": "semi_auto",
            "queue_depth": 5,
            "health": "healthy",
        })

        assert sent == 1

        call_args = ws.send_json.call_args[0][0]
        assert call_args["type"] == "system_status"
        assert call_args["data"]["mode"] == "semi_auto"


class TestGetWsManager:
    """Tests for get_ws_manager function."""

    def test_get_ws_manager_creates_singleton(self):
        """Test that get_ws_manager creates and returns a singleton."""
        import interfaces.web as web_module
        web_module._ws_manager = None

        manager1 = get_ws_manager()
        manager2 = get_ws_manager()

        assert manager1 is manager2
        assert isinstance(manager1, WebSocketManager)
