"""
Unit tests for the ClusterManager module.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from integration.cluster_manager import (
    ClusterManager,
    ClusterInfo,
    ClusterRole,
    ClusterState,
    ClusterStore,
    InMemoryClusterStore,
    SyncEvent,
    SyncScope,
    get_cluster_manager,
    init_cluster_manager,
    publish_cluster_event,
)


class TestClusterInfo:
    """Tests for ClusterInfo dataclass."""

    def test_create_cluster_info(self):
        """Test creating a ClusterInfo instance."""
        info = ClusterInfo(
            cluster_id="cluster-001",
            name="test-cluster",
            endpoint="http://localhost:8000",
            role=ClusterRole.FOLLOWER,
            state=ClusterState.HEALTHY,
            region="us-east-1",
            zone="us-east-1a",
        )

        assert info.cluster_id == "cluster-001"
        assert info.name == "test-cluster"
        assert info.role == ClusterRole.FOLLOWER
        assert info.state == ClusterState.HEALTHY

    def test_to_dict(self):
        """Test serializing ClusterInfo to dict."""
        info = ClusterInfo(
            cluster_id="cluster-001",
            name="test-cluster",
            endpoint="http://localhost:8000",
            role=ClusterRole.LEADER,
            state=ClusterState.HEALTHY,
        )

        data = info.to_dict()

        assert data["cluster_id"] == "cluster-001"
        assert data["role"] == "leader"
        assert data["state"] == "healthy"

    def test_from_dict(self):
        """Test deserializing ClusterInfo from dict."""
        data = {
            "cluster_id": "cluster-002",
            "name": "remote-cluster",
            "endpoint": "http://remote:8000",
            "role": "follower",
            "state": "syncing",
            "region": "eu-west-1",
            "zone": "",
            "version": "1.0.0",
        }

        info = ClusterInfo.from_dict(data)

        assert info.cluster_id == "cluster-002"
        assert info.role == ClusterRole.FOLLOWER
        assert info.state == ClusterState.SYNCING
        assert info.region == "eu-west-1"


class TestSyncEvent:
    """Tests for SyncEvent dataclass."""

    def test_create_sync_event(self):
        """Test creating a SyncEvent."""
        event = SyncEvent(
            event_id="event-001",
            source_cluster="cluster-001",
            scope=SyncScope.DECISIONS,
            action="create",
            data={"decision_id": "dec-001"},
            timestamp=datetime.utcnow(),
        )

        assert event.event_id == "event-001"
        assert event.scope == SyncScope.DECISIONS
        assert event.action == "create"

    def test_to_dict(self):
        """Test serializing SyncEvent to dict."""
        now = datetime.utcnow()
        event = SyncEvent(
            event_id="event-001",
            source_cluster="cluster-001",
            scope=SyncScope.THRESHOLDS,
            action="update",
            data={"key": "auto_approve", "value": 0.8},
            timestamp=now,
        )

        data = event.to_dict()

        assert data["event_id"] == "event-001"
        assert data["scope"] == "thresholds"
        assert data["action"] == "update"
        assert "key" in data["data"]

    def test_from_dict(self):
        """Test deserializing SyncEvent from dict."""
        data = {
            "event_id": "event-002",
            "source_cluster": "cluster-002",
            "scope": "decisions",
            "action": "delete",
            "data": {},
            "timestamp": datetime.utcnow().isoformat(),
            "version": 2,
        }

        event = SyncEvent.from_dict(data)

        assert event.event_id == "event-002"
        assert event.scope == SyncScope.DECISIONS
        assert event.version == 2


class TestInMemoryClusterStore:
    """Tests for InMemoryClusterStore."""

    @pytest.fixture
    def store(self):
        """Create a fresh InMemoryClusterStore."""
        return InMemoryClusterStore()

    @pytest.fixture
    def sample_cluster_info(self):
        """Create sample cluster info."""
        return ClusterInfo(
            cluster_id="test-cluster",
            name="Test Cluster",
            endpoint="http://localhost:8000",
            role=ClusterRole.FOLLOWER,
            state=ClusterState.HEALTHY,
        )

    @pytest.mark.asyncio
    async def test_register_cluster(self, store, sample_cluster_info):
        """Test registering a cluster."""
        result = await store.register_cluster(sample_cluster_info)

        assert result is True

        retrieved = await store.get_cluster("test-cluster")
        assert retrieved is not None
        assert retrieved.name == "Test Cluster"

    @pytest.mark.asyncio
    async def test_deregister_cluster(self, store, sample_cluster_info):
        """Test deregistering a cluster."""
        await store.register_cluster(sample_cluster_info)

        result = await store.deregister_cluster("test-cluster")
        assert result is True

        retrieved = await store.get_cluster("test-cluster")
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_list_clusters(self, store):
        """Test listing all clusters."""
        for i in range(3):
            info = ClusterInfo(
                cluster_id=f"cluster-{i}",
                name=f"Cluster {i}",
                endpoint=f"http://localhost:800{i}",
                role=ClusterRole.FOLLOWER,
                state=ClusterState.HEALTHY,
            )
            await store.register_cluster(info)

        clusters = await store.list_clusters()
        assert len(clusters) == 3

    @pytest.mark.asyncio
    async def test_update_cluster(self, store, sample_cluster_info):
        """Test updating cluster info."""
        await store.register_cluster(sample_cluster_info)

        sample_cluster_info.state = ClusterState.DEGRADED
        result = await store.update_cluster(sample_cluster_info)

        assert result is True

        retrieved = await store.get_cluster("test-cluster")
        assert retrieved.state == ClusterState.DEGRADED

    @pytest.mark.asyncio
    async def test_acquire_leader_lock(self, store, sample_cluster_info):
        """Test acquiring leader lock."""
        await store.register_cluster(sample_cluster_info)

        result = await store.acquire_leader_lock("test-cluster", ttl_seconds=30)
        assert result is True

        leader = await store.get_leader()
        assert leader == "test-cluster"

    @pytest.mark.asyncio
    async def test_acquire_leader_lock_already_held(self, store):
        """Test that leader lock cannot be acquired when held."""
        info1 = ClusterInfo(
            cluster_id="cluster-1",
            name="Cluster 1",
            endpoint="http://localhost:8001",
            role=ClusterRole.FOLLOWER,
            state=ClusterState.HEALTHY,
        )
        info2 = ClusterInfo(
            cluster_id="cluster-2",
            name="Cluster 2",
            endpoint="http://localhost:8002",
            role=ClusterRole.FOLLOWER,
            state=ClusterState.HEALTHY,
        )

        await store.register_cluster(info1)
        await store.register_cluster(info2)

        # First cluster acquires lock
        result1 = await store.acquire_leader_lock("cluster-1", ttl_seconds=30)
        assert result1 is True

        # Second cluster fails to acquire
        result2 = await store.acquire_leader_lock("cluster-2", ttl_seconds=30)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_release_leader_lock(self, store, sample_cluster_info):
        """Test releasing leader lock."""
        await store.register_cluster(sample_cluster_info)
        await store.acquire_leader_lock("test-cluster", ttl_seconds=30)

        result = await store.release_leader_lock("test-cluster")
        assert result is True

        leader = await store.get_leader()
        assert leader is None

    @pytest.mark.asyncio
    async def test_push_and_get_sync_events(self, store):
        """Test pushing and retrieving sync events."""
        event = SyncEvent(
            event_id="event-001",
            source_cluster="cluster-1",
            scope=SyncScope.DECISIONS,
            action="create",
            data={"test": True},
            timestamp=datetime.utcnow(),
        )

        await store.push_sync_event(event)

        # Register a different cluster to receive events
        info = ClusterInfo(
            cluster_id="cluster-2",
            name="Cluster 2",
            endpoint="http://localhost:8002",
            role=ClusterRole.FOLLOWER,
            state=ClusterState.HEALTHY,
        )
        await store.register_cluster(info)

        events = await store.get_pending_events("cluster-2")
        assert len(events) == 1
        assert events[0].event_id == "event-001"

    @pytest.mark.asyncio
    async def test_ack_event(self, store):
        """Test acknowledging a sync event."""
        event = SyncEvent(
            event_id="event-001",
            source_cluster="cluster-1",
            scope=SyncScope.DECISIONS,
            action="create",
            data={},
            timestamp=datetime.utcnow(),
        )

        await store.push_sync_event(event)

        info = ClusterInfo(
            cluster_id="cluster-2",
            name="Cluster 2",
            endpoint="http://localhost:8002",
            role=ClusterRole.FOLLOWER,
            state=ClusterState.HEALTHY,
        )
        await store.register_cluster(info)

        # Ack the event
        await store.ack_event("cluster-2", "event-001")

        # Should no longer be pending
        events = await store.get_pending_events("cluster-2")
        assert len(events) == 0


class TestClusterManager:
    """Tests for ClusterManager."""

    @pytest.fixture
    def cluster_manager(self):
        """Create a ClusterManager for testing."""
        return ClusterManager(
            cluster_id="test-cluster",
            cluster_name="Test Cluster",
            endpoint="http://localhost:8000",
            region="us-east-1",
            zone="us-east-1a",
        )

    def test_initialization(self, cluster_manager):
        """Test ClusterManager initialization."""
        assert cluster_manager.cluster_id == "test-cluster"
        assert cluster_manager.cluster_name == "Test Cluster"
        assert cluster_manager.role == ClusterRole.OBSERVER
        assert cluster_manager.state == ClusterState.HEALTHY
        assert not cluster_manager.is_leader

    def test_get_cluster_info(self, cluster_manager):
        """Test getting cluster info."""
        info = cluster_manager.get_cluster_info()

        assert info.cluster_id == "test-cluster"
        assert info.name == "Test Cluster"
        assert info.endpoint == "http://localhost:8000"
        assert info.region == "us-east-1"

    def test_get_statistics(self, cluster_manager):
        """Test getting statistics."""
        stats = cluster_manager.get_statistics()

        assert stats["cluster_id"] == "test-cluster"
        assert stats["role"] == "observer"
        assert stats["is_leader"] is False
        assert stats["running"] is False

    @pytest.mark.asyncio
    async def test_start_and_stop(self, cluster_manager):
        """Test starting and stopping the manager."""
        await cluster_manager.start()

        assert cluster_manager._running is True

        await cluster_manager.stop()

        assert cluster_manager._running is False

    @pytest.mark.asyncio
    async def test_register_event_handler(self, cluster_manager):
        """Test registering event handlers."""
        handler_called = []

        def handler(event):
            handler_called.append(event)

        cluster_manager.register_event_handler(SyncScope.DECISIONS, handler)

        assert len(cluster_manager._event_handlers[SyncScope.DECISIONS]) == 1

    @pytest.mark.asyncio
    async def test_publish_event(self, cluster_manager):
        """Test publishing events."""
        await cluster_manager.start()

        try:
            event_id = await cluster_manager.publish_event(
                scope=SyncScope.DECISIONS,
                action="create",
                data={"decision_id": "dec-001"},
            )

            assert event_id is not None
        finally:
            await cluster_manager.stop()

    @pytest.mark.asyncio
    async def test_get_clusters(self, cluster_manager):
        """Test getting cluster list."""
        await cluster_manager.start()

        try:
            clusters = await cluster_manager.get_clusters()

            # Should contain at least this cluster
            assert len(clusters) >= 1
            assert any(c.cluster_id == "test-cluster" for c in clusters)
        finally:
            await cluster_manager.stop()


class TestModuleFunctions:
    """Tests for module-level functions."""

    def test_init_cluster_manager(self):
        """Test initializing global cluster manager."""
        manager = init_cluster_manager(
            cluster_id="global-test",
            cluster_name="Global Test",
            endpoint="http://localhost:9000",
        )

        assert manager is not None
        assert manager.cluster_id == "global-test"

        # Verify it's retrievable
        retrieved = get_cluster_manager()
        assert retrieved is manager

    @pytest.mark.asyncio
    async def test_publish_cluster_event_when_running(self):
        """Test publishing cluster event when manager is running."""
        manager = init_cluster_manager(
            cluster_id="publish-test",
            cluster_name="Publish Test",
            endpoint="http://localhost:9001",
        )

        await manager.start()

        try:
            event_id = await publish_cluster_event(
                scope=SyncScope.THRESHOLDS,
                action="update",
                data={"key": "test", "value": 0.5},
            )

            assert event_id is not None
        finally:
            await manager.stop()

    @pytest.mark.asyncio
    async def test_publish_cluster_event_when_not_running(self):
        """Test publishing cluster event when manager is not running."""
        manager = init_cluster_manager(
            cluster_id="not-running-test",
            cluster_name="Not Running",
            endpoint="http://localhost:9002",
        )

        # Don't start the manager

        event_id = await publish_cluster_event(
            scope=SyncScope.DECISIONS,
            action="create",
            data={},
        )

        # Should return None when not running
        assert event_id is None
