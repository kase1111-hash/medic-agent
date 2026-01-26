"""
Unit tests for the ClusterManager module.
"""

import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, AsyncMock, patch

from integration.cluster_manager import (
    ClusterManager,
    ClusterInfo,
    ClusterRole,
    ClusterState,
    ClusterStore,
    InMemoryClusterStore,
    RedisClusterStore,
    EtcdClusterStore,
    SyncEvent,
    SyncScope,
    create_cluster_store,
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
            timestamp=datetime.now(timezone.utc),
        )

        assert event.event_id == "event-001"
        assert event.scope == SyncScope.DECISIONS
        assert event.action == "create"

    def test_to_dict(self):
        """Test serializing SyncEvent to dict."""
        now = datetime.now(timezone.utc)
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            timestamp=datetime.now(timezone.utc),
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
            timestamp=datetime.now(timezone.utc),
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


class TestRedisClusterStore:
    """Tests for RedisClusterStore with mocked Redis client."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        mock = AsyncMock()
        mock.hset = AsyncMock(return_value=True)
        mock.hgetall = AsyncMock(return_value={})
        mock.delete = AsyncMock(return_value=1)
        mock.expire = AsyncMock(return_value=True)
        mock.set = AsyncMock(return_value=True)
        mock.get = AsyncMock(return_value=None)
        mock.lpush = AsyncMock(return_value=1)
        mock.ltrim = AsyncMock(return_value=True)
        mock.lrange = AsyncMock(return_value=[])
        mock.sadd = AsyncMock(return_value=1)
        mock.smembers = AsyncMock(return_value=set())
        mock.close = AsyncMock()

        # scan_iter needs to be an async generator
        async def async_scan_iter(*args, **kwargs):
            for item in []:
                yield item
        mock.scan_iter = async_scan_iter

        return mock

    @pytest.fixture
    def redis_store(self, mock_redis):
        """Create RedisClusterStore with mocked Redis."""
        store = RedisClusterStore(host="localhost", port=6379)
        store._redis = mock_redis
        store._connected = True
        return store

    @pytest.fixture
    def sample_cluster_info(self):
        """Create sample cluster info."""
        return ClusterInfo(
            cluster_id="redis-test",
            name="Redis Test Cluster",
            endpoint="http://localhost:8000",
            role=ClusterRole.FOLLOWER,
            state=ClusterState.HEALTHY,
        )

    def test_initialization(self):
        """Test RedisClusterStore initialization."""
        store = RedisClusterStore(
            host="redis.example.com",
            port=6380,
            db=1,
            password="secret",
            ssl=True,
        )

        assert store.host == "redis.example.com"
        assert store.port == 6380
        assert store.db == 1
        assert store.password == "secret"
        assert store.ssl is True
        assert store._connected is False

    @pytest.mark.asyncio
    async def test_register_cluster(self, redis_store, sample_cluster_info, mock_redis):
        """Test registering a cluster via Redis."""
        result = await redis_store.register_cluster(sample_cluster_info)

        assert result is True
        mock_redis.hset.assert_called_once()
        mock_redis.expire.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_cluster(self, redis_store, mock_redis):
        """Test getting a cluster from Redis."""
        mock_redis.hgetall.return_value = {
            "cluster_id": "redis-test",
            "name": "Redis Test",
            "endpoint": "http://localhost:8000",
            "role": "follower",
            "state": "healthy",
            "region": "",
            "zone": "",
            "version": "1.0.0",
        }

        result = await redis_store.get_cluster("redis-test")

        assert result is not None
        assert result.cluster_id == "redis-test"
        mock_redis.hgetall.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_cluster_not_found(self, redis_store, mock_redis):
        """Test getting a cluster that doesn't exist."""
        mock_redis.hgetall.return_value = {}

        result = await redis_store.get_cluster("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_deregister_cluster(self, redis_store, mock_redis):
        """Test deregistering a cluster."""
        result = await redis_store.deregister_cluster("redis-test")

        assert result is True
        assert mock_redis.delete.call_count == 2  # cluster key and acked key

    @pytest.mark.asyncio
    async def test_acquire_leader_lock_success(self, redis_store, mock_redis):
        """Test successfully acquiring leader lock."""
        mock_redis.set.return_value = True

        result = await redis_store.acquire_leader_lock("redis-test", ttl_seconds=30)

        assert result is True
        mock_redis.set.assert_called_with(
            redis_store.LEADER_KEY,
            "redis-test",
            nx=True,
            ex=30,
        )

    @pytest.mark.asyncio
    async def test_acquire_leader_lock_already_leader(self, redis_store, mock_redis):
        """Test acquiring lock when already leader."""
        mock_redis.set.return_value = False
        mock_redis.get.return_value = "redis-test"

        result = await redis_store.acquire_leader_lock("redis-test", ttl_seconds=30)

        assert result is True
        mock_redis.expire.assert_called()

    @pytest.mark.asyncio
    async def test_acquire_leader_lock_failure(self, redis_store, mock_redis):
        """Test failing to acquire leader lock."""
        mock_redis.set.return_value = False
        mock_redis.get.return_value = "other-cluster"

        result = await redis_store.acquire_leader_lock("redis-test", ttl_seconds=30)

        assert result is False

    @pytest.mark.asyncio
    async def test_release_leader_lock(self, redis_store, mock_redis):
        """Test releasing leader lock."""
        mock_redis.get.return_value = "redis-test"

        result = await redis_store.release_leader_lock("redis-test")

        assert result is True
        mock_redis.delete.assert_called_with(redis_store.LEADER_KEY)

    @pytest.mark.asyncio
    async def test_release_leader_lock_not_leader(self, redis_store, mock_redis):
        """Test releasing lock when not the leader."""
        mock_redis.get.return_value = "other-cluster"

        result = await redis_store.release_leader_lock("redis-test")

        assert result is False

    @pytest.mark.asyncio
    async def test_get_leader(self, redis_store, mock_redis):
        """Test getting current leader."""
        mock_redis.get.return_value = "leader-cluster"

        result = await redis_store.get_leader()

        assert result == "leader-cluster"

    @pytest.mark.asyncio
    async def test_push_sync_event(self, redis_store, mock_redis):
        """Test pushing a sync event."""
        event = SyncEvent(
            event_id="event-001",
            source_cluster="redis-test",
            scope=SyncScope.DECISIONS,
            action="create",
            data={"test": True},
            timestamp=datetime.now(timezone.utc),
        )

        result = await redis_store.push_sync_event(event)

        assert result is True
        mock_redis.lpush.assert_called_once()
        mock_redis.ltrim.assert_called_once()

    @pytest.mark.asyncio
    async def test_ack_event(self, redis_store, mock_redis):
        """Test acknowledging an event."""
        result = await redis_store.ack_event("redis-test", "event-001")

        assert result is True
        mock_redis.sadd.assert_called_once()
        mock_redis.expire.assert_called()

    @pytest.mark.asyncio
    async def test_close(self, redis_store, mock_redis):
        """Test closing Redis connection."""
        await redis_store.close()

        mock_redis.close.assert_called_once()
        assert redis_store._connected is False


class TestEtcdClusterStore:
    """Tests for EtcdClusterStore with mocked etcd client."""

    @pytest.fixture
    def mock_etcd(self):
        """Create a mock etcd3 client."""
        mock = Mock()
        mock.put = Mock()
        mock.get = Mock(return_value=(None, None))
        mock.delete = Mock()
        mock.delete_prefix = Mock()
        mock.get_prefix = Mock(return_value=[])
        mock.lease = Mock(return_value=Mock(id=12345))
        mock.revoke_lease = Mock()
        mock.refresh_lease = Mock()
        mock.close = Mock()
        mock.transaction = Mock(return_value=(True, []))
        mock.transactions = Mock()
        mock.transactions.version = Mock(return_value=Mock())
        mock.transactions.put = Mock(return_value=Mock())
        return mock

    @pytest.fixture
    def etcd_store(self, mock_etcd):
        """Create EtcdClusterStore with mocked etcd."""
        store = EtcdClusterStore(host="localhost", port=2379)
        store._client = mock_etcd
        store._connected = True
        return store

    @pytest.fixture
    def sample_cluster_info(self):
        """Create sample cluster info."""
        return ClusterInfo(
            cluster_id="etcd-test",
            name="Etcd Test Cluster",
            endpoint="http://localhost:8000",
            role=ClusterRole.FOLLOWER,
            state=ClusterState.HEALTHY,
        )

    def test_initialization(self):
        """Test EtcdClusterStore initialization."""
        store = EtcdClusterStore(
            endpoints=["https://etcd1:2379", "https://etcd2:2379"],
            host="etcd.example.com",
            port=2380,
            cert_file="/path/to/cert",
            key_file="/path/to/key",
            ca_file="/path/to/ca",
            timeout=15,
        )

        assert store.endpoints == ["https://etcd1:2379", "https://etcd2:2379"]
        assert store.host == "etcd.example.com"
        assert store.port == 2380
        assert store.cert_file == "/path/to/cert"
        assert store.key_file == "/path/to/key"
        assert store.timeout == 15
        assert store._connected is False

    @pytest.mark.asyncio
    async def test_register_cluster(self, etcd_store, sample_cluster_info, mock_etcd):
        """Test registering a cluster via etcd."""
        result = await etcd_store.register_cluster(sample_cluster_info)

        assert result is True
        mock_etcd.put.assert_called_once()
        mock_etcd.lease.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_cluster(self, etcd_store, mock_etcd):
        """Test getting a cluster from etcd."""
        import json
        cluster_data = {
            "cluster_id": "etcd-test",
            "name": "Etcd Test",
            "endpoint": "http://localhost:8000",
            "role": "follower",
            "state": "healthy",
            "region": "",
            "zone": "",
            "version": "1.0.0",
        }
        mock_etcd.get.return_value = (json.dumps(cluster_data).encode(), None)

        result = await etcd_store.get_cluster("etcd-test")

        assert result is not None
        assert result.cluster_id == "etcd-test"

    @pytest.mark.asyncio
    async def test_get_cluster_not_found(self, etcd_store, mock_etcd):
        """Test getting a cluster that doesn't exist."""
        mock_etcd.get.return_value = (None, None)

        result = await etcd_store.get_cluster("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_deregister_cluster(self, etcd_store, mock_etcd):
        """Test deregistering a cluster."""
        result = await etcd_store.deregister_cluster("etcd-test")

        assert result is True
        mock_etcd.delete.assert_called_once()
        mock_etcd.delete_prefix.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_clusters(self, etcd_store, mock_etcd):
        """Test listing clusters from etcd."""
        import json
        cluster1 = {
            "cluster_id": "cluster-1",
            "name": "Cluster 1",
            "endpoint": "http://localhost:8001",
            "role": "leader",
            "state": "healthy",
            "region": "",
            "zone": "",
            "version": "1.0.0",
        }
        cluster2 = {
            "cluster_id": "cluster-2",
            "name": "Cluster 2",
            "endpoint": "http://localhost:8002",
            "role": "follower",
            "state": "healthy",
            "region": "",
            "zone": "",
            "version": "1.0.0",
        }

        mock_metadata1 = Mock()
        mock_metadata1.key = b"/medic/cluster/nodes/cluster-1"
        mock_metadata2 = Mock()
        mock_metadata2.key = b"/medic/cluster/nodes/cluster-2"

        mock_etcd.get_prefix.return_value = [
            (json.dumps(cluster1).encode(), mock_metadata1),
            (json.dumps(cluster2).encode(), mock_metadata2),
        ]

        result = await etcd_store.list_clusters()

        assert len(result) == 2
        assert any(c.cluster_id == "cluster-1" for c in result)
        assert any(c.cluster_id == "cluster-2" for c in result)

    @pytest.mark.asyncio
    async def test_acquire_leader_lock_success(self, etcd_store, mock_etcd):
        """Test successfully acquiring leader lock via etcd."""
        mock_etcd.get.return_value = (None, None)
        mock_etcd.transaction.return_value = (True, [])

        result = await etcd_store.acquire_leader_lock("etcd-test", ttl_seconds=30)

        assert result is True

    @pytest.mark.asyncio
    async def test_acquire_leader_lock_already_leader(self, etcd_store, mock_etcd):
        """Test acquiring lock when already leader."""
        mock_etcd.get.return_value = (b"etcd-test", None)

        result = await etcd_store.acquire_leader_lock("etcd-test", ttl_seconds=30)

        assert result is True
        mock_etcd.put.assert_called()

    @pytest.mark.asyncio
    async def test_acquire_leader_lock_failure(self, etcd_store, mock_etcd):
        """Test failing to acquire leader lock."""
        mock_etcd.get.return_value = (b"other-cluster", None)

        result = await etcd_store.acquire_leader_lock("etcd-test", ttl_seconds=30)

        assert result is False

    @pytest.mark.asyncio
    async def test_release_leader_lock(self, etcd_store, mock_etcd):
        """Test releasing leader lock."""
        mock_etcd.get.return_value = (b"etcd-test", None)

        result = await etcd_store.release_leader_lock("etcd-test")

        assert result is True
        mock_etcd.delete.assert_called()

    @pytest.mark.asyncio
    async def test_get_leader(self, etcd_store, mock_etcd):
        """Test getting current leader."""
        mock_etcd.get.return_value = (b"leader-cluster", None)

        result = await etcd_store.get_leader()

        assert result == "leader-cluster"

    @pytest.mark.asyncio
    async def test_push_sync_event(self, etcd_store, mock_etcd):
        """Test pushing a sync event."""
        event = SyncEvent(
            event_id="event-001",
            source_cluster="etcd-test",
            scope=SyncScope.DECISIONS,
            action="create",
            data={"test": True},
            timestamp=datetime.now(timezone.utc),
        )

        result = await etcd_store.push_sync_event(event)

        assert result is True
        mock_etcd.put.assert_called_once()
        mock_etcd.lease.assert_called()

    @pytest.mark.asyncio
    async def test_ack_event(self, etcd_store, mock_etcd):
        """Test acknowledging an event."""
        result = await etcd_store.ack_event("etcd-test", "event-001")

        assert result is True
        mock_etcd.put.assert_called_once()
        mock_etcd.lease.assert_called()

    @pytest.mark.asyncio
    async def test_close(self, etcd_store, mock_etcd):
        """Test closing etcd connection."""
        await etcd_store.close()

        mock_etcd.close.assert_called_once()
        assert etcd_store._connected is False


class TestCreateClusterStore:
    """Tests for the create_cluster_store factory function."""

    def test_create_memory_store(self):
        """Test creating an in-memory store."""
        config = {"store": {"type": "memory"}}
        store = create_cluster_store(config)

        assert isinstance(store, InMemoryClusterStore)

    def test_create_redis_store(self):
        """Test creating a Redis store."""
        config = {
            "store": {
                "type": "redis",
                "redis": {
                    "host": "redis.example.com",
                    "port": 6380,
                    "db": 2,
                    "password": "secret",
                    "ssl": True,
                },
            }
        }
        store = create_cluster_store(config)

        assert isinstance(store, RedisClusterStore)
        assert store.host == "redis.example.com"
        assert store.port == 6380
        assert store.db == 2
        assert store.password == "secret"
        assert store.ssl is True

    def test_create_etcd_store(self):
        """Test creating an etcd store."""
        config = {
            "store": {
                "type": "etcd",
                "etcd": {
                    "endpoints": ["https://etcd1:2379", "https://etcd2:2379"],
                    "host": "etcd.example.com",
                    "port": 2380,
                    "cert_file": "/etc/certs/client.crt",
                    "key_file": "/etc/certs/client.key",
                    "ca_cert": "/etc/certs/ca.crt",
                    "timeout": 15,
                },
            }
        }
        store = create_cluster_store(config)

        assert isinstance(store, EtcdClusterStore)
        assert store.endpoints == ["https://etcd1:2379", "https://etcd2:2379"]
        assert store.cert_file == "/etc/certs/client.crt"
        assert store.key_file == "/etc/certs/client.key"
        assert store.ca_file == "/etc/certs/ca.crt"
        assert store.timeout == 15

    def test_create_unknown_store_defaults_to_memory(self):
        """Test that unknown store type defaults to in-memory."""
        config = {"store": {"type": "unknown"}}
        store = create_cluster_store(config)

        assert isinstance(store, InMemoryClusterStore)

    def test_create_store_with_empty_config(self):
        """Test creating store with empty config defaults to memory."""
        store = create_cluster_store({})

        assert isinstance(store, InMemoryClusterStore)

    def test_create_redis_store_defaults(self):
        """Test creating Redis store with minimal config uses defaults."""
        config = {"store": {"type": "redis"}}
        store = create_cluster_store(config)

        assert isinstance(store, RedisClusterStore)
        assert store.host == "localhost"
        assert store.port == 6379
        assert store.db == 0

    def test_create_etcd_store_defaults(self):
        """Test creating etcd store with minimal config uses defaults."""
        config = {"store": {"type": "etcd"}}
        store = create_cluster_store(config)

        assert isinstance(store, EtcdClusterStore)
        assert store.host == "localhost"
        assert store.port == 2379
