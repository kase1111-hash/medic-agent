"""
Medic Agent Multi-Cluster Support

Provides cluster coordination, leader election, and state synchronization
for running Medic agents across multiple Kubernetes clusters.

Features:
- Cluster registration and discovery
- Leader election using distributed locks
- State synchronization across clusters
- Cross-cluster event propagation
- Failover and recovery handling
"""

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

from core.logger import get_logger

logger = get_logger("integration.cluster")


class ClusterRole(str, Enum):
    """Role of a cluster in the federation."""
    LEADER = "leader"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    OBSERVER = "observer"


class ClusterState(str, Enum):
    """State of a cluster."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    SYNCING = "syncing"


class SyncScope(str, Enum):
    """Scope of data to synchronize."""
    DECISIONS = "decisions"
    OUTCOMES = "outcomes"
    THRESHOLDS = "thresholds"
    CONFIG = "config"
    ALL = "all"


@dataclass
class ClusterInfo:
    """Information about a cluster in the federation."""
    cluster_id: str
    name: str
    endpoint: str
    role: ClusterRole
    state: ClusterState
    region: str = ""
    zone: str = ""
    version: str = ""
    last_heartbeat: Optional[datetime] = None
    last_sync: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cluster_id": self.cluster_id,
            "name": self.name,
            "endpoint": self.endpoint,
            "role": self.role.value,
            "state": self.state.value,
            "region": self.region,
            "zone": self.zone,
            "version": self.version,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClusterInfo":
        """Create from dictionary."""
        return cls(
            cluster_id=data["cluster_id"],
            name=data["name"],
            endpoint=data["endpoint"],
            role=ClusterRole(data["role"]),
            state=ClusterState(data["state"]),
            region=data.get("region", ""),
            zone=data.get("zone", ""),
            version=data.get("version", ""),
            last_heartbeat=datetime.fromisoformat(data["last_heartbeat"]) if data.get("last_heartbeat") else None,
            last_sync=datetime.fromisoformat(data["last_sync"]) if data.get("last_sync") else None,
            metadata=data.get("metadata", {}),
        )


@dataclass
class SyncEvent:
    """An event to be synchronized across clusters."""
    event_id: str
    source_cluster: str
    scope: SyncScope
    action: str
    data: Dict[str, Any]
    timestamp: datetime
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "source_cluster": self.source_cluster,
            "scope": self.scope.value,
            "action": self.action,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SyncEvent":
        """Create from dictionary."""
        return cls(
            event_id=data["event_id"],
            source_cluster=data["source_cluster"],
            scope=SyncScope(data["scope"]),
            action=data["action"],
            data=data["data"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            version=data.get("version", 1),
        )


class ClusterStore:
    """
    Abstract interface for cluster state storage.

    Implementations can use Redis, etcd, or other distributed stores.
    """

    async def register_cluster(self, info: ClusterInfo) -> bool:
        """Register a cluster in the federation."""
        raise NotImplementedError

    async def deregister_cluster(self, cluster_id: str) -> bool:
        """Remove a cluster from the federation."""
        raise NotImplementedError

    async def get_cluster(self, cluster_id: str) -> Optional[ClusterInfo]:
        """Get cluster information."""
        raise NotImplementedError

    async def list_clusters(self) -> List[ClusterInfo]:
        """List all clusters in the federation."""
        raise NotImplementedError

    async def update_cluster(self, info: ClusterInfo) -> bool:
        """Update cluster information."""
        raise NotImplementedError

    async def acquire_leader_lock(self, cluster_id: str, ttl_seconds: int = 30) -> bool:
        """Try to acquire the leader lock."""
        raise NotImplementedError

    async def release_leader_lock(self, cluster_id: str) -> bool:
        """Release the leader lock."""
        raise NotImplementedError

    async def get_leader(self) -> Optional[str]:
        """Get the current leader cluster ID."""
        raise NotImplementedError

    async def push_sync_event(self, event: SyncEvent) -> bool:
        """Push a sync event for propagation."""
        raise NotImplementedError

    async def get_pending_events(self, cluster_id: str, limit: int = 100) -> List[SyncEvent]:
        """Get pending sync events for a cluster."""
        raise NotImplementedError

    async def ack_event(self, cluster_id: str, event_id: str) -> bool:
        """Acknowledge receipt of a sync event."""
        raise NotImplementedError


class InMemoryClusterStore(ClusterStore):
    """
    In-memory cluster store for development and testing.

    For production, use RedisClusterStore or EtcdClusterStore.
    """

    def __init__(self):
        self._clusters: Dict[str, ClusterInfo] = {}
        self._leader: Optional[str] = None
        self._leader_lock_time: Optional[datetime] = None
        self._leader_lock_ttl: int = 30
        self._events: List[SyncEvent] = []
        self._acked_events: Dict[str, Set[str]] = {}  # cluster_id -> set of event_ids
        self._lock = asyncio.Lock()

    async def register_cluster(self, info: ClusterInfo) -> bool:
        async with self._lock:
            self._clusters[info.cluster_id] = info
            self._acked_events[info.cluster_id] = set()
            logger.info(f"Cluster registered: {info.cluster_id} ({info.name})")
            return True

    async def deregister_cluster(self, cluster_id: str) -> bool:
        async with self._lock:
            if cluster_id in self._clusters:
                del self._clusters[cluster_id]
                if cluster_id in self._acked_events:
                    del self._acked_events[cluster_id]
                if self._leader == cluster_id:
                    self._leader = None
                    self._leader_lock_time = None
                logger.info(f"Cluster deregistered: {cluster_id}")
                return True
            return False

    async def get_cluster(self, cluster_id: str) -> Optional[ClusterInfo]:
        return self._clusters.get(cluster_id)

    async def list_clusters(self) -> List[ClusterInfo]:
        return list(self._clusters.values())

    async def update_cluster(self, info: ClusterInfo) -> bool:
        async with self._lock:
            if info.cluster_id in self._clusters:
                self._clusters[info.cluster_id] = info
                return True
            return False

    async def acquire_leader_lock(self, cluster_id: str, ttl_seconds: int = 30) -> bool:
        async with self._lock:
            now = datetime.utcnow()

            # Check if lock is expired
            if self._leader and self._leader_lock_time:
                if now - self._leader_lock_time > timedelta(seconds=self._leader_lock_ttl):
                    self._leader = None
                    self._leader_lock_time = None

            # Try to acquire lock
            if self._leader is None:
                self._leader = cluster_id
                self._leader_lock_time = now
                self._leader_lock_ttl = ttl_seconds
                logger.info(f"Cluster {cluster_id} acquired leader lock")
                return True

            # Renew if already leader
            if self._leader == cluster_id:
                self._leader_lock_time = now
                return True

            return False

    async def release_leader_lock(self, cluster_id: str) -> bool:
        async with self._lock:
            if self._leader == cluster_id:
                self._leader = None
                self._leader_lock_time = None
                logger.info(f"Cluster {cluster_id} released leader lock")
                return True
            return False

    async def get_leader(self) -> Optional[str]:
        # Check if lock is expired
        if self._leader and self._leader_lock_time:
            if datetime.utcnow() - self._leader_lock_time > timedelta(seconds=self._leader_lock_ttl):
                async with self._lock:
                    self._leader = None
                    self._leader_lock_time = None
        return self._leader

    async def push_sync_event(self, event: SyncEvent) -> bool:
        async with self._lock:
            self._events.append(event)
            # Keep only last 1000 events
            if len(self._events) > 1000:
                self._events = self._events[-1000:]
            return True

    async def get_pending_events(self, cluster_id: str, limit: int = 100) -> List[SyncEvent]:
        acked = self._acked_events.get(cluster_id, set())
        pending = [e for e in self._events if e.event_id not in acked and e.source_cluster != cluster_id]
        return pending[:limit]

    async def ack_event(self, cluster_id: str, event_id: str) -> bool:
        async with self._lock:
            if cluster_id not in self._acked_events:
                self._acked_events[cluster_id] = set()
            self._acked_events[cluster_id].add(event_id)
            return True


class RedisClusterStore(ClusterStore):
    """
    Redis-backed cluster store for production multi-cluster deployments.

    Uses Redis for:
    - Cluster registration and discovery
    - Distributed leader election with SETNX
    - Event synchronization via Redis Streams or Lists

    Requires redis-py (async): pip install redis
    """

    # Redis key prefixes
    CLUSTER_PREFIX = "medic:cluster:"
    LEADER_KEY = "medic:cluster:leader"
    EVENTS_KEY = "medic:cluster:events"
    ACKED_PREFIX = "medic:cluster:acked:"

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        ssl: bool = False,
        max_events: int = 1000,
    ):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.ssl = ssl
        self.max_events = max_events
        self._redis: Optional[Any] = None
        self._connected = False

    async def _ensure_connected(self) -> None:
        """Ensure Redis connection is established."""
        if self._connected and self._redis:
            return

        try:
            import redis.asyncio as redis
        except ImportError:
            raise ImportError(
                "redis package required for RedisClusterStore. "
                "Install with: pip install redis"
            )

        self._redis = redis.Redis(
            host=self.host,
            port=self.port,
            db=self.db,
            password=self.password,
            ssl=self.ssl,
            decode_responses=True,
        )
        self._connected = True
        logger.info(f"Connected to Redis at {self.host}:{self.port}")

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._redis:
            await self._redis.close()
            self._connected = False
            logger.info("Redis connection closed")

    def _cluster_key(self, cluster_id: str) -> str:
        """Get Redis key for a cluster."""
        return f"{self.CLUSTER_PREFIX}{cluster_id}"

    async def register_cluster(self, info: ClusterInfo) -> bool:
        await self._ensure_connected()
        try:
            key = self._cluster_key(info.cluster_id)
            await self._redis.hset(key, mapping=info.to_dict())
            # Set expiration for automatic cleanup of stale clusters
            await self._redis.expire(key, 300)  # 5 minutes
            logger.info(f"Cluster registered in Redis: {info.cluster_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to register cluster: {e}")
            return False

    async def deregister_cluster(self, cluster_id: str) -> bool:
        await self._ensure_connected()
        try:
            key = self._cluster_key(cluster_id)
            await self._redis.delete(key)
            # Clean up acked events
            acked_key = f"{self.ACKED_PREFIX}{cluster_id}"
            await self._redis.delete(acked_key)
            logger.info(f"Cluster deregistered from Redis: {cluster_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to deregister cluster: {e}")
            return False

    async def get_cluster(self, cluster_id: str) -> Optional[ClusterInfo]:
        await self._ensure_connected()
        try:
            key = self._cluster_key(cluster_id)
            data = await self._redis.hgetall(key)
            if data:
                return ClusterInfo.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to get cluster: {e}")
            return None

    async def list_clusters(self) -> List[ClusterInfo]:
        await self._ensure_connected()
        try:
            pattern = f"{self.CLUSTER_PREFIX}*"
            keys = []
            async for key in self._redis.scan_iter(match=pattern):
                if key != self.LEADER_KEY:
                    keys.append(key)

            clusters = []
            for key in keys:
                data = await self._redis.hgetall(key)
                if data:
                    try:
                        clusters.append(ClusterInfo.from_dict(data))
                    except Exception:
                        pass
            return clusters
        except Exception as e:
            logger.error(f"Failed to list clusters: {e}")
            return []

    async def update_cluster(self, info: ClusterInfo) -> bool:
        await self._ensure_connected()
        try:
            key = self._cluster_key(info.cluster_id)
            await self._redis.hset(key, mapping=info.to_dict())
            # Refresh expiration
            await self._redis.expire(key, 300)
            return True
        except Exception as e:
            logger.error(f"Failed to update cluster: {e}")
            return False

    async def acquire_leader_lock(self, cluster_id: str, ttl_seconds: int = 30) -> bool:
        await self._ensure_connected()
        try:
            # Try to set leader with NX (only if not exists) and EX (with expiration)
            result = await self._redis.set(
                self.LEADER_KEY,
                cluster_id,
                nx=True,
                ex=ttl_seconds,
            )

            if result:
                logger.info(f"Cluster {cluster_id} acquired leader lock via Redis")
                return True

            # Check if we already hold the lock
            current_leader = await self._redis.get(self.LEADER_KEY)
            if current_leader == cluster_id:
                # Refresh the TTL
                await self._redis.expire(self.LEADER_KEY, ttl_seconds)
                return True

            return False
        except Exception as e:
            logger.error(f"Failed to acquire leader lock: {e}")
            return False

    async def release_leader_lock(self, cluster_id: str) -> bool:
        await self._ensure_connected()
        try:
            # Only release if we hold the lock
            current_leader = await self._redis.get(self.LEADER_KEY)
            if current_leader == cluster_id:
                await self._redis.delete(self.LEADER_KEY)
                logger.info(f"Cluster {cluster_id} released leader lock")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to release leader lock: {e}")
            return False

    async def get_leader(self) -> Optional[str]:
        await self._ensure_connected()
        try:
            return await self._redis.get(self.LEADER_KEY)
        except Exception as e:
            logger.error(f"Failed to get leader: {e}")
            return None

    async def push_sync_event(self, event: SyncEvent) -> bool:
        await self._ensure_connected()
        try:
            import json
            event_data = json.dumps(event.to_dict())
            await self._redis.lpush(self.EVENTS_KEY, event_data)
            # Trim to max events
            await self._redis.ltrim(self.EVENTS_KEY, 0, self.max_events - 1)
            return True
        except Exception as e:
            logger.error(f"Failed to push sync event: {e}")
            return False

    async def get_pending_events(self, cluster_id: str, limit: int = 100) -> List[SyncEvent]:
        await self._ensure_connected()
        try:
            import json

            # Get acked event IDs for this cluster
            acked_key = f"{self.ACKED_PREFIX}{cluster_id}"
            acked = await self._redis.smembers(acked_key)

            # Get events from list
            events_data = await self._redis.lrange(self.EVENTS_KEY, 0, limit * 2)

            pending = []
            for data in events_data:
                try:
                    event = SyncEvent.from_dict(json.loads(data))
                    # Skip if already acked or from same cluster
                    if event.event_id not in acked and event.source_cluster != cluster_id:
                        pending.append(event)
                        if len(pending) >= limit:
                            break
                except Exception:
                    pass

            return pending
        except Exception as e:
            logger.error(f"Failed to get pending events: {e}")
            return []

    async def ack_event(self, cluster_id: str, event_id: str) -> bool:
        await self._ensure_connected()
        try:
            acked_key = f"{self.ACKED_PREFIX}{cluster_id}"
            await self._redis.sadd(acked_key, event_id)
            # Keep acked set manageable
            await self._redis.expire(acked_key, 86400)  # 24 hours
            return True
        except Exception as e:
            logger.error(f"Failed to ack event: {e}")
            return False


class EtcdClusterStore(ClusterStore):
    """
    Etcd-backed cluster store for production multi-cluster deployments.

    Uses etcd for:
    - Cluster registration and discovery with TTL-based leases
    - Distributed leader election with etcd's lease mechanism
    - Event synchronization via key-value storage

    Requires etcd3: pip install etcd3
    """

    # Etcd key prefixes
    CLUSTER_PREFIX = "/medic/cluster/nodes/"
    LEADER_KEY = "/medic/cluster/leader"
    EVENTS_PREFIX = "/medic/cluster/events/"
    ACKED_PREFIX = "/medic/cluster/acked/"

    def __init__(
        self,
        endpoints: Optional[List[str]] = None,
        host: str = "localhost",
        port: int = 2379,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        ca_file: Optional[str] = None,
        timeout: int = 10,
        max_events: int = 1000,
    ):
        self.endpoints = endpoints or [f"{host}:{port}"]
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.timeout = timeout
        self.max_events = max_events
        self._client: Optional[Any] = None
        self._connected = False
        self._lease: Optional[Any] = None
        self._lease_id: Optional[int] = None

    async def _ensure_connected(self) -> None:
        """Ensure etcd connection is established."""
        if self._connected and self._client:
            return

        try:
            import etcd3
        except ImportError:
            raise ImportError(
                "etcd3 package required for EtcdClusterStore. "
                "Install with: pip install etcd3"
            )

        # Parse first endpoint for host/port if using endpoints list
        if self.endpoints:
            first_endpoint = self.endpoints[0]
            if ":" in first_endpoint:
                parts = first_endpoint.rsplit(":", 1)
                self.host = parts[0].replace("https://", "").replace("http://", "")
                self.port = int(parts[1])

        # Build SSL/TLS configuration if certificates provided
        if self.cert_file and self.key_file:
            self._client = etcd3.client(
                host=self.host,
                port=self.port,
                cert_cert=self.cert_file,
                cert_key=self.key_file,
                ca_cert=self.ca_file,
                timeout=self.timeout,
            )
        else:
            self._client = etcd3.client(
                host=self.host,
                port=self.port,
                timeout=self.timeout,
            )

        self._connected = True
        logger.info(f"Connected to etcd at {self.host}:{self.port}")

    async def close(self) -> None:
        """Close the etcd connection."""
        if self._lease_id and self._client:
            try:
                self._client.revoke_lease(self._lease_id)
            except Exception:
                pass
        if self._client:
            self._client.close()
            self._connected = False
            self._client = None
            logger.info("Etcd connection closed")

    def _cluster_key(self, cluster_id: str) -> str:
        """Get etcd key for a cluster."""
        return f"{self.CLUSTER_PREFIX}{cluster_id}"

    def _run_sync(self, func, *args, **kwargs):
        """Run a synchronous etcd3 function (etcd3 lib is sync-only)."""
        import asyncio
        loop = asyncio.get_event_loop()
        return loop.run_in_executor(None, lambda: func(*args, **kwargs))

    async def register_cluster(self, info: ClusterInfo) -> bool:
        await self._ensure_connected()
        try:
            import json

            key = self._cluster_key(info.cluster_id)
            value = json.dumps(info.to_dict())

            # Create a lease for automatic cleanup (5 minutes = 300 seconds)
            lease = self._client.lease(300)
            self._client.put(key, value, lease=lease)

            logger.info(f"Cluster registered in etcd: {info.cluster_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to register cluster in etcd: {e}")
            return False

    async def deregister_cluster(self, cluster_id: str) -> bool:
        await self._ensure_connected()
        try:
            key = self._cluster_key(cluster_id)
            self._client.delete(key)

            # Clean up acked events
            acked_prefix = f"{self.ACKED_PREFIX}{cluster_id}/"
            self._client.delete_prefix(acked_prefix)

            logger.info(f"Cluster deregistered from etcd: {cluster_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to deregister cluster from etcd: {e}")
            return False

    async def get_cluster(self, cluster_id: str) -> Optional[ClusterInfo]:
        await self._ensure_connected()
        try:
            import json

            key = self._cluster_key(cluster_id)
            value, _ = self._client.get(key)

            if value:
                data = json.loads(value.decode("utf-8"))
                return ClusterInfo.from_dict(data)
            return None
        except Exception as e:
            logger.error(f"Failed to get cluster from etcd: {e}")
            return None

    async def list_clusters(self) -> List[ClusterInfo]:
        await self._ensure_connected()
        try:
            import json

            clusters = []
            for value, metadata in self._client.get_prefix(self.CLUSTER_PREFIX):
                if value:
                    try:
                        data = json.loads(value.decode("utf-8"))
                        clusters.append(ClusterInfo.from_dict(data))
                    except Exception:
                        pass

            return clusters
        except Exception as e:
            logger.error(f"Failed to list clusters from etcd: {e}")
            return []

    async def update_cluster(self, info: ClusterInfo) -> bool:
        await self._ensure_connected()
        try:
            import json

            key = self._cluster_key(info.cluster_id)
            value = json.dumps(info.to_dict())

            # Create new lease and update
            lease = self._client.lease(300)
            self._client.put(key, value, lease=lease)

            return True
        except Exception as e:
            logger.error(f"Failed to update cluster in etcd: {e}")
            return False

    async def acquire_leader_lock(self, cluster_id: str, ttl_seconds: int = 30) -> bool:
        await self._ensure_connected()
        try:
            # Create or refresh lease for leader lock
            if not self._lease_id:
                lease = self._client.lease(ttl_seconds)
                self._lease_id = lease.id
            else:
                # Refresh existing lease
                try:
                    self._client.refresh_lease(self._lease_id)
                except Exception:
                    # Lease expired, create new one
                    lease = self._client.lease(ttl_seconds)
                    self._lease_id = lease.id

            # Try to acquire leader lock using transaction
            # put_if_not_exists pattern
            current_value, _ = self._client.get(self.LEADER_KEY)

            if current_value is None:
                # No leader, try to become leader
                lease = self._client.lease(ttl_seconds)
                self._lease_id = lease.id
                success, _ = self._client.transaction(
                    compare=[
                        self._client.transactions.version(self.LEADER_KEY) == 0
                    ],
                    success=[
                        self._client.transactions.put(
                            self.LEADER_KEY, cluster_id, lease=lease
                        )
                    ],
                    failure=[],
                )

                if success:
                    logger.info(f"Cluster {cluster_id} acquired leader lock via etcd")
                    return True
            elif current_value.decode("utf-8") == cluster_id:
                # We already hold the lock, refresh it
                lease = self._client.lease(ttl_seconds)
                self._client.put(self.LEADER_KEY, cluster_id, lease=lease)
                return True

            return False
        except Exception as e:
            logger.error(f"Failed to acquire leader lock in etcd: {e}")
            return False

    async def release_leader_lock(self, cluster_id: str) -> bool:
        await self._ensure_connected()
        try:
            current_value, _ = self._client.get(self.LEADER_KEY)

            if current_value and current_value.decode("utf-8") == cluster_id:
                self._client.delete(self.LEADER_KEY)
                if self._lease_id:
                    try:
                        self._client.revoke_lease(self._lease_id)
                    except Exception:
                        pass
                    self._lease_id = None
                logger.info(f"Cluster {cluster_id} released leader lock")
                return True

            return False
        except Exception as e:
            logger.error(f"Failed to release leader lock in etcd: {e}")
            return False

    async def get_leader(self) -> Optional[str]:
        await self._ensure_connected()
        try:
            value, _ = self._client.get(self.LEADER_KEY)
            if value:
                return value.decode("utf-8")
            return None
        except Exception as e:
            logger.error(f"Failed to get leader from etcd: {e}")
            return None

    async def push_sync_event(self, event: SyncEvent) -> bool:
        await self._ensure_connected()
        try:
            import json
            import time

            # Use timestamp-based key for ordering
            key = f"{self.EVENTS_PREFIX}{int(time.time() * 1000000)}_{event.event_id}"
            value = json.dumps(event.to_dict())

            # Create lease for automatic cleanup (1 hour)
            lease = self._client.lease(3600)
            self._client.put(key, value, lease=lease)

            # Cleanup old events if too many
            await self._cleanup_old_events()

            return True
        except Exception as e:
            logger.error(f"Failed to push sync event to etcd: {e}")
            return False

    async def _cleanup_old_events(self) -> None:
        """Remove oldest events if over limit."""
        try:
            events = list(self._client.get_prefix(self.EVENTS_PREFIX))
            if len(events) > self.max_events:
                # Sort by key (timestamp-based) and delete oldest
                sorted_events = sorted(events, key=lambda x: x[1].key)
                to_delete = len(events) - self.max_events
                for _, metadata in sorted_events[:to_delete]:
                    self._client.delete(metadata.key)
        except Exception as e:
            logger.debug(f"Failed to cleanup old events: {e}")

    async def get_pending_events(self, cluster_id: str, limit: int = 100) -> List[SyncEvent]:
        await self._ensure_connected()
        try:
            import json

            # Get acked event IDs for this cluster
            acked_prefix = f"{self.ACKED_PREFIX}{cluster_id}/"
            acked = set()
            for value, _ in self._client.get_prefix(acked_prefix):
                if value:
                    acked.add(value.decode("utf-8"))

            # Get events
            pending = []
            for value, metadata in self._client.get_prefix(self.EVENTS_PREFIX):
                if value:
                    try:
                        event = SyncEvent.from_dict(json.loads(value.decode("utf-8")))
                        # Skip if already acked or from same cluster
                        if event.event_id not in acked and event.source_cluster != cluster_id:
                            pending.append(event)
                            if len(pending) >= limit:
                                break
                    except Exception:
                        pass

            return pending
        except Exception as e:
            logger.error(f"Failed to get pending events from etcd: {e}")
            return []

    async def ack_event(self, cluster_id: str, event_id: str) -> bool:
        await self._ensure_connected()
        try:
            key = f"{self.ACKED_PREFIX}{cluster_id}/{event_id}"

            # Create lease for automatic cleanup (24 hours)
            lease = self._client.lease(86400)
            self._client.put(key, event_id, lease=lease)

            return True
        except Exception as e:
            logger.error(f"Failed to ack event in etcd: {e}")
            return False


def create_cluster_store(config: Dict[str, Any]) -> ClusterStore:
    """
    Factory function to create a cluster store based on configuration.

    Args:
        config: Cluster configuration dict with 'store' section

    Returns:
        Appropriate ClusterStore implementation
    """
    store_config = config.get("store", {})
    store_type = store_config.get("type", "memory")

    if store_type == "redis":
        redis_config = store_config.get("redis", {})
        return RedisClusterStore(
            host=redis_config.get("host", "localhost"),
            port=redis_config.get("port", 6379),
            db=redis_config.get("db", 0),
            password=redis_config.get("password"),
            ssl=redis_config.get("ssl", False),
        )
    elif store_type == "etcd":
        etcd_config = store_config.get("etcd", {})
        return EtcdClusterStore(
            endpoints=etcd_config.get("endpoints"),
            host=etcd_config.get("host", "localhost"),
            port=etcd_config.get("port", 2379),
            cert_file=etcd_config.get("cert_file"),
            key_file=etcd_config.get("key_file"),
            ca_file=etcd_config.get("ca_cert"),
            timeout=etcd_config.get("timeout", 10),
        )
    elif store_type == "memory":
        return InMemoryClusterStore()
    else:
        logger.warning(f"Unknown store type '{store_type}', using in-memory")
        return InMemoryClusterStore()


class ClusterManager:
    """
    Manages cluster federation for multi-cluster Medic deployments.

    Responsibilities:
    - Cluster registration and discovery
    - Leader election
    - State synchronization
    - Cross-cluster communication
    - Failover handling
    """

    def __init__(
        self,
        cluster_id: str,
        cluster_name: str,
        endpoint: str,
        store: Optional[ClusterStore] = None,
        region: str = "",
        zone: str = "",
    ):
        self.cluster_id = cluster_id
        self.cluster_name = cluster_name
        self.endpoint = endpoint
        self.region = region
        self.zone = zone

        self._store = store or InMemoryClusterStore()
        self._role = ClusterRole.OBSERVER
        self._state = ClusterState.HEALTHY
        self._running = False

        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._election_task: Optional[asyncio.Task] = None
        self._sync_task: Optional[asyncio.Task] = None

        # Event handlers
        self._event_handlers: Dict[SyncScope, List[Callable]] = {
            scope: [] for scope in SyncScope
        }

        # Configuration
        self._heartbeat_interval = 10  # seconds
        self._election_interval = 15  # seconds
        self._sync_interval = 5  # seconds
        self._leader_ttl = 30  # seconds

    @property
    def role(self) -> ClusterRole:
        """Get the current cluster role."""
        return self._role

    @property
    def state(self) -> ClusterState:
        """Get the current cluster state."""
        return self._state

    @property
    def is_leader(self) -> bool:
        """Check if this cluster is the leader."""
        return self._role == ClusterRole.LEADER

    def get_cluster_info(self) -> ClusterInfo:
        """Get information about this cluster."""
        return ClusterInfo(
            cluster_id=self.cluster_id,
            name=self.cluster_name,
            endpoint=self.endpoint,
            role=self._role,
            state=self._state,
            region=self.region,
            zone=self.zone,
            version="0.2.0",
            last_heartbeat=datetime.utcnow(),
        )

    async def start(self) -> None:
        """Start the cluster manager."""
        if self._running:
            return

        self._running = True

        # Register this cluster
        await self._store.register_cluster(self.get_cluster_info())

        # Start background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._election_task = asyncio.create_task(self._election_loop())
        self._sync_task = asyncio.create_task(self._sync_loop())

        logger.info(f"Cluster manager started: {self.cluster_id}")

    async def stop(self) -> None:
        """Stop the cluster manager."""
        self._running = False

        # Cancel background tasks
        for task in [self._heartbeat_task, self._election_task, self._sync_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Release leader lock if held
        if self._role == ClusterRole.LEADER:
            await self._store.release_leader_lock(self.cluster_id)

        # Deregister cluster
        await self._store.deregister_cluster(self.cluster_id)

        logger.info(f"Cluster manager stopped: {self.cluster_id}")

    def register_event_handler(
        self,
        scope: SyncScope,
        handler: Callable[[SyncEvent], None],
    ) -> None:
        """Register a handler for sync events."""
        self._event_handlers[scope].append(handler)

    async def publish_event(
        self,
        scope: SyncScope,
        action: str,
        data: Dict[str, Any],
    ) -> str:
        """
        Publish an event for synchronization across clusters.

        Args:
            scope: Type of data being synchronized
            action: Action performed (create, update, delete)
            data: Event data

        Returns:
            Event ID
        """
        event = SyncEvent(
            event_id=str(uuid.uuid4()),
            source_cluster=self.cluster_id,
            scope=scope,
            action=action,
            data=data,
            timestamp=datetime.utcnow(),
        )

        await self._store.push_sync_event(event)
        logger.debug(f"Published sync event: {event.event_id} ({scope.value}/{action})")

        return event.event_id

    async def get_clusters(self) -> List[ClusterInfo]:
        """Get list of all clusters in the federation."""
        return await self._store.list_clusters()

    async def get_leader_cluster(self) -> Optional[ClusterInfo]:
        """Get the leader cluster information."""
        leader_id = await self._store.get_leader()
        if leader_id:
            return await self._store.get_cluster(leader_id)
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get cluster manager statistics."""
        return {
            "cluster_id": self.cluster_id,
            "cluster_name": self.cluster_name,
            "role": self._role.value,
            "state": self._state.value,
            "region": self.region,
            "zone": self.zone,
            "is_leader": self.is_leader,
            "running": self._running,
        }

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to update cluster status."""
        while self._running:
            try:
                info = self.get_cluster_info()
                await self._store.update_cluster(info)

                # Check health of other clusters
                await self._check_cluster_health()

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

            await asyncio.sleep(self._heartbeat_interval)

    async def _election_loop(self) -> None:
        """Participate in leader election."""
        while self._running:
            try:
                current_leader = await self._store.get_leader()

                if current_leader == self.cluster_id:
                    # We are the leader, renew lock
                    if await self._store.acquire_leader_lock(self.cluster_id, self._leader_ttl):
                        self._role = ClusterRole.LEADER
                    else:
                        self._role = ClusterRole.FOLLOWER
                elif current_leader is None:
                    # No leader, try to become one
                    self._role = ClusterRole.CANDIDATE
                    if await self._store.acquire_leader_lock(self.cluster_id, self._leader_ttl):
                        self._role = ClusterRole.LEADER
                        logger.info(f"Cluster {self.cluster_id} became leader")
                    else:
                        self._role = ClusterRole.FOLLOWER
                else:
                    # Someone else is leader
                    self._role = ClusterRole.FOLLOWER

            except Exception as e:
                logger.error(f"Election error: {e}")

            await asyncio.sleep(self._election_interval)

    async def _sync_loop(self) -> None:
        """Process sync events from other clusters."""
        while self._running:
            try:
                # Get pending events
                events = await self._store.get_pending_events(self.cluster_id)

                for event in events:
                    await self._process_sync_event(event)
                    await self._store.ack_event(self.cluster_id, event.event_id)

            except Exception as e:
                logger.error(f"Sync error: {e}")

            await asyncio.sleep(self._sync_interval)

    async def _process_sync_event(self, event: SyncEvent) -> None:
        """Process a sync event from another cluster."""
        logger.debug(f"Processing sync event: {event.event_id} from {event.source_cluster}")

        # Call registered handlers
        handlers = self._event_handlers.get(event.scope, [])
        handlers.extend(self._event_handlers.get(SyncScope.ALL, []))

        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"Error in sync event handler: {e}")

    async def _check_cluster_health(self) -> None:
        """Check health of all clusters in the federation."""
        clusters = await self._store.list_clusters()
        now = datetime.utcnow()

        for cluster in clusters:
            if cluster.cluster_id == self.cluster_id:
                continue

            if cluster.last_heartbeat:
                age = now - cluster.last_heartbeat
                if age > timedelta(seconds=self._heartbeat_interval * 3):
                    # Mark as unreachable
                    cluster.state = ClusterState.UNREACHABLE
                    await self._store.update_cluster(cluster)
                    logger.warning(f"Cluster {cluster.cluster_id} marked unreachable")


# Singleton instance
_cluster_manager: Optional[ClusterManager] = None


def get_cluster_manager() -> Optional[ClusterManager]:
    """Get the global cluster manager instance."""
    return _cluster_manager


def init_cluster_manager(
    cluster_id: str,
    cluster_name: str,
    endpoint: str,
    store: Optional[ClusterStore] = None,
    region: str = "",
    zone: str = "",
) -> ClusterManager:
    """Initialize the global cluster manager."""
    global _cluster_manager
    _cluster_manager = ClusterManager(
        cluster_id=cluster_id,
        cluster_name=cluster_name,
        endpoint=endpoint,
        store=store,
        region=region,
        zone=zone,
    )
    return _cluster_manager


async def publish_cluster_event(
    scope: SyncScope,
    action: str,
    data: Dict[str, Any],
) -> Optional[str]:
    """
    Convenience function to publish a cluster event.

    Returns event ID if cluster manager is active, None otherwise.
    """
    manager = get_cluster_manager()
    if manager and manager._running:
        return await manager.publish_event(scope, action, data)
    return None
