"""
Medic Agent Resurrector

Handles the actual resurrection of killed modules, including
restore operations, health verification, and rollback procedures.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import uuid

from core.models import (
    ResurrectionRequest,
    ResurrectionStatus,
    ResurrectionDecision,
    KillReport,
)
from core.logger import get_logger, LogContext

logger = get_logger("execution.resurrector")


class ResurrectionMethod(Enum):
    """Method used to resurrect a module."""
    RESTART = "restart"           # Simple restart
    RESTORE_SNAPSHOT = "snapshot" # Restore from snapshot
    REDEPLOY = "redeploy"         # Full redeployment
    SCALE_UP = "scale_up"         # Scale up new instances
    FAILOVER = "failover"         # Failover to backup


@dataclass
class ResurrectionResult:
    """Result of a resurrection attempt."""
    request_id: str
    success: bool
    method_used: ResurrectionMethod
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    new_instance_id: Optional[str] = None
    health_check_passed: bool = False
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "success": self.success,
            "method_used": self.method_used.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "new_instance_id": self.new_instance_id,
            "health_check_passed": self.health_check_passed,
            "error_message": self.error_message,
            "metrics": self.metrics,
        }


class Resurrector(ABC):
    """
    Abstract interface for resurrection execution.

    Implementations handle the actual mechanics of bringing
    killed modules back to life.
    """

    @abstractmethod
    async def resurrect(self, request: ResurrectionRequest) -> ResurrectionResult:
        """
        Execute resurrection workflow.

        Args:
            request: The resurrection request to execute

        Returns:
            ResurrectionResult with outcome details
        """
        pass

    @abstractmethod
    async def rollback(self, request_id: str, reason: str) -> bool:
        """
        Rollback a resurrection.

        Args:
            request_id: The request to rollback
            reason: Reason for rollback

        Returns:
            True if rollback succeeded
        """
        pass

    @abstractmethod
    async def get_status(self, request_id: str) -> Optional[ResurrectionStatus]:
        """Get current status of a resurrection request."""
        pass

    @abstractmethod
    def can_resurrect(self, target_module: str) -> bool:
        """Check if a module is eligible for resurrection."""
        pass


class ModuleResurrector(Resurrector):
    """
    Default implementation of module resurrection.

    Supports multiple resurrection methods and integrates
    with container orchestration systems.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        executor: Optional[Callable] = None,
    ):
        self.config = config or {}

        # Resurrection settings
        self.default_method = ResurrectionMethod(
            self.config.get("default_method", "restart")
        )
        self.max_retries = self.config.get("max_retries", 2)
        self.health_check_timeout = self.config.get("health_check_timeout", 30)
        self.startup_grace_period = self.config.get("startup_grace_period", 10)

        # External executor (for actual system commands)
        self._executor = executor or self._default_executor

        # State tracking
        self._active_requests: Dict[str, ResurrectionRequest] = {}
        self._results: Dict[str, ResurrectionResult] = {}

        # Blacklist
        self._blacklist = set(self.config.get("blacklist", []))

    async def resurrect(self, request: ResurrectionRequest) -> ResurrectionResult:
        """Execute the resurrection workflow."""
        with LogContext(
            request_id=request.request_id,
            kill_id=request.kill_id,
            target_module=request.target_module,
        ):
            logger.info(
                "Starting resurrection",
                target_instance=request.target_instance_id,
            )

            started_at = datetime.utcnow()
            self._active_requests[request.request_id] = request

            # Update request status
            request.status = ResurrectionStatus.IN_PROGRESS
            request.executed_at = started_at

            try:
                # Determine resurrection method
                method = self._select_method(request)

                # Execute resurrection
                new_instance_id = await self._execute_resurrection(
                    request, method
                )

                # Wait for startup
                await asyncio.sleep(self.startup_grace_period)

                # Perform health check
                health_passed = await self._perform_health_check(
                    request.target_module,
                    new_instance_id or request.target_instance_id,
                )

                completed_at = datetime.utcnow()
                duration = (completed_at - started_at).total_seconds()

                if health_passed:
                    request.status = ResurrectionStatus.COMPLETED
                    request.completed_at = completed_at

                    result = ResurrectionResult(
                        request_id=request.request_id,
                        success=True,
                        method_used=method,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_seconds=duration,
                        new_instance_id=new_instance_id,
                        health_check_passed=True,
                        metrics={"startup_time": self.startup_grace_period},
                    )

                    logger.info(
                        "Resurrection completed successfully",
                        duration=duration,
                        method=method.value,
                    )
                else:
                    # Health check failed - trigger rollback
                    request.status = ResurrectionStatus.FAILED

                    result = ResurrectionResult(
                        request_id=request.request_id,
                        success=False,
                        method_used=method,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_seconds=duration,
                        new_instance_id=new_instance_id,
                        health_check_passed=False,
                        error_message="Health check failed after resurrection",
                    )

                    logger.warning(
                        "Resurrection failed health check",
                        duration=duration,
                    )

            except Exception as e:
                completed_at = datetime.utcnow()
                duration = (completed_at - started_at).total_seconds()

                request.status = ResurrectionStatus.FAILED

                result = ResurrectionResult(
                    request_id=request.request_id,
                    success=False,
                    method_used=self.default_method,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=duration,
                    error_message=str(e),
                )

                logger.error(
                    f"Resurrection failed: {e}",
                    duration=duration,
                    exc_info=True,
                )

            finally:
                self._results[request.request_id] = result
                del self._active_requests[request.request_id]

            return result

    async def rollback(self, request_id: str, reason: str) -> bool:
        """Rollback a resurrection by killing the resurrected module."""
        logger.info(
            "Initiating rollback",
            request_id=request_id,
            reason=reason,
        )

        result = self._results.get(request_id)
        if not result:
            logger.warning(f"No result found for request: {request_id}")
            return False

        if not result.success:
            logger.info("Request already failed, no rollback needed")
            return True

        try:
            # Execute rollback (kill the resurrected instance)
            instance_id = result.new_instance_id or request_id
            await self._executor(
                "rollback",
                instance_id,
                reason=reason,
            )

            logger.info("Rollback completed", request_id=request_id)
            return True

        except Exception as e:
            logger.error(f"Rollback failed: {e}", exc_info=True)
            return False

    async def get_status(self, request_id: str) -> Optional[ResurrectionStatus]:
        """Get current status of a resurrection request."""
        # Check active requests
        if request_id in self._active_requests:
            return self._active_requests[request_id].status

        # Check completed results
        if request_id in self._results:
            result = self._results[request_id]
            if result.success:
                return ResurrectionStatus.COMPLETED
            else:
                return ResurrectionStatus.FAILED

        return None

    def can_resurrect(self, target_module: str) -> bool:
        """Check if a module can be resurrected."""
        # Check blacklist
        if target_module in self._blacklist:
            logger.debug(f"Module {target_module} is blacklisted")
            return False

        # Check for active resurrection
        for request in self._active_requests.values():
            if request.target_module == target_module:
                logger.debug(f"Module {target_module} has active resurrection")
                return False

        return True

    def _select_method(self, request: ResurrectionRequest) -> ResurrectionMethod:
        """Select the appropriate resurrection method."""
        # Check for method override in request metadata
        # For now, use default method
        return self.default_method

    async def _execute_resurrection(
        self,
        request: ResurrectionRequest,
        method: ResurrectionMethod,
    ) -> Optional[str]:
        """Execute the actual resurrection operation."""
        logger.debug(
            f"Executing resurrection with method: {method.value}",
            target_module=request.target_module,
        )

        # Call external executor
        result = await self._executor(
            method.value,
            request.target_module,
            instance_id=request.target_instance_id,
            request_id=request.request_id,
        )

        # Return new instance ID if available
        if isinstance(result, dict):
            return result.get("new_instance_id")

        return None

    async def _perform_health_check(
        self,
        module: str,
        instance_id: str,
    ) -> bool:
        """Perform health check on resurrected module."""
        logger.debug(
            "Performing health check",
            module=module,
            instance=instance_id,
        )

        try:
            result = await asyncio.wait_for(
                self._executor(
                    "health_check",
                    module,
                    instance_id=instance_id,
                ),
                timeout=self.health_check_timeout,
            )

            if isinstance(result, dict):
                return result.get("healthy", False)

            return bool(result)

        except asyncio.TimeoutError:
            logger.warning("Health check timed out")
            return False
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    async def _default_executor(
        self,
        action: str,
        target: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Default executor for resurrection operations.

        This is a placeholder that simulates resurrection operations.
        In production, this would interface with container orchestration
        systems like Kubernetes, Docker Swarm, etc.
        """
        logger.debug(f"Mock executor: {action} on {target}", **kwargs)

        # Simulate operation delay
        await asyncio.sleep(0.5)

        if action == "restart":
            return {
                "success": True,
                "new_instance_id": f"{target}-{uuid.uuid4().hex[:8]}",
            }

        if action == "health_check":
            # Simulate health check (90% success rate for testing)
            import random
            return {"healthy": random.random() > 0.1}

        if action == "rollback":
            return {"success": True}

        return {"success": True}

    def get_active_count(self) -> int:
        """Get count of active resurrections."""
        return len(self._active_requests)

    def get_statistics(self) -> Dict[str, Any]:
        """Get resurrection statistics."""
        total = len(self._results)
        if total == 0:
            return {
                "total": 0,
                "success_rate": 0.0,
                "avg_duration": 0.0,
            }

        successful = sum(1 for r in self._results.values() if r.success)
        total_duration = sum(r.duration_seconds for r in self._results.values())

        return {
            "total": total,
            "successful": successful,
            "failed": total - successful,
            "success_rate": successful / total,
            "avg_duration": total_duration / total,
            "active": len(self._active_requests),
        }


class KubernetesResurrector(Resurrector):
    """
    Kubernetes-based resurrection implementation.

    Interfaces with Kubernetes API to manage pod resurrection.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.namespace = self.config.get("namespace", "default")
        self._k8s_client = None

        # State
        self._active_requests: Dict[str, ResurrectionRequest] = {}
        self._results: Dict[str, ResurrectionResult] = {}

    async def _get_client(self):
        """Get or create Kubernetes client."""
        if self._k8s_client is None:
            try:
                from kubernetes import client, config as k8s_config
                k8s_config.load_incluster_config()
                self._k8s_client = client.CoreV1Api()
            except Exception:
                # Fall back to local config
                try:
                    from kubernetes import client, config as k8s_config
                    k8s_config.load_kube_config()
                    self._k8s_client = client.CoreV1Api()
                except Exception as e:
                    logger.error(f"Failed to initialize Kubernetes client: {e}")
                    raise

        return self._k8s_client

    async def resurrect(self, request: ResurrectionRequest) -> ResurrectionResult:
        """Resurrect a Kubernetes pod."""
        started_at = datetime.utcnow()

        try:
            client = await self._get_client()

            # Delete the old pod (Kubernetes will recreate it)
            await asyncio.to_thread(
                client.delete_namespaced_pod,
                name=request.target_instance_id,
                namespace=self.namespace,
            )

            # Wait for new pod
            await asyncio.sleep(5)

            # Verify new pod is running
            pods = await asyncio.to_thread(
                client.list_namespaced_pod,
                namespace=self.namespace,
                label_selector=f"app={request.target_module}",
            )

            new_pod = None
            for pod in pods.items:
                if pod.status.phase == "Running":
                    new_pod = pod
                    break

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            if new_pod:
                return ResurrectionResult(
                    request_id=request.request_id,
                    success=True,
                    method_used=ResurrectionMethod.RESTART,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=duration,
                    new_instance_id=new_pod.metadata.name,
                    health_check_passed=True,
                )
            else:
                return ResurrectionResult(
                    request_id=request.request_id,
                    success=False,
                    method_used=ResurrectionMethod.RESTART,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=duration,
                    error_message="New pod not found in Running state",
                )

        except Exception as e:
            completed_at = datetime.utcnow()
            return ResurrectionResult(
                request_id=request.request_id,
                success=False,
                method_used=ResurrectionMethod.RESTART,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=(completed_at - started_at).total_seconds(),
                error_message=str(e),
            )

    async def rollback(self, request_id: str, reason: str) -> bool:
        """Rollback by deleting the resurrected pod."""
        result = self._results.get(request_id)
        if not result or not result.new_instance_id:
            return False

        try:
            client = await self._get_client()
            await asyncio.to_thread(
                client.delete_namespaced_pod,
                name=result.new_instance_id,
                namespace=self.namespace,
            )
            return True
        except Exception as e:
            logger.error(f"K8s rollback failed: {e}")
            return False

    async def get_status(self, request_id: str) -> Optional[ResurrectionStatus]:
        """Get status from Kubernetes."""
        if request_id in self._active_requests:
            return self._active_requests[request_id].status
        if request_id in self._results:
            return (
                ResurrectionStatus.COMPLETED
                if self._results[request_id].success
                else ResurrectionStatus.FAILED
            )
        return None

    def can_resurrect(self, target_module: str) -> bool:
        """Check if module can be resurrected in Kubernetes."""
        return True  # Assume all modules can be resurrected


def create_resurrector(config: Dict[str, Any]) -> Resurrector:
    """Factory function to create the appropriate resurrector."""
    resurrection_config = config.get("resurrection", {})
    backend = resurrection_config.get("backend", "default")

    if backend == "kubernetes":
        return KubernetesResurrector(resurrection_config)

    return ModuleResurrector(resurrection_config)
