"""
Medic Agent Container Resurrector

Restarts containers that were killed by Smith, after the decision
engine approves resurrection. Uses the Docker API directly.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.logger import get_logger
from core.models import KillReport, ResurrectionDecision

logger = get_logger("core.resurrector")


@dataclass
class ResurrectionResult:
    """Result of a resurrection attempt."""
    success: bool
    target_module: str
    target_instance_id: str
    container_id: Optional[str] = None
    started_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    health_status: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class Resurrector(ABC):
    """Abstract interface for container resurrection."""

    @abstractmethod
    def resurrect(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
    ) -> ResurrectionResult:
        """
        Attempt to resurrect a killed container.

        Returns a ResurrectionResult with success/failure and timing info.
        """
        pass

    @abstractmethod
    def health_check(self, container_name: str) -> Optional[str]:
        """
        Check health status of a container.

        Returns health status string or None if container not found.
        """
        pass


class DockerResurrector(Resurrector):
    """
    Resurrects containers via Docker API.

    Finds the stopped container by name/label matching and restarts it.
    Waits for it to become healthy before reporting success.
    """

    def __init__(
        self,
        health_check_timeout: int = 30,
        restart_timeout: int = 30,
        label_prefix: str = "medic.module",
    ):
        self.health_check_timeout = health_check_timeout
        self.restart_timeout = restart_timeout
        self.label_prefix = label_prefix
        self._client = None

    def _get_client(self):
        """Lazy-init Docker client."""
        if self._client is None:
            import docker
            self._client = docker.from_env()
        return self._client

    def _find_container(self, kill_report: KillReport):
        """
        Find the target container by instance ID or module name.

        Lookup order:
        1. Container name matches target_instance_id
        2. Container has label medic.module=<target_module>
        3. Container name contains target_module
        """
        client = self._get_client()

        # Try by exact container name (instance ID)
        try:
            return client.containers.get(kill_report.target_instance_id)
        except Exception:
            pass

        # Try by label
        label_filter = {f"{self.label_prefix}": kill_report.target_module}
        containers = client.containers.list(all=True, filters={"label": label_filter})
        if containers:
            return containers[0]

        # Try by name containing module name
        all_containers = client.containers.list(all=True)
        for c in all_containers:
            if kill_report.target_module in c.name:
                return c

        return None

    def resurrect(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
    ) -> ResurrectionResult:
        """Restart the killed container via Docker API."""
        t0 = time.monotonic()

        try:
            container = self._find_container(kill_report)
        except Exception as e:
            elapsed = time.monotonic() - t0
            logger.error("Docker API unavailable", error=str(e))
            return ResurrectionResult(
                success=False,
                target_module=kill_report.target_module,
                target_instance_id=kill_report.target_instance_id,
                duration_seconds=elapsed,
                error=f"docker_unavailable: {e}",
            )
        if container is None:
            elapsed = time.monotonic() - t0
            logger.error(
                "Container not found for resurrection",
                target_module=kill_report.target_module,
                instance_id=kill_report.target_instance_id,
            )
            return ResurrectionResult(
                success=False,
                target_module=kill_report.target_module,
                target_instance_id=kill_report.target_instance_id,
                duration_seconds=elapsed,
                error="container_not_found",
            )

        container_id = container.id[:12]
        status_before = container.status

        logger.info(
            "Restarting container",
            container_id=container_id,
            container_name=container.name,
            status_before=status_before,
            target_module=kill_report.target_module,
        )

        try:
            container.restart(timeout=self.restart_timeout)
        except Exception as e:
            elapsed = time.monotonic() - t0
            logger.error(
                "Docker restart failed",
                container_id=container_id,
                error=str(e),
            )
            return ResurrectionResult(
                success=False,
                target_module=kill_report.target_module,
                target_instance_id=kill_report.target_instance_id,
                container_id=container_id,
                duration_seconds=elapsed,
                error=f"restart_failed: {e}",
            )

        # Wait for container to be running
        container.reload()
        if container.status != "running":
            elapsed = time.monotonic() - t0
            logger.error(
                "Container not running after restart",
                container_id=container_id,
                status=container.status,
            )
            return ResurrectionResult(
                success=False,
                target_module=kill_report.target_module,
                target_instance_id=kill_report.target_instance_id,
                container_id=container_id,
                duration_seconds=elapsed,
                error=f"not_running: status={container.status}",
            )

        # Check health if container has a healthcheck
        health_status = self._wait_for_health(container)

        elapsed = time.monotonic() - t0
        success = health_status in ("healthy", None)  # None = no healthcheck defined

        if success:
            logger.info(
                "Container resurrected successfully",
                container_id=container_id,
                container_name=container.name,
                duration_seconds=round(elapsed, 2),
                health_status=health_status or "no_healthcheck",
            )
        else:
            logger.warning(
                "Container restarted but unhealthy",
                container_id=container_id,
                health_status=health_status,
                duration_seconds=round(elapsed, 2),
            )

        return ResurrectionResult(
            success=success,
            target_module=kill_report.target_module,
            target_instance_id=kill_report.target_instance_id,
            container_id=container_id,
            started_at=datetime.now(timezone.utc),
            duration_seconds=elapsed,
            health_status=health_status or "no_healthcheck",
            metadata={
                "container_name": container.name,
                "status_before": status_before,
            },
        )

    def _wait_for_health(self, container) -> Optional[str]:
        """Wait for container health check to pass, if configured."""
        container.reload()
        health = container.attrs.get("State", {}).get("Health")
        if health is None:
            return None  # No healthcheck defined

        deadline = time.monotonic() + self.health_check_timeout
        while time.monotonic() < deadline:
            container.reload()
            status = container.attrs["State"]["Health"]["Status"]
            if status == "healthy":
                return "healthy"
            if status == "unhealthy":
                return "unhealthy"
            time.sleep(1)

        return container.attrs["State"]["Health"]["Status"]

    def health_check(self, container_name: str) -> Optional[str]:
        """Check health status of a named container."""
        try:
            client = self._get_client()
            container = client.containers.get(container_name)
            health = container.attrs.get("State", {}).get("Health")
            if health:
                return health["Status"]
            return container.status
        except Exception:
            return None


class DryRunResurrector(Resurrector):
    """
    Logs what it would do without touching Docker.

    Used in observer mode and for testing.
    """

    def __init__(self):
        self.history: list[ResurrectionResult] = []

    def resurrect(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
    ) -> ResurrectionResult:
        """Log the resurrection without executing it."""
        logger.info(
            "DRY RUN: Would restart container",
            target_module=kill_report.target_module,
            instance_id=kill_report.target_instance_id,
            decision_id=decision.decision_id,
            risk_score=round(decision.risk_score, 3),
        )

        result = ResurrectionResult(
            success=True,
            target_module=kill_report.target_module,
            target_instance_id=kill_report.target_instance_id,
            container_id="dry-run",
            started_at=datetime.now(timezone.utc),
            duration_seconds=0.0,
            health_status="dry_run",
            metadata={"dry_run": True},
        )
        self.history.append(result)
        return result

    def health_check(self, container_name: str) -> Optional[str]:
        """Always returns healthy in dry-run mode."""
        return "dry_run"


def create_resurrector(config: Dict[str, Any], mode: str) -> Resurrector:
    """
    Factory function to create the appropriate resurrector.

    In observer mode, always returns DryRunResurrector.
    In live mode, returns DockerResurrector.
    """
    if mode == "observer":
        logger.info("Using DryRunResurrector (observer mode)")
        return DryRunResurrector()

    resurrector_config = config.get("resurrector", {})

    logger.info(
        "Using DockerResurrector (live mode)",
        health_check_timeout=resurrector_config.get("health_check_timeout", 30),
    )

    return DockerResurrector(
        health_check_timeout=resurrector_config.get("health_check_timeout", 30),
        restart_timeout=resurrector_config.get("restart_timeout", 30),
        label_prefix=resurrector_config.get("label_prefix", "medic.module"),
    )
