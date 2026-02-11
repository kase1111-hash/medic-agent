"""
Boundary-SIEM Integration Client

Queries Boundary-SIEM for threat intelligence to enrich kill report
risk assessment. Provides real SIEM data to replace the placeholder
SIEMResult defaults.

API reference: https://github.com/kase1111-hash/Boundary-SIEM
"""

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import requests

from core.logger import get_logger
from core.models import KillReport, SIEMResult

logger = get_logger("core.siem")


class SIEMClient(ABC):
    """Abstract interface for SIEM enrichment."""

    @abstractmethod
    def enrich(self, kill_report: KillReport) -> SIEMResult:
        """Query SIEM for threat context about a killed module."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check if the SIEM is reachable."""
        pass


class BoundarySIEMClient(SIEMClient):
    """
    Client for the Boundary-SIEM REST API.

    Authenticates via session token, then queries:
    1. POST /v1/search      — recent events for the target module
    2. GET  /v1/alerts       — active alerts for the target module
    3. POST /v1/aggregations — severity distribution

    Computes a normalized SIEMResult from the combined data.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        tenant_id: str = "default",
        timeout: int = 10,
        lookback_hours: int = 24,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.tenant_id = tenant_id
        self.timeout = timeout
        self.lookback_hours = lookback_hours
        self._token: Optional[str] = None
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"

    def _authenticate(self) -> None:
        """Login and cache the session token."""
        resp = self._session.post(
            f"{self.base_url}/api/auth/login",
            json={
                "username": self.username,
                "password": self.password,
                "tenant_id": self.tenant_id,
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        self._token = resp.json()["token"]
        self._session.headers["Authorization"] = f"Bearer {self._token}"
        logger.info("Authenticated with Boundary-SIEM")

    def _ensure_auth(self) -> None:
        """Authenticate if we don't have a token yet."""
        if self._token is None:
            self._authenticate()

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Make an authenticated request, re-auth on 401."""
        self._ensure_auth()
        resp = self._session.request(
            method,
            f"{self.base_url}{path}",
            timeout=self.timeout,
            **kwargs,
        )
        if resp.status_code == 401:
            logger.info("SIEM token expired, re-authenticating")
            self._authenticate()
            resp = self._session.request(
                method,
                f"{self.base_url}{path}",
                timeout=self.timeout,
                **kwargs,
            )
        return resp

    def _search_events(
        self, module: str, min_severity: int = 1, limit: int = 100,
    ) -> Dict[str, Any]:
        """Search for recent events from a specific module."""
        resp = self._request(
            "POST",
            "/v1/search",
            json={
                "query": f'source.product = "{module}"'
                         f' AND severity >= {min_severity}',
                "start_time": f"now-{self.lookback_hours}h",
                "end_time": "now",
                "limit": limit,
                "order_by": "severity",
                "order_desc": True,
            },
        )
        if resp.status_code != 200:
            logger.warning(
                "SIEM search failed",
                status=resp.status_code,
                target_module=module,
            )
            return {"total_count": 0, "results": []}
        return resp.json()

    def _get_active_alerts(self, module: str) -> List[Dict[str, Any]]:
        """Get active (unresolved) alerts related to a module."""
        resp = self._request(
            "GET",
            "/v1/alerts",
            params={
                "status": "new",
                "limit": 50,
            },
        )
        if resp.status_code != 200:
            logger.warning("SIEM alerts query failed", status=resp.status_code)
            return []

        data = resp.json()
        alerts = data if isinstance(data, list) else data.get("alerts", [])

        # Filter to alerts that mention this module
        return [
            a for a in alerts
            if module in a.get("title", "")
            or module in a.get("description", "")
            or module in a.get("group_key", "")
        ]

    def _count_false_positives(self, module: str) -> int:
        """Count resolved/suppressed alerts for this module (likely FPs)."""
        resp = self._request(
            "GET",
            "/v1/alerts",
            params={
                "status": "resolved",
                "limit": 100,
            },
        )
        if resp.status_code != 200:
            return 0

        data = resp.json()
        alerts = data if isinstance(data, list) else data.get("alerts", [])

        return sum(
            1 for a in alerts
            if module in a.get("title", "")
            or module in a.get("description", "")
            or module in a.get("group_key", "")
        )

    def enrich(self, kill_report: KillReport) -> SIEMResult:
        """
        Query Boundary-SIEM and compute a risk assessment.

        Risk score formula (0.0 = safe, 1.0 = dangerous):
        - Base: proportion of high-severity events (severity >= 7)
        - Alert boost: +0.3 for each active critical/high alert (capped at 0.4)
        - Event volume boost: +0.1 if > 20 events in the lookback window
        - Clamped to [0.0, 1.0]
        """
        module = kill_report.target_module
        t0 = time.monotonic()

        try:
            search_result = self._search_events(module, min_severity=1)
            active_alerts = self._get_active_alerts(module)
            fp_count = self._count_false_positives(module)
        except Exception as e:
            elapsed = time.monotonic() - t0
            logger.error(
                "SIEM enrichment failed, using defaults",
                target_module=module,
                error=str(e),
                duration_ms=round(elapsed * 1000),
            )
            return SIEMResult()  # Fall back to defaults

        elapsed = time.monotonic() - t0

        total_events = search_result.get("total_count", 0)
        events = search_result.get("results", [])

        # Count high-severity events (severity >= 7 on SIEM's 1-10 scale)
        high_severity_count = sum(
            1 for e in events if e.get("severity", 0) >= 7
        )

        # Compute risk score
        risk_score = 0.0

        if total_events > 0:
            risk_score = high_severity_count / total_events * 0.5

        # Alert boost
        critical_alerts = [
            a for a in active_alerts
            if a.get("severity") in ("critical", "high")
        ]
        alert_boost = min(0.4, len(critical_alerts) * 0.3)
        risk_score += alert_boost

        # Volume boost
        if total_events > 20:
            risk_score += 0.1

        risk_score = min(1.0, max(0.0, risk_score))

        # Recommendation
        if critical_alerts:
            recommendation = "deny_resurrection"
        elif risk_score > 0.5:
            recommendation = "manual_review"
        elif risk_score < 0.2 and fp_count > 0:
            recommendation = "safe_to_resurrect"
        elif total_events == 0:
            recommendation = "no_data"
        else:
            recommendation = "proceed_with_caution"

        logger.info(
            "SIEM enrichment complete",
            target_module=module,
            risk_score=round(risk_score, 3),
            total_events=total_events,
            high_severity=high_severity_count,
            active_alerts=len(active_alerts),
            false_positives=fp_count,
            recommendation=recommendation,
            duration_ms=round(elapsed * 1000),
        )

        return SIEMResult(
            risk_score=risk_score,
            false_positive_history=fp_count,
            recommendation=recommendation,
        )

    def health_check(self) -> bool:
        """Check if the SIEM is reachable."""
        try:
            resp = self._session.get(
                f"{self.base_url}/health",
                timeout=self.timeout,
            )
            return resp.status_code == 200
        except Exception:
            return False


class NoopSIEMClient(SIEMClient):
    """Returns defaults when no SIEM is configured."""

    def enrich(self, kill_report: KillReport) -> SIEMResult:
        return SIEMResult()

    def health_check(self) -> bool:
        return True


def create_siem_client(config: Dict[str, Any]) -> SIEMClient:
    """
    Factory function to create the SIEM client.

    If siem config is present and enabled, creates a BoundarySIEMClient.
    Otherwise returns NoopSIEMClient (Phase 1/2 behavior preserved).
    """
    siem_config = config.get("siem", {})

    if not siem_config.get("enabled", False):
        logger.info("SIEM integration disabled, using NoopSIEMClient")
        return NoopSIEMClient()

    base_url = siem_config.get("base_url")
    if not base_url:
        logger.warning("SIEM enabled but no base_url configured, using NoopSIEMClient")
        return NoopSIEMClient()

    logger.info(
        "Using BoundarySIEMClient",
        base_url=base_url,
        lookback_hours=siem_config.get("lookback_hours", 24),
    )

    return BoundarySIEMClient(
        base_url=base_url,
        username=siem_config.get("username", ""),
        password=siem_config.get("password", ""),
        tenant_id=siem_config.get("tenant_id", "default"),
        timeout=siem_config.get("timeout", 10),
        lookback_hours=siem_config.get("lookback_hours", 24),
    )
