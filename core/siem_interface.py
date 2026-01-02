"""
Medic Agent SIEM Interface

Provides adapters for querying SIEM systems to enrich kill reports
with threat intelligence and historical context.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import uuid

from core.models import (
    KillReport,
    SIEMContextResponse,
    ThreatIndicator,
    OutcomeRecord,
)
from core.logger import get_logger, LogContext

logger = get_logger("core.siem_interface")


class SIEMAdapter(ABC):
    """
    Abstract interface for SIEM query operations.

    Implementations should handle authentication, query execution,
    and response parsing for different SIEM backends.
    """

    @abstractmethod
    async def query_context(self, kill_report: KillReport) -> SIEMContextResponse:
        """Query SIEM for context about a kill event."""
        pass

    @abstractmethod
    async def get_historical_data(
        self, module: str, days: int = 30
    ) -> List[Dict[str, Any]]:
        """Retrieve historical behavior data for a module."""
        pass

    @abstractmethod
    async def report_outcome(self, outcome: OutcomeRecord) -> bool:
        """Report resurrection outcome back to SIEM."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify SIEM connectivity."""
        pass


class RESTSIEMAdapter(SIEMAdapter):
    """
    REST API-based SIEM adapter.

    Communicates with SIEM via HTTP/HTTPS REST endpoints.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:8080/siem",
        api_key: Optional[str] = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._session: Optional[Any] = None

    async def _get_session(self) -> Any:
        """Get or create HTTP session."""
        if self._session is None:
            try:
                import aiohttp
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    headers=self._get_headers(),
                )
            except ImportError:
                logger.warning("aiohttp not installed, SIEM queries will use mock data")
                return None
        return self._session

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def query_context(self, kill_report: KillReport) -> SIEMContextResponse:
        """
        Query SIEM for enriched context about a kill event.

        Args:
            kill_report: The kill report to enrich with SIEM data

        Returns:
            SIEMContextResponse with threat indicators and context
        """
        query_id = str(uuid.uuid4())

        with LogContext(kill_id=kill_report.kill_id, query_id=query_id):
            logger.info(
                "Querying SIEM for kill context",
                target_module=kill_report.target_module,
            )

            session = await self._get_session()

            if session is None:
                # Mock mode - return synthetic response
                return self._generate_mock_response(kill_report, query_id)

            request_body = {
                "query_type": "kill_context",
                "kill_id": kill_report.kill_id,
                "target_module": kill_report.target_module,
                "target_instance_id": kill_report.target_instance_id,
                "timestamp": kill_report.timestamp.isoformat(),
                "include_historical": True,
                "historical_days": 30,
            }

            for attempt in range(self.max_retries):
                try:
                    async with session.post(
                        f"{self.endpoint}/query",
                        json=request_body,
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            logger.info(
                                "SIEM query successful",
                                risk_score=data.get("risk_score"),
                            )
                            return SIEMContextResponse.from_dict(data)
                        else:
                            error_text = await response.text()
                            logger.warning(
                                f"SIEM query failed with status {response.status}",
                                error=error_text,
                            )

                except asyncio.TimeoutError:
                    logger.warning(f"SIEM query timeout (attempt {attempt + 1})")
                except Exception as e:
                    logger.error(f"SIEM query error: {e}")

                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff

            # All retries failed, return default response
            logger.error("All SIEM query attempts failed, using default context")
            return self._generate_default_response(kill_report, query_id)

    async def get_historical_data(
        self, module: str, days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Retrieve historical behavior data for a module.

        Args:
            module: Module name to query
            days: Number of days of history to retrieve

        Returns:
            List of historical data points
        """
        logger.info(f"Fetching historical data for {module}", days=days)

        session = await self._get_session()

        if session is None:
            # Mock mode
            return self._generate_mock_history(module, days)

        try:
            async with session.get(
                f"{self.endpoint}/history/{module}",
                params={"days": days},
            ) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            logger.error(f"Failed to fetch historical data: {e}")

        return []

    async def report_outcome(self, outcome: OutcomeRecord) -> bool:
        """
        Report resurrection outcome back to SIEM.

        This feeds the outcome data back to SIEM for correlation
        and future threat intelligence.
        """
        logger.info(
            "Reporting outcome to SIEM",
            outcome_id=outcome.outcome_id,
            result=outcome.result.value,
        )

        session = await self._get_session()

        if session is None:
            return True  # Mock mode

        try:
            async with session.post(
                f"{self.endpoint}/outcomes",
                json=outcome.to_dict(),
            ) as response:
                if response.status in (200, 201):
                    logger.info("Outcome reported successfully")
                    return True
                else:
                    logger.warning(f"Failed to report outcome: {response.status}")
        except Exception as e:
            logger.error(f"Error reporting outcome: {e}")

        return False

    async def health_check(self) -> bool:
        """Verify SIEM connectivity."""
        session = await self._get_session()

        if session is None:
            return True  # Mock mode

        try:
            async with session.get(f"{self.endpoint}/health") as response:
                return response.status == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    def _generate_mock_response(
        self, kill_report: KillReport, query_id: str
    ) -> SIEMContextResponse:
        """Generate a mock SIEM response for testing."""
        import random

        # Generate mock threat indicators based on kill reason
        indicators = []
        if kill_report.kill_reason.value in ("threat_detected", "anomaly_behavior"):
            indicators.append(
                ThreatIndicator(
                    indicator_type="behavior",
                    value=f"anomaly_{kill_report.target_module}",
                    threat_score=random.uniform(0.3, 0.8),
                    source="behavior_analytics",
                    last_seen=datetime.utcnow(),
                    tags=["behavioral", "automated"],
                )
            )

        # Calculate mock risk score based on kill report severity
        severity_scores = {
            "critical": 0.9,
            "high": 0.7,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1,
        }
        base_risk = severity_scores.get(kill_report.severity.value, 0.5)
        risk_score = min(1.0, base_risk * random.uniform(0.8, 1.2))

        # Mock false positive history
        fp_history = random.randint(0, 5)

        return SIEMContextResponse(
            query_id=query_id,
            kill_id=kill_report.kill_id,
            timestamp=datetime.utcnow(),
            threat_indicators=indicators,
            historical_behavior={
                "avg_cpu_usage": random.uniform(10, 80),
                "avg_memory_mb": random.randint(100, 2000),
                "restart_count_30d": random.randint(0, 10),
                "alert_count_30d": random.randint(0, 20),
            },
            false_positive_history=fp_history,
            network_context={
                "outbound_connections_24h": random.randint(0, 1000),
                "unique_destinations": random.randint(0, 50),
            },
            user_context=None,
            risk_score=risk_score,
            recommendation=self._get_recommendation(risk_score, fp_history),
        )

    def _generate_default_response(
        self, kill_report: KillReport, query_id: str
    ) -> SIEMContextResponse:
        """Generate default response when SIEM is unavailable."""
        return SIEMContextResponse(
            query_id=query_id,
            kill_id=kill_report.kill_id,
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=0,
            network_context={},
            user_context=None,
            risk_score=0.5,  # Default to medium risk when unknown
            recommendation="manual_review_recommended",
        )

    def _generate_mock_history(
        self, module: str, days: int
    ) -> List[Dict[str, Any]]:
        """Generate mock historical data."""
        import random

        history = []
        for i in range(days):
            date = datetime.utcnow() - timedelta(days=i)
            history.append({
                "date": date.isoformat(),
                "module": module,
                "cpu_avg": random.uniform(10, 80),
                "memory_avg": random.randint(100, 2000),
                "error_count": random.randint(0, 10),
                "request_count": random.randint(100, 10000),
            })
        return history

    def _get_recommendation(self, risk_score: float, fp_history: int) -> str:
        """Generate recommendation based on risk and history."""
        if risk_score < 0.3 and fp_history > 2:
            return "likely_false_positive"
        elif risk_score < 0.4:
            return "low_risk_auto_approve"
        elif risk_score < 0.6:
            return "medium_risk_review"
        elif risk_score < 0.8:
            return "high_risk_deny"
        else:
            return "critical_risk_deny"


class MockSIEMAdapter(SIEMAdapter):
    """
    Mock SIEM adapter for testing and development.

    Returns configurable responses without network calls.
    """

    def __init__(
        self,
        default_risk_score: float = 0.5,
        default_fp_history: int = 0,
    ):
        self.default_risk_score = default_risk_score
        self.default_fp_history = default_fp_history
        self._responses: Dict[str, SIEMContextResponse] = {}

    def set_response(self, kill_id: str, response: SIEMContextResponse) -> None:
        """Pre-configure response for a specific kill_id."""
        self._responses[kill_id] = response

    async def query_context(self, kill_report: KillReport) -> SIEMContextResponse:
        """Return configured or default mock response."""
        if kill_report.kill_id in self._responses:
            return self._responses[kill_report.kill_id]

        return SIEMContextResponse(
            query_id=str(uuid.uuid4()),
            kill_id=kill_report.kill_id,
            timestamp=datetime.utcnow(),
            threat_indicators=[],
            historical_behavior={},
            false_positive_history=self.default_fp_history,
            network_context={},
            user_context=None,
            risk_score=self.default_risk_score,
            recommendation="mock_response",
        )

    async def get_historical_data(
        self, module: str, days: int = 30
    ) -> List[Dict[str, Any]]:
        """Return empty history."""
        return []

    async def report_outcome(self, outcome: OutcomeRecord) -> bool:
        """Always succeed."""
        return True

    async def health_check(self) -> bool:
        """Always healthy."""
        return True


def create_siem_adapter(config: Dict[str, Any]) -> SIEMAdapter:
    """
    Factory function to create the appropriate SIEM adapter based on config.

    Args:
        config: Configuration dictionary with SIEM settings

    Returns:
        Configured SIEMAdapter instance
    """
    import os

    siem_config = config.get("siem", {})
    adapter_type = siem_config.get("adapter", "rest")

    if adapter_type == "mock":
        return MockSIEMAdapter(
            default_risk_score=siem_config.get("default_risk_score", 0.5),
        )

    # Get API key from environment variable or config
    auth_config = siem_config.get("auth", {})
    api_key = None

    # Priority: environment variable > config file
    key_env_name = auth_config.get("key_env", "SIEM_API_KEY")
    api_key = os.environ.get(key_env_name)

    if not api_key:
        # Fall back to config file (not recommended for production)
        api_key = auth_config.get("api_key")

    if not api_key:
        logger.warning(
            f"SIEM API key not configured. Set {key_env_name} environment variable "
            "or configure siem.auth.api_key in config file."
        )

    # Validate API key format (basic check)
    if api_key and api_key.startswith("dev-") or api_key == "replace-with-actual-api-key":
        logger.warning(
            "SIEM API key appears to be a placeholder. "
            "Set a real API key for production use."
        )

    # Default to REST adapter
    return RESTSIEMAdapter(
        endpoint=siem_config.get("endpoint", "http://localhost:8080/siem"),
        api_key=api_key,
        timeout_seconds=siem_config.get("timeout_seconds", 30),
        max_retries=siem_config.get("retry", {}).get("max_attempts", 3),
    )
