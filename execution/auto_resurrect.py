"""
Medic Agent Auto-Resurrection Manager

Manages automated resurrection workflows for low-risk cases.
Implements rate limiting, cooldown periods, and safety constraints.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import uuid

from core.models import (
    KillReport,
    ResurrectionRequest,
    ResurrectionStatus,
    ResurrectionDecision,
    DecisionOutcome,
)
from core.risk import RiskAssessment
from core.logger import get_logger, LogContext

logger = get_logger("execution.auto_resurrect")


class AutoResurrectionResult(Enum):
    """Result of an auto-resurrection attempt."""
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    COOLDOWN = "cooldown"
    NOT_ELIGIBLE = "not_eligible"
    BLACKLISTED = "blacklisted"


@dataclass
class AutoResurrectionConfig:
    """Configuration for auto-resurrection behavior."""
    enabled: bool = True
    max_per_hour: int = 10
    max_per_module_per_hour: int = 3
    cooldown_seconds: int = 300  # 5 minutes
    min_confidence: float = 0.85
    max_risk_score: float = 0.3
    require_health_check: bool = True
    monitoring_duration_minutes: int = 30


@dataclass
class ResurrectionAttempt:
    """Record of an auto-resurrection attempt."""
    attempt_id: str
    kill_id: str
    target_module: str
    timestamp: datetime
    result: AutoResurrectionResult
    request_id: Optional[str] = None
    error_message: Optional[str] = None
    duration_seconds: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attempt_id": self.attempt_id,
            "kill_id": self.kill_id,
            "target_module": self.target_module,
            "timestamp": self.timestamp.isoformat(),
            "result": self.result.value,
            "request_id": self.request_id,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
        }


class AutoResurrectionManager:
    """
    Manages automated resurrection for low-risk modules.

    Implements safety constraints including:
    - Rate limiting (global and per-module)
    - Cooldown periods between resurrections
    - Blacklist for modules that shouldn't be auto-resurrected
    - Integration with monitoring for post-resurrection verification
    """

    def __init__(
        self,
        config: AutoResurrectionConfig,
        resurrector: Any,
        monitor: Optional[Any] = None,
        risk_assessor: Optional[Any] = None,
    ):
        self.config = config
        self.resurrector = resurrector
        self.monitor = monitor
        self.risk_assessor = risk_assessor

        # Rate limiting state
        self._attempts_this_hour: List[ResurrectionAttempt] = []
        self._module_attempts: Dict[str, List[datetime]] = {}

        # Cooldown tracking
        self._last_resurrection: Dict[str, datetime] = {}

        # Blacklist
        self._blacklist: Set[str] = set()

        # History
        self._history: List[ResurrectionAttempt] = []

        # Callbacks
        self._on_success: List[Callable] = []
        self._on_failure: List[Callable] = []

        logger.info(
            "AutoResurrectionManager initialized",
            max_per_hour=config.max_per_hour,
            max_risk=config.max_risk_score,
        )

    async def attempt_resurrection(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
        risk_assessment: Optional[RiskAssessment] = None,
    ) -> ResurrectionAttempt:
        """
        Attempt auto-resurrection of a killed module.

        Args:
            kill_report: The kill report
            decision: The resurrection decision
            risk_assessment: Optional detailed risk assessment

        Returns:
            ResurrectionAttempt with result
        """
        attempt_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)

        with LogContext(
            attempt_id=attempt_id,
            kill_id=kill_report.kill_id,
            target_module=kill_report.target_module,
        ):
            logger.info("Starting auto-resurrection attempt")

            # Check eligibility
            eligible, reason = self._check_eligibility(
                kill_report, decision, risk_assessment
            )

            if not eligible:
                attempt = ResurrectionAttempt(
                    attempt_id=attempt_id,
                    kill_id=kill_report.kill_id,
                    target_module=kill_report.target_module,
                    timestamp=started_at,
                    result=self._reason_to_result(reason),
                    error_message=reason,
                )
                self._record_attempt(attempt)
                return attempt

            try:
                # Create resurrection request
                request = ResurrectionRequest.from_decision(decision, kill_report)
                request.approved_by = "auto"
                request.approved_at = datetime.now(timezone.utc)

                # Execute resurrection
                result = await self.resurrector.resurrect(request)

                duration = (datetime.now(timezone.utc) - started_at).total_seconds()

                if result.success:
                    # Update cooldown
                    self._last_resurrection[kill_report.target_module] = datetime.now(timezone.utc)

                    # Start monitoring if available
                    if self.monitor and self.config.require_health_check:
                        await self.monitor.start_monitoring(
                            request,
                            duration_minutes=self.config.monitoring_duration_minutes,
                        )

                    attempt = ResurrectionAttempt(
                        attempt_id=attempt_id,
                        kill_id=kill_report.kill_id,
                        target_module=kill_report.target_module,
                        timestamp=started_at,
                        result=AutoResurrectionResult.SUCCESS,
                        request_id=request.request_id,
                        duration_seconds=duration,
                    )

                    logger.info(
                        "Auto-resurrection successful",
                        duration=duration,
                        request_id=request.request_id,
                    )

                    # Trigger success callbacks
                    await self._trigger_callbacks(self._on_success, attempt)

                else:
                    attempt = ResurrectionAttempt(
                        attempt_id=attempt_id,
                        kill_id=kill_report.kill_id,
                        target_module=kill_report.target_module,
                        timestamp=started_at,
                        result=AutoResurrectionResult.FAILED,
                        request_id=request.request_id,
                        error_message=result.error_message,
                        duration_seconds=duration,
                    )

                    logger.warning(
                        "Auto-resurrection failed",
                        error=result.error_message,
                    )

                    # Trigger failure callbacks
                    await self._trigger_callbacks(self._on_failure, attempt)

            except Exception as e:
                duration = (datetime.now(timezone.utc) - started_at).total_seconds()
                attempt = ResurrectionAttempt(
                    attempt_id=attempt_id,
                    kill_id=kill_report.kill_id,
                    target_module=kill_report.target_module,
                    timestamp=started_at,
                    result=AutoResurrectionResult.FAILED,
                    error_message=str(e),
                    duration_seconds=duration,
                )

                logger.error(f"Auto-resurrection error: {e}", exc_info=True)

            self._record_attempt(attempt)
            return attempt

    def _check_eligibility(
        self,
        kill_report: KillReport,
        decision: ResurrectionDecision,
        risk_assessment: Optional[RiskAssessment],
    ) -> tuple[bool, str]:
        """Check if module is eligible for auto-resurrection."""
        # Check if enabled
        if not self.config.enabled:
            return False, "Auto-resurrection is disabled"

        # Check blacklist
        if kill_report.target_module in self._blacklist:
            return False, f"Module '{kill_report.target_module}' is blacklisted"

        # Check decision outcome
        if decision.outcome != DecisionOutcome.APPROVE_AUTO:
            return False, f"Decision outcome is {decision.outcome.value}, not approve_auto"

        # Check risk score
        if decision.risk_score > self.config.max_risk_score:
            return False, f"Risk score {decision.risk_score:.2f} exceeds max {self.config.max_risk_score}"

        # Check confidence
        if decision.confidence < self.config.min_confidence:
            return False, f"Confidence {decision.confidence:.2f} below min {self.config.min_confidence}"

        # Check auto_approve_eligible flag
        if not decision.auto_approve_eligible:
            return False, "Decision not marked as auto-approve eligible"

        # Check rate limiting
        rate_ok, rate_reason = self._check_rate_limit(kill_report.target_module)
        if not rate_ok:
            return False, rate_reason

        # Check cooldown
        cooldown_ok, cooldown_reason = self._check_cooldown(kill_report.target_module)
        if not cooldown_ok:
            return False, cooldown_reason

        # Additional checks from risk assessment
        if risk_assessment and risk_assessment.requires_escalation:
            return False, "Risk assessment requires escalation"

        return True, ""

    def _check_rate_limit(self, module: str) -> tuple[bool, str]:
        """Check global and per-module rate limits."""
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)

        # Clean old attempts
        self._attempts_this_hour = [
            a for a in self._attempts_this_hour
            if a.timestamp > hour_ago
        ]

        # Check global rate
        if len(self._attempts_this_hour) >= self.config.max_per_hour:
            return False, f"Global rate limit exceeded ({self.config.max_per_hour}/hour)"

        # Clean old module attempts
        if module in self._module_attempts:
            self._module_attempts[module] = [
                t for t in self._module_attempts[module]
                if t > hour_ago
            ]

        # Check per-module rate
        module_count = len(self._module_attempts.get(module, []))
        if module_count >= self.config.max_per_module_per_hour:
            return False, f"Module rate limit exceeded ({self.config.max_per_module_per_hour}/hour)"

        return True, ""

    def _check_cooldown(self, module: str) -> tuple[bool, str]:
        """Check if module is in cooldown period."""
        if module not in self._last_resurrection:
            return True, ""

        last = self._last_resurrection[module]
        elapsed = (datetime.now(timezone.utc) - last).total_seconds()

        if elapsed < self.config.cooldown_seconds:
            remaining = self.config.cooldown_seconds - elapsed
            return False, f"Module in cooldown for {remaining:.0f} more seconds"

        return True, ""

    def _reason_to_result(self, reason: str) -> AutoResurrectionResult:
        """Convert reason string to result enum."""
        if "rate limit" in reason.lower():
            return AutoResurrectionResult.RATE_LIMITED
        if "cooldown" in reason.lower():
            return AutoResurrectionResult.COOLDOWN
        if "blacklist" in reason.lower():
            return AutoResurrectionResult.BLACKLISTED
        return AutoResurrectionResult.NOT_ELIGIBLE

    def _record_attempt(self, attempt: ResurrectionAttempt) -> None:
        """Record an attempt in history and rate limiting."""
        self._history.append(attempt)
        self._attempts_this_hour.append(attempt)

        # Track module attempts for rate limiting
        module = attempt.target_module
        if module not in self._module_attempts:
            self._module_attempts[module] = []
        self._module_attempts[module].append(attempt.timestamp)

        # Trim history
        max_history = 1000
        if len(self._history) > max_history:
            self._history = self._history[-max_history:]

    async def _trigger_callbacks(
        self,
        callbacks: List[Callable],
        attempt: ResurrectionAttempt,
    ) -> None:
        """Trigger registered callbacks."""
        for callback in callbacks:
            try:
                result = callback(attempt)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def blacklist_module(self, module: str, reason: str = "") -> None:
        """Add a module to the blacklist."""
        self._blacklist.add(module)
        logger.info(f"Module blacklisted: {module}", reason=reason)

    def unblacklist_module(self, module: str) -> None:
        """Remove a module from the blacklist."""
        self._blacklist.discard(module)
        logger.info(f"Module removed from blacklist: {module}")

    def get_blacklist(self) -> Set[str]:
        """Get current blacklist."""
        return self._blacklist.copy()

    def on_success(self, callback: Callable) -> None:
        """Register callback for successful auto-resurrections."""
        self._on_success.append(callback)

    def on_failure(self, callback: Callable) -> None:
        """Register callback for failed auto-resurrections."""
        self._on_failure.append(callback)

    def get_statistics(self) -> Dict[str, Any]:
        """Get auto-resurrection statistics."""
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)

        recent = [a for a in self._history if a.timestamp > hour_ago]
        today = [a for a in self._history if a.timestamp > day_ago]

        success_count = sum(1 for a in today if a.result == AutoResurrectionResult.SUCCESS)
        fail_count = sum(1 for a in today if a.result == AutoResurrectionResult.FAILED)

        return {
            "enabled": self.config.enabled,
            "attempts_last_hour": len(recent),
            "attempts_last_24h": len(today),
            "success_rate_24h": success_count / len(today) if today else 0.0,
            "successes_24h": success_count,
            "failures_24h": fail_count,
            "rate_limit": {
                "global_limit": self.config.max_per_hour,
                "global_used": len(recent),
            },
            "blacklisted_modules": list(self._blacklist),
            "cooldown_seconds": self.config.cooldown_seconds,
        }

    def get_history(
        self,
        limit: int = 50,
        module: Optional[str] = None,
    ) -> List[ResurrectionAttempt]:
        """Get auto-resurrection history."""
        history = self._history
        if module:
            history = [a for a in history if a.target_module == module]
        return list(reversed(history[-limit:]))


def create_auto_resurrector(
    config: Dict[str, Any],
    resurrector: Any,
    monitor: Optional[Any] = None,
    risk_assessor: Optional[Any] = None,
) -> AutoResurrectionManager:
    """Factory function to create auto-resurrection manager."""
    auto_config = config.get("auto_resurrection", {})

    return AutoResurrectionManager(
        config=AutoResurrectionConfig(
            enabled=auto_config.get("enabled", True),
            max_per_hour=auto_config.get("max_per_hour", 10),
            max_per_module_per_hour=auto_config.get("max_per_module_per_hour", 3),
            cooldown_seconds=auto_config.get("cooldown_seconds", 300),
            min_confidence=auto_config.get("min_confidence", 0.85),
            max_risk_score=auto_config.get("max_risk_score", 0.3),
            require_health_check=auto_config.get("require_health_check", True),
            monitoring_duration_minutes=auto_config.get("monitoring_duration_minutes", 30),
        ),
        resurrector=resurrector,
        monitor=monitor,
        risk_assessor=risk_assessor,
    )
