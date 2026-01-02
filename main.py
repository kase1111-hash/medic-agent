#!/usr/bin/env python3
"""
Medic Agent - Main Entry Point

Autonomous resilience layer that listens to Smith kill reports,
evaluates legitimacy, and manages resurrection workflows.

Usage:
    python main.py [--config CONFIG_PATH] [--mode MODE]

Modes:
    observer  - Log decisions but don't act (Phase 1)
    manual    - Require human approval (Phase 2)
    semi_auto - Auto-approve low-risk (Phase 3)
    full_auto - Fully autonomous (Phase 5)
"""

import argparse
import asyncio
import os
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from core.logger import configure_logging, get_logger, set_trace_context
from core.listener import create_listener, KillReportListener
from core.siem_interface import create_siem_adapter, SIEMAdapter
from core.decision import create_decision_engine, DecisionEngine
from core.log_decisions import create_decision_logger, DecisionLogger
from core.reporting import create_report_generator, ReportGenerator
from core.models import KillReport, DecisionOutcome

# Phase 2+ imports
from execution.recommendation import create_recommendation_engine, RecommendationEngine
from execution.resurrector import create_resurrector, Resurrector
from execution.monitor import create_monitor, ResurrectionMonitor
from interfaces.approval_queue import create_approval_queue, ApprovalQueue

# Phase 3 imports
from core.risk import create_risk_assessor, RiskAssessor, AdvancedRiskAssessor
from core.event_bus import create_event_bus, EventBus, EventType, Event
from execution.auto_resurrect import create_auto_resurrector, AutoResurrectionManager

# Phase 4 imports
from learning.outcome_store import (
    create_outcome_store, OutcomeStore, ResurrectionOutcome, OutcomeType
)
from learning.pattern_analyzer import create_pattern_analyzer, PatternAnalyzer
from learning.threshold_adapter import create_threshold_adapter, ThresholdAdapter
from learning.feedback import (
    create_feedback_processor, create_automated_collector,
    FeedbackProcessor, AutomatedFeedbackCollector
)

# Phase 5 imports (Full Autonomous)
from integration.edge_case_manager import (
    create_edge_case_manager, EdgeCaseManager, EdgeCase, EdgeCaseAction
)
from integration.smith_negotiator import (
    create_smith_negotiator, SmithNegotiator, NegotiationType
)
from integration.veto_protocol import (
    create_veto_protocol, VetoProtocol, VetoRequest, VetoDecision
)
from integration.self_monitor import (
    create_self_monitor, SelfMonitor, HealthStatus
)

# Phase 6 imports (Production Readiness)
from core.metrics import create_metrics, MedicMetrics
from core.errors import (
    MedicError, SmithConnectionError, SIEMQueryError,
    create_siem_circuit_breaker, create_smith_circuit_breaker,
    CircuitBreaker,
)

logger = get_logger("main")


class MedicAgent:
    """
    Main Medic Agent orchestrator.

    Coordinates the listener, SIEM adapter, decision engine,
    and logging/reporting components.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mode = config.get("mode", {}).get("current", "observer")

        # Core components (Phase 0-1)
        self.listener: Optional[KillReportListener] = None
        self.siem_adapter: Optional[SIEMAdapter] = None
        self.decision_engine: Optional[DecisionEngine] = None
        self.decision_logger: Optional[DecisionLogger] = None
        self.report_generator: Optional[ReportGenerator] = None

        # Execution components (Phase 2+)
        self.recommendation_engine: Optional[RecommendationEngine] = None
        self.resurrector: Optional[Resurrector] = None
        self.monitor: Optional[ResurrectionMonitor] = None
        self.approval_queue: Optional[ApprovalQueue] = None

        # Phase 3 components
        self.risk_assessor: Optional[AdvancedRiskAssessor] = None
        self.event_bus: Optional[EventBus] = None
        self.auto_resurrector: Optional[AutoResurrectionManager] = None

        # Phase 4 components (Learning)
        self.outcome_store: Optional[OutcomeStore] = None
        self.pattern_analyzer: Optional[PatternAnalyzer] = None
        self.threshold_adapter: Optional[ThresholdAdapter] = None
        self.feedback_processor: Optional[FeedbackProcessor] = None
        self.automated_collector: Optional[AutomatedFeedbackCollector] = None

        # Phase 5 components (Full Autonomous)
        self.edge_case_manager: Optional[EdgeCaseManager] = None
        self.smith_negotiator: Optional[SmithNegotiator] = None
        self.veto_protocol: Optional[VetoProtocol] = None
        self.self_monitor: Optional[SelfMonitor] = None

        # Phase 6 components (Production Readiness)
        self.metrics: Optional[MedicMetrics] = None
        self.siem_circuit_breaker: Optional[CircuitBreaker] = None
        self.smith_circuit_breaker: Optional[CircuitBreaker] = None

        # Runtime state
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._processed_count = 0
        self._start_time: Optional[datetime] = None

    async def initialize(self) -> None:
        """Initialize all components."""
        logger.info(f"Initializing Medic Agent in {self.mode} mode")

        # Configure logging
        log_config = self.config.get("logging", {})
        configure_logging(
            level=log_config.get("level", "INFO"),
            format_type=log_config.get("format", "text"),
            log_file=self._get_log_file_path(),
        )

        # Create core components (Phase 0-1)
        self.listener = create_listener(self.config)
        self.siem_adapter = create_siem_adapter(self.config)
        self.decision_engine = create_decision_engine(self.config)
        self.decision_logger = create_decision_logger(self.config)
        self.report_generator = create_report_generator(
            self.decision_logger, self.config
        )

        # Create execution components (Phase 2+)
        if self.mode in ("manual", "semi_auto", "full_auto"):
            self.recommendation_engine = create_recommendation_engine(
                self.config, self.decision_logger
            )
            self.resurrector = create_resurrector(self.config)
            self.monitor = create_monitor(self.config)
            self.approval_queue = create_approval_queue(self.config)

            # Set up rollback callback
            self.monitor.set_rollback_callback(self._handle_rollback)

            logger.info("Phase 2 components initialized")

        # Create Phase 3 components (semi-auto mode)
        if self.mode in ("semi_auto", "full_auto"):
            self.event_bus = create_event_bus()
            self.risk_assessor = create_risk_assessor(self.config)
            self.auto_resurrector = create_auto_resurrector(
                self.config,
                resurrector=self.resurrector,
                monitor=self.monitor,
                risk_assessor=self.risk_assessor,
            )

            # Set up event handlers for auto-resurrection
            self._setup_event_handlers()

            logger.info("Phase 3 components initialized")

        # Create Phase 4 components (Learning)
        learning_config = self.config.get("learning", {})
        if learning_config.get("enabled", False):
            self.outcome_store = create_outcome_store(self.config)
            self.pattern_analyzer = create_pattern_analyzer(
                self.outcome_store,
                learning_config.get("analysis", {}),
            )
            self.threshold_adapter = create_threshold_adapter(
                self.outcome_store,
                self.config,
            )
            self.feedback_processor = create_feedback_processor(
                self.outcome_store,
                on_feedback_processed=self._on_feedback_processed,
            )

            # Set up automated feedback collection if monitoring is available
            if self.monitor and learning_config.get("feedback", {}).get("auto_collect", True):
                self.automated_collector = create_automated_collector(
                    self.feedback_processor,
                    self.outcome_store,
                )

            logger.info("Phase 4 learning components initialized")

        # Create Phase 5 components (Full Autonomous)
        if self.mode == "full_auto":
            # Edge case manager
            edge_case_config = self.config.get("edge_cases", {})
            self.edge_case_manager = create_edge_case_manager(
                config=edge_case_config,
                on_edge_case_detected=self._on_edge_case_detected,
                on_action_required=self._on_edge_case_action,
            )

            # Smith negotiator
            smith_config = self.config.get("smith", {})
            self.smith_negotiator = create_smith_negotiator(
                config=smith_config.get("negotiation", {}),
                message_sender=self._send_smith_message,
            )

            # Veto protocol (requires decision engine and outcome store)
            veto_config = smith_config.get("veto_protocol", {})
            if veto_config.get("enabled", False):
                self.veto_protocol = create_veto_protocol(
                    config=veto_config,
                    decision_engine=self.decision_engine,
                    outcome_store=self.outcome_store,
                    on_veto_decision=self._on_veto_decision,
                )

            # Self-monitor
            monitor_config = self.config.get("self_monitoring", {})
            if monitor_config.get("enabled", True):
                self.self_monitor = create_self_monitor(
                    config=monitor_config,
                    on_health_change=self._on_health_change,
                    on_critical=self._on_critical_health,
                )
                # Start self-monitoring
                await self.self_monitor.start()

            logger.info("Phase 5 full autonomous components initialized")

        # Create Phase 6 components (Production Readiness)
        metrics_config = self.config.get("metrics", {})
        if metrics_config.get("enabled", True):
            self.metrics = create_metrics(metrics_config)
            self.metrics.set_agent_info(
                version="6.0.0",
                mode=self.mode,
                phase="6",
            )

            # Start metrics server if configured
            metrics_port = metrics_config.get("port", 9090)
            try:
                self.metrics.start_server(port=metrics_port)
            except Exception as e:
                logger.warning(f"Could not start metrics server: {e}")

        # Create circuit breakers for resilience
        self.siem_circuit_breaker = create_siem_circuit_breaker()
        self.smith_circuit_breaker = create_smith_circuit_breaker()

        logger.info("Phase 6 production components initialized")

        logger.info("All components initialized")

    def _get_log_file_path(self) -> Optional[str]:
        """Get log file path from config."""
        for output in self.config.get("logging", {}).get("outputs", []):
            if output.get("type") == "file":
                return output.get("path")
        return None

    async def start(self) -> None:
        """Start the agent's main processing loop."""
        if self._running:
            logger.warning("Agent is already running")
            return

        await self.initialize()

        self._running = True
        self._start_time = datetime.utcnow()
        self._shutdown_event.clear()

        logger.info("Medic Agent started")
        self._log_startup_info()

        try:
            await self.listener.connect()
            await self._process_loop()
        except asyncio.CancelledError:
            logger.info("Agent cancelled")
        except Exception as e:
            logger.error(f"Agent error: {e}", exc_info=True)
            raise
        finally:
            await self.shutdown()

    async def _process_loop(self) -> None:
        """Main processing loop for kill reports."""
        logger.info("Entering main processing loop")

        async for kill_report in self.listener.listen():
            if not self._running:
                break

            try:
                await self._process_kill_report(kill_report)
            except Exception as e:
                logger.error(
                    f"Error processing kill report: {e}",
                    kill_id=kill_report.kill_id,
                    exc_info=True,
                )

            # Check for shutdown
            if self._shutdown_event.is_set():
                break

    async def _process_kill_report(self, kill_report: KillReport) -> None:
        """Process a single kill report through the decision pipeline."""
        set_trace_context()

        logger.info(
            "Processing kill report",
            kill_id=kill_report.kill_id,
            target_module=kill_report.target_module,
            kill_reason=kill_report.kill_reason.value,
            severity=kill_report.severity.value,
        )

        # Query SIEM for context
        siem_context = await self.siem_adapter.query_context(kill_report)

        # Make decision
        decision = self.decision_engine.should_resurrect(kill_report, siem_context)

        # Log decision
        self.decision_logger.log_decision(decision, kill_report, siem_context)

        # Acknowledge the message
        await self.listener.acknowledge(kill_report.kill_id)

        self._processed_count += 1

        # Log summary
        logger.info(
            "Kill report processed",
            kill_id=kill_report.kill_id,
            decision_id=decision.decision_id,
            outcome=decision.outcome.value,
            risk_level=decision.risk_level.value,
        )

        # Mode-specific handling
        if self.mode == "observer":
            self._log_observer_summary(decision)
        elif self.mode == "manual":
            await self._handle_manual_mode(kill_report, siem_context, decision)
        elif self.mode == "semi_auto":
            await self._handle_semi_auto_mode(kill_report, siem_context, decision)
        elif self.mode == "full_auto":
            await self._handle_full_auto_mode(kill_report, siem_context, decision)

    async def _handle_manual_mode(
        self,
        kill_report: KillReport,
        siem_context,
        decision,
    ) -> None:
        """Handle kill report in manual mode - queue for human approval."""
        # Skip if decision is to deny
        if decision.outcome == DecisionOutcome.DENY:
            logger.info(
                "Decision is DENY, not queuing for approval",
                kill_id=kill_report.kill_id,
            )
            return

        # Generate proposal
        proposal = self.recommendation_engine.generate_proposal(
            kill_report, siem_context, decision
        )

        # Queue for approval
        item_id = await self.approval_queue.enqueue(proposal)

        logger.info(
            "Proposal queued for manual approval",
            item_id=item_id,
            target_module=kill_report.target_module,
            recommendation=proposal.recommendation.value,
        )

    async def _handle_semi_auto_mode(
        self,
        kill_report: KillReport,
        siem_context,
        decision,
    ) -> None:
        """Handle kill report in semi-auto mode using Phase 3 components."""
        # Perform advanced risk assessment
        risk_assessment = None
        if self.risk_assessor:
            risk_assessment = self.risk_assessor.assess(kill_report, siem_context)

            # Emit risk assessment event
            if self.event_bus:
                await self.event_bus.emit_event(
                    EventType.DECISION_MADE,
                    source="medic.semi_auto",
                    payload={
                        "kill_id": kill_report.kill_id,
                        "risk_level": risk_assessment.risk_level.value,
                        "risk_score": risk_assessment.risk_score,
                        "auto_approve_eligible": risk_assessment.auto_approve_eligible,
                    },
                    correlation_id=kill_report.kill_id,
                )

        # Try auto-resurrection if eligible
        if (decision.outcome == DecisionOutcome.APPROVE_AUTO
            and decision.auto_approve_eligible
            and self.auto_resurrector):

            logger.info(
                "Attempting auto-resurrection",
                kill_id=kill_report.kill_id,
                risk_score=decision.risk_score,
            )

            attempt = await self.auto_resurrector.attempt_resurrection(
                kill_report, decision, risk_assessment
            )

            # Emit resurrection event
            if self.event_bus:
                await self.event_bus.emit_event(
                    EventType.RESURRECTION_COMPLETED if attempt.result.value == "success"
                    else EventType.RESURRECTION_FAILED,
                    source="medic.auto_resurrector",
                    payload=attempt.to_dict(),
                    correlation_id=kill_report.kill_id,
                )

            if attempt.result.value != "success":
                # Auto-resurrection not possible, queue for manual review
                logger.info(
                    "Auto-resurrection not possible, queuing for manual review",
                    kill_id=kill_report.kill_id,
                    reason=attempt.error_message,
                )
                await self._handle_manual_mode(kill_report, siem_context, decision)

        elif decision.outcome != DecisionOutcome.DENY:
            # Queue for manual review
            await self._handle_manual_mode(kill_report, siem_context, decision)

    async def _handle_full_auto_mode(
        self,
        kill_report: KillReport,
        siem_context,
        decision,
    ) -> None:
        """Handle kill report in full autonomous mode with Smith collaboration."""
        # Check for edge cases first
        if self.edge_case_manager:
            edge_case = await self.edge_case_manager.check_edge_cases(
                kill_report, decision
            )
            if edge_case and edge_case.requires_action:
                logger.warning(
                    "Edge case detected",
                    kill_id=kill_report.kill_id,
                    edge_case_type=edge_case.case_type.value,
                    severity=edge_case.severity.value,
                )
                # Handle according to recommended action
                if edge_case.recommended_action == EdgeCaseAction.ESCALATE:
                    await self._handle_manual_mode(kill_report, siem_context, decision)
                    return
                elif edge_case.recommended_action == EdgeCaseAction.PAUSE:
                    logger.info("Pausing resurrection due to edge case")
                    return
                elif edge_case.recommended_action == EdgeCaseAction.CIRCUIT_BREAK:
                    logger.warning("Circuit breaker activated, denying resurrection")
                    return

        # Perform advanced risk assessment
        risk_assessment = None
        if self.risk_assessor:
            risk_assessment = self.risk_assessor.assess(kill_report, siem_context)

        # Try Smith negotiation for borderline cases
        if (self.smith_negotiator
            and 0.4 <= decision.risk_score <= 0.7
            and decision.outcome != DecisionOutcome.DENY):

            negotiation = await self.smith_negotiator.request_pre_kill_consultation(
                kill_id=kill_report.kill_id,
                module_name=kill_report.target_module,
                context={
                    "risk_score": decision.risk_score,
                    "kill_reason": kill_report.kill_reason.value,
                    "siem_context": siem_context.to_dict() if siem_context else {},
                },
            )

            if negotiation and negotiation.outcome:
                logger.info(
                    "Smith negotiation complete",
                    kill_id=kill_report.kill_id,
                    outcome=negotiation.outcome.value,
                )

        # Proceed with auto-resurrection if approved
        if (decision.outcome in (DecisionOutcome.APPROVE_AUTO, DecisionOutcome.PENDING_REVIEW)
            and self.auto_resurrector):

            logger.info(
                "Full-auto resurrection",
                kill_id=kill_report.kill_id,
                risk_score=decision.risk_score,
            )

            attempt = await self.auto_resurrector.attempt_resurrection(
                kill_report, decision, risk_assessment
            )

            # Record outcome for learning
            if self.outcome_store:
                self._record_outcome(
                    decision,
                    kill_report,
                    was_auto_approved=True,
                    request_id=attempt.request_id if attempt else None,
                )

            # Emit resurrection event
            if self.event_bus:
                event_type = (
                    EventType.RESURRECTION_COMPLETED
                    if attempt.result.value == "success"
                    else EventType.RESURRECTION_FAILED
                )
                await self.event_bus.emit_event(
                    event_type,
                    source="medic.full_auto",
                    payload=attempt.to_dict(),
                    correlation_id=kill_report.kill_id,
                )

            # If failed, try appeal with Smith
            if (attempt.result.value != "success"
                and self.smith_negotiator):
                await self.smith_negotiator.appeal_kill_decision(
                    kill_id=kill_report.kill_id,
                    appeal_reason=f"Resurrection failed: {attempt.error_message}",
                    evidence={"attempt": attempt.to_dict()},
                )

    async def _handle_rollback(self, request_id: str, reason: str) -> None:
        """Handle rollback triggered by monitor."""
        logger.warning(
            "Rollback triggered by monitor",
            request_id=request_id,
            reason=reason,
        )
        if self.resurrector:
            await self.resurrector.rollback(request_id, reason)

        # Emit rollback event
        if self.event_bus:
            await self.event_bus.emit_event(
                EventType.RESURRECTION_ROLLBACK,
                source="medic.monitor",
                payload={"request_id": request_id, "reason": reason},
            )

        # Notify automated collector about rollback (Phase 4)
        if self.automated_collector:
            self.automated_collector.on_rollback_triggered(request_id, reason)

    # Phase 5 callback handlers
    def _on_edge_case_detected(self, edge_case: EdgeCase) -> None:
        """Handle edge case detection."""
        logger.warning(
            "Edge case detected",
            case_id=edge_case.case_id,
            case_type=edge_case.case_type.value,
            severity=edge_case.severity.value,
            affected_modules=edge_case.affected_modules,
        )

        # Emit event if event bus available
        if self.event_bus:
            asyncio.create_task(
                self.event_bus.emit_event(
                    EventType.ANOMALY_DETECTED,
                    source="medic.edge_case_manager",
                    payload=edge_case.to_dict(),
                )
            )

    async def _on_edge_case_action(self, edge_case: EdgeCase, action: EdgeCaseAction) -> None:
        """Handle required action for edge case."""
        logger.info(
            "Edge case action required",
            case_id=edge_case.case_id,
            action=action.value,
        )

        if action == EdgeCaseAction.ALERT_OPERATOR:
            # Could integrate with alerting system here
            logger.warning(
                "OPERATOR ALERT: Edge case requires attention",
                case_type=edge_case.case_type.value,
                details=edge_case.details,
            )

    def _on_veto_decision(self, veto_response) -> None:
        """Handle veto decision from veto protocol."""
        logger.info(
            "Veto decision made",
            request_id=veto_response.request_id,
            decision=veto_response.decision.value,
            reason=veto_response.reason.value if veto_response.reason else None,
        )

    def _on_health_change(self, status: HealthStatus, previous: HealthStatus) -> None:
        """Handle health status change from self-monitor."""
        logger.info(
            "Agent health status changed",
            new_status=status.value,
            previous_status=previous.value,
        )

        # Emit health event
        if self.event_bus:
            asyncio.create_task(
                self.event_bus.emit_event(
                    EventType.ANOMALY_DETECTED if status == HealthStatus.DEGRADED else EventType.DECISION_MADE,
                    source="medic.self_monitor",
                    payload={
                        "status": status.value,
                        "previous": previous.value,
                    },
                )
            )

    async def _on_critical_health(self, reason: str) -> None:
        """Handle critical health condition from self-monitor."""
        logger.critical(
            "CRITICAL: Agent health critical",
            reason=reason,
        )

        # In critical state, switch to safe mode
        if self.mode == "full_auto":
            logger.warning("Switching to semi_auto mode due to critical health")
            self.mode = "semi_auto"

    async def _send_smith_message(self, topic: str, message: dict) -> Optional[dict]:
        """Send message to Smith via the listener's connection."""
        if self.listener and hasattr(self.listener, "send_message"):
            return await self.listener.send_message(topic, message)
        logger.warning("No message sender available for Smith communication")
        return None

    def _setup_event_handlers(self) -> None:
        """Set up event handlers for Phase 3 event-driven architecture."""
        if not self.event_bus:
            return

        # Handler for anomaly detection
        async def on_anomaly(event: Event) -> None:
            logger.warning(
                "Anomaly detected via event bus",
                event_id=event.event_id,
                payload=event.payload,
            )
            # Could trigger additional analysis or alerting here

        self.event_bus.subscribe(EventType.ANOMALY_DETECTED, on_anomaly)

        # Handler for resurrection failures
        async def on_resurrection_failed(event: Event) -> None:
            module = event.payload.get("target_module")
            if module and self.auto_resurrector:
                # Consider blacklisting after repeated failures
                history = self.auto_resurrector.get_history(limit=10, module=module)
                failures = sum(1 for a in history if a.result.value == "failed")
                if failures >= 3:
                    self.auto_resurrector.blacklist_module(
                        module,
                        reason=f"Too many failures ({failures} in recent history)"
                    )
                    logger.warning(
                        "Module blacklisted due to repeated failures",
                        module=module,
                        failure_count=failures,
                    )

        self.event_bus.subscribe(EventType.RESURRECTION_FAILED, on_resurrection_failed)

        logger.info("Event handlers configured")

    def _on_feedback_processed(self, feedback, updates: dict) -> None:
        """Handle processed feedback from the learning system."""
        logger.info(
            "Feedback processed",
            feedback_id=feedback.feedback_id,
            outcome_id=feedback.outcome_id,
            feedback_type=feedback.feedback_type.value,
            updates=list(updates.keys()),
        )

        # If thresholds need adjustment, trigger analysis
        if self.threshold_adapter and feedback.feedback_type.value in (
            "outcome_correction", "decision_correction"
        ):
            # Schedule threshold analysis (don't block)
            proposal = self.threshold_adapter.analyze_and_propose()
            if proposal:
                logger.info(
                    "Threshold adjustment proposal created",
                    proposal_id=proposal.proposal_id,
                    adjustments=len(proposal.adjustments),
                )

    def _record_outcome(
        self,
        decision,
        kill_report: KillReport,
        was_auto_approved: bool = False,
        request_id: Optional[str] = None,
    ) -> Optional[str]:
        """Record a resurrection outcome for learning."""
        if not self.outcome_store:
            return None

        import uuid

        outcome = ResurrectionOutcome(
            outcome_id=str(uuid.uuid4()),
            decision_id=decision.decision_id,
            kill_id=kill_report.kill_id,
            target_module=kill_report.target_module,
            timestamp=datetime.utcnow(),
            outcome_type=OutcomeType.UNDETERMINED,  # Will be updated by monitoring
            original_risk_score=decision.risk_score,
            original_confidence=decision.confidence,
            original_decision=decision.outcome.value,
            was_auto_approved=was_auto_approved,
            metadata={"request_id": request_id} if request_id else {},
        )

        self.outcome_store.store_outcome(outcome)

        logger.debug(
            "Outcome recorded",
            outcome_id=outcome.outcome_id,
            kill_id=kill_report.kill_id,
        )

        return outcome.outcome_id

    def _log_observer_summary(self, decision) -> None:
        """Log observer mode summary of what would have happened."""
        from core.models import DecisionOutcome

        if decision.outcome == DecisionOutcome.APPROVE_AUTO:
            action = "would AUTO-RESURRECT"
        elif decision.outcome == DecisionOutcome.DENY:
            action = "would DENY resurrection"
        elif decision.outcome == DecisionOutcome.PENDING_REVIEW:
            action = "would QUEUE for human review"
        else:
            action = f"would {decision.outcome.value}"

        logger.info(
            f"[OBSERVER] {action}",
            decision_id=decision.decision_id,
            risk_score=round(decision.risk_score, 3),
            confidence=round(decision.confidence, 3),
        )

    def _log_startup_info(self) -> None:
        """Log startup information."""
        constitution = self.config.get("constitution", {})
        phases = constitution.get("phases", {})

        enabled_phases = [
            name for name, phase in phases.items() if phase.get("enabled", False)
        ]

        logger.info(
            "Agent configuration",
            mode=self.mode,
            enabled_phases=enabled_phases,
            smith_host=self.config.get("smith", {}).get("event_bus", {}).get("host"),
            siem_endpoint=self.config.get("siem", {}).get("endpoint"),
        )

    async def shutdown(self) -> None:
        """Gracefully shut down the agent."""
        if not self._running:
            return

        logger.info("Shutting down Medic Agent")
        self._running = False
        self._shutdown_event.set()

        # Flush logs
        if self.decision_logger:
            self.decision_logger.flush()

        # Disconnect from Smith
        if self.listener:
            await self.listener.disconnect()

        # Close SIEM adapter
        if hasattr(self.siem_adapter, "close"):
            await self.siem_adapter.close()

        # Close outcome store (Phase 4)
        if self.outcome_store and hasattr(self.outcome_store, "close"):
            self.outcome_store.close()

        # Stop self-monitor (Phase 5)
        if self.self_monitor:
            await self.self_monitor.stop()

        # Log final stats
        uptime = (datetime.utcnow() - self._start_time).total_seconds() if self._start_time else 0
        logger.info(
            "Agent stopped",
            processed_count=self._processed_count,
            uptime_seconds=round(uptime, 1),
        )

    async def generate_report(self) -> None:
        """Generate a report on demand."""
        if not self.report_generator:
            await self.initialize()

        summary = self.report_generator.generate_daily_summary()
        print(f"\nDaily Summary for {summary.date}")
        print(f"Total Decisions: {summary.total_decisions}")
        print(f"Outcomes: {summary.outcomes}")
        print(f"Average Risk Score: {summary.avg_risk_score}")
        print(f"Would Have Resurrected: {summary.would_have_resurrected}")
        print(f"Would Have Denied: {summary.would_have_denied}")

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        uptime = None
        if self._start_time:
            uptime = (datetime.utcnow() - self._start_time).total_seconds()

        return {
            "status": "running" if self._running else "stopped",
            "mode": self.mode,
            "processed_count": self._processed_count,
            "uptime_seconds": uptime,
            "start_time": self._start_time.isoformat() if self._start_time else None,
        }


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    path = Path(config_path)
    if not path.exists():
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return {}

    with open(path, "r") as f:
        config = yaml.safe_load(f)

    # Also load constitution if it exists
    constitution_path = path.parent / "constitution.yaml"
    if constitution_path.exists():
        with open(constitution_path, "r") as f:
            config["constitution"] = yaml.safe_load(f)

    return config


def setup_signal_handlers(agent: MedicAgent) -> None:
    """Set up signal handlers for graceful shutdown."""
    loop = asyncio.get_event_loop()

    def handle_signal(signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown")
        asyncio.create_task(agent.shutdown())

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)


async def main_async(args: argparse.Namespace) -> int:
    """Async main entry point."""
    # Load configuration
    config = load_config(args.config)

    # Override mode if specified
    if args.mode:
        if "mode" not in config:
            config["mode"] = {}
        config["mode"]["current"] = args.mode

    # Create and start agent
    agent = MedicAgent(config)

    if args.report:
        # Just generate a report
        await agent.generate_report()
        return 0

    if args.cli:
        # Run CLI interface for manual approval
        await agent.initialize()
        from interfaces.cli import run_cli_async
        await run_cli_async(
            agent.approval_queue,
            config,
            resurrector=agent.resurrector,
            monitor=agent.monitor,
        )
        return 0

    # Set up signal handlers
    setup_signal_handlers(agent)

    # Run the agent
    try:
        await agent.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1

    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Medic Agent - Autonomous Resilience Layer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--config",
        "-c",
        default="config/medic.yaml",
        help="Path to configuration file (default: config/medic.yaml)",
    )

    parser.add_argument(
        "--mode",
        "-m",
        choices=["observer", "manual", "semi_auto", "full_auto"],
        help="Operating mode (overrides config)",
    )

    parser.add_argument(
        "--report",
        "-r",
        action="store_true",
        help="Generate a daily report and exit",
    )

    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run the CLI interface for manual approval",
    )

    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version="Medic Agent v6.0.0 (Phase 6 - Production Ready)",
    )

    args = parser.parse_args()

    # Run async main
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
