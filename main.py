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
        """Handle kill report in semi-auto mode."""
        # Auto-approve if eligible, otherwise queue
        if decision.outcome == DecisionOutcome.APPROVE_AUTO and decision.auto_approve_eligible:
            logger.info(
                "Auto-approving resurrection",
                kill_id=kill_report.kill_id,
            )
            # Create request and execute
            from core.models import ResurrectionRequest
            request = ResurrectionRequest.from_decision(decision, kill_report)
            request.approved_by = "auto"

            result = await self.resurrector.resurrect(request)
            if result.success:
                # Start monitoring
                await self.monitor.start_monitoring(
                    request,
                    duration_minutes=self.config.get("resurrection", {}).get(
                        "monitoring_duration_minutes", 30
                    ),
                )
        elif decision.outcome != DecisionOutcome.DENY:
            # Queue for manual review
            await self._handle_manual_mode(kill_report, siem_context, decision)

    async def _handle_rollback(self, request_id: str, reason: str) -> None:
        """Handle rollback triggered by monitor."""
        logger.warning(
            "Rollback triggered by monitor",
            request_id=request_id,
            reason=reason,
        )
        if self.resurrector:
            await self.resurrector.rollback(request_id, reason)

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
        version="Medic Agent v2.0.0 (Phase 2)",
    )

    args = parser.parse_args()

    # Run async main
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
