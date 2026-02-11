"""
Medic Agent — Autonomous Resilience Layer

Listens for Smith kill reports, evaluates resurrection risk,
makes decisions, records outcomes. One kill report at a time.

Usage:
    python main.py                          # Use config/medic.yaml
    python main.py --config path/to.yaml    # Custom config
    python main.py --mock                   # Mock listener (no Redis)
"""

import argparse
import asyncio
import os
import signal
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import yaml

from core.decision import DecisionEngine, create_decision_engine
from core.listener import KillReportListener, create_listener
from core.logger import configure_logging, get_logger
from core.models import DecisionOutcome, KillReport, ResurrectionDecision
from learning.outcome_store import (
    FeedbackSource,
    OutcomeStore,
    OutcomeType,
    ResurrectionOutcome,
    create_outcome_store,
)

logger = get_logger("medic.main")


def load_config(config_path: str) -> Dict[str, Any]:
    """Load and validate configuration from YAML file."""
    path = Path(config_path)
    if not path.exists():
        logger.error("Config file not found: %s", config_path)
        sys.exit(1)

    with open(path) as f:
        config = yaml.safe_load(f)

    # Environment overrides
    if env_mode := os.environ.get("MEDIC_MODE"):
        config["mode"] = env_mode

    logger.info("Config loaded", path=config_path, mode=config.get("mode"))
    return config


def build_outcome(
    kill_report: KillReport,
    decision: ResurrectionDecision,
) -> ResurrectionOutcome:
    """Build an outcome record from a decision (no resurrection yet)."""
    return ResurrectionOutcome(
        outcome_id=str(uuid.uuid4()),
        decision_id=decision.decision_id,
        kill_id=kill_report.kill_id,
        target_module=kill_report.target_module,
        timestamp=datetime.now(timezone.utc),
        outcome_type=OutcomeType.UNDETERMINED,
        original_risk_score=decision.risk_score,
        original_confidence=decision.confidence,
        original_decision=decision.outcome.value,
        was_auto_approved=decision.outcome == DecisionOutcome.APPROVE_AUTO,
        feedback_source=FeedbackSource.AUTOMATED,
        metadata={
            "kill_reason": kill_report.kill_reason.value,
            "severity": kill_report.severity.value,
            "risk_level": decision.risk_level.value,
        },
    )


async def process_kill_report(
    kill_report: KillReport,
    decision_engine: DecisionEngine,
    outcome_store: OutcomeStore,
    listener: KillReportListener,
    mode: str,
) -> None:
    """Process a single kill report through the full pipeline."""

    # 1. Make decision
    decision = decision_engine.should_resurrect(kill_report)

    # 2. Act on decision (Phase 2 adds real resurrection here)
    if decision.outcome == DecisionOutcome.APPROVE_AUTO:
        if mode == "observer":
            logger.info(
                "OBSERVER: Would auto-resurrect (no action taken)",
                kill_id=kill_report.kill_id,
                target_module=kill_report.target_module,
            )
        else:
            logger.info(
                "APPROVED: Resurrection approved — awaiting executor (Phase 2)",
                kill_id=kill_report.kill_id,
                target_module=kill_report.target_module,
            )
    elif decision.outcome == DecisionOutcome.DENY:
        logger.info(
            "DENIED: Resurrection denied",
            kill_id=kill_report.kill_id,
            target_module=kill_report.target_module,
            risk_score=round(decision.risk_score, 3),
        )
    elif decision.outcome == DecisionOutcome.PENDING_REVIEW:
        logger.info(
            "PENDING: Queued for manual review",
            kill_id=kill_report.kill_id,
            target_module=kill_report.target_module,
            risk_score=round(decision.risk_score, 3),
        )

    # 3. Record outcome
    outcome = build_outcome(kill_report, decision)
    outcome_store.store_outcome(outcome)

    # 4. Acknowledge message
    await listener.acknowledge(kill_report.kill_id)

    logger.info(
        "Kill report processed",
        kill_id=kill_report.kill_id,
        decision=decision.outcome.value,
        risk=round(decision.risk_score, 3),
        confidence=round(decision.confidence, 3),
        outcome_id=outcome.outcome_id,
    )


async def run(config: Dict[str, Any]) -> None:
    """Main event loop: listen → decide → record."""
    mode = config.get("mode", "observer")

    # Initialize components
    listener = create_listener(config)
    decision_engine = create_decision_engine(config)
    outcome_store = create_outcome_store(config)

    # Wire outcome store into risk assessor if using the decision engine
    # that has a risk config (for false positive history lookups)
    if hasattr(decision_engine, 'config'):
        logger.debug("Outcome store available for history lookups")

    # Connect to event bus
    await listener.connect()
    healthy = await listener.health_check()
    if not healthy:
        logger.error("Listener health check failed after connect")
        return

    logger.info(
        "Medic Agent started",
        mode=mode,
        version="0.2.0-alpha",
    )

    processed = 0

    try:
        async for kill_report in listener.listen():
            try:
                await process_kill_report(
                    kill_report=kill_report,
                    decision_engine=decision_engine,
                    outcome_store=outcome_store,
                    listener=listener,
                    mode=mode,
                )
                processed += 1
            except Exception as e:
                logger.error(
                    "Failed to process kill report",
                    kill_id=kill_report.kill_id,
                    error=str(e),
                    exc_info=True,
                )
    except asyncio.CancelledError:
        logger.info("Main loop cancelled")
    finally:
        logger.info("Shutting down", total_processed=processed)
        await listener.disconnect()


def setup_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Register signal handlers for graceful shutdown."""
    shutdown_event = asyncio.Event()

    def handle_signal(sig: int) -> None:
        sig_name = signal.Signals(sig).name
        logger.info("Received %s, shutting down gracefully...", sig_name)
        # Cancel all running tasks
        for task in asyncio.all_tasks(loop):
            if task is not asyncio.current_task():
                task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal, sig)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Medic Agent — Autonomous Resilience Layer",
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("MEDIC_CONFIG_PATH", "config/medic.yaml"),
        help="Path to configuration file (default: config/medic.yaml)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock listener instead of Redis (for development)",
    )
    parser.add_argument(
        "--mode",
        choices=["observer", "live"],
        help="Override operating mode from config",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point."""
    args = parse_args()
    config = load_config(args.config)

    # CLI overrides
    if args.mock:
        config.setdefault("smith", {}).setdefault("event_bus", {})["type"] = "mock"
    if args.mode:
        config["mode"] = args.mode

    # Configure logging
    log_config = config.get("logging", {})
    configure_logging(
        level=log_config.get("level", "INFO"),
        format_type=log_config.get("format", "text"),
    )

    logger.info(
        "Medic Agent v0.2.0-alpha",
        mode=config.get("mode"),
        listener=config.get("smith", {}).get("event_bus", {}).get("type", "redis"),
    )

    # Run the event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        setup_signal_handlers(loop)
    except NotImplementedError:
        # Signal handlers not supported on this platform (e.g., Windows)
        pass

    try:
        loop.run_until_complete(run(config))
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        # Cancel remaining tasks
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()
        logger.info("Medic Agent stopped")


if __name__ == "__main__":
    main()
