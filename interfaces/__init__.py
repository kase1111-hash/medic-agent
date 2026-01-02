"""
Medic Agent Interfaces Module

CLI/Web UI for human review and manual approval workflows.
Introduced in Phase 2.
"""

from interfaces.approval_queue import (
    ApprovalQueue,
    InMemoryApprovalQueue,
    QueueItem,
    QueueItemStatus,
    create_approval_queue,
)
from interfaces.cli import (
    CLIInterface,
    create_cli,
    run_cli_async,
)
from interfaces.web import (
    WebAPI,
    create_web_app,
    run_web_server,
    FASTAPI_AVAILABLE,
)

__all__ = [
    # Approval Queue
    "ApprovalQueue",
    "InMemoryApprovalQueue",
    "QueueItem",
    "QueueItemStatus",
    "create_approval_queue",
    # CLI
    "CLIInterface",
    "create_cli",
    "run_cli_async",
    # Web
    "WebAPI",
    "create_web_app",
    "run_web_server",
    "FASTAPI_AVAILABLE",
]
