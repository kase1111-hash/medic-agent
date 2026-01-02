"""
Medic Agent CLI Interface

Command-line interface for human review and approval workflows.
Provides an interactive terminal UI for operators.
"""

import argparse
import asyncio
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from interfaces.approval_queue import ApprovalQueue, QueueItem, QueueItemStatus
from execution.recommendation import ResurrectionProposal, RecommendationType
from core.models import ResurrectionRequest
from core.logger import get_logger

logger = get_logger("interfaces.cli")


class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


def colorize(text: str, color: str) -> str:
    """Add color to text."""
    return f"{color}{text}{Colors.RESET}"


class CLIInterface:
    """
    Interactive CLI for resurrection approval workflows.

    Provides a menu-driven interface for reviewing, approving,
    and denying resurrection proposals.
    """

    def __init__(
        self,
        approval_queue: ApprovalQueue,
        resurrector: Optional[Any] = None,
        monitor: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.queue = approval_queue
        self.resurrector = resurrector
        self.monitor = monitor
        self.config = config or {}

        # Operator identity
        self.operator_name = self.config.get("operator", "operator")

        # Display settings
        self.page_size = self.config.get("page_size", 10)
        self.use_colors = self.config.get("use_colors", True)

    def color(self, text: str, color: str) -> str:
        """Colorize text if colors are enabled."""
        if self.use_colors:
            return colorize(text, color)
        return text

    async def run_interactive(self) -> None:
        """Run the interactive CLI loop."""
        print(self.color("\n=== Medic Agent CLI ===", Colors.BOLD + Colors.CYAN))
        print(f"Operator: {self.operator_name}")
        print("Type 'help' for commands\n")

        while True:
            try:
                command = input(self.color("medic> ", Colors.GREEN)).strip().lower()

                if not command:
                    continue

                if command in ("quit", "exit", "q"):
                    print("Goodbye!")
                    break

                await self._handle_command(command)

            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except EOFError:
                break
            except Exception as e:
                print(self.color(f"Error: {e}", Colors.RED))

    async def _handle_command(self, command: str) -> None:
        """Handle a CLI command."""
        parts = command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        commands = {
            "help": self._cmd_help,
            "list": self._cmd_list,
            "ls": self._cmd_list,
            "show": self._cmd_show,
            "view": self._cmd_show,
            "approve": self._cmd_approve,
            "deny": self._cmd_deny,
            "reject": self._cmd_deny,
            "stats": self._cmd_stats,
            "status": self._cmd_stats,
            "refresh": self._cmd_refresh,
        }

        handler = commands.get(cmd)
        if handler:
            await handler(args)
        else:
            print(f"Unknown command: {cmd}. Type 'help' for available commands.")

    async def _cmd_help(self, args: List[str]) -> None:
        """Display help information."""
        help_text = """
Available Commands:
  list, ls            List pending approval items
  show, view <id>     Show details of a specific item
  approve <id>        Approve a resurrection proposal
  deny <id> <reason>  Deny a resurrection proposal
  stats, status       Show queue statistics
  refresh             Refresh the queue display
  help                Show this help message
  quit, exit, q       Exit the CLI

Examples:
  list                       Show all pending items
  show abc123                View details of item abc123
  approve abc123             Approve item abc123
  deny abc123 "Too risky"    Deny with reason
"""
        print(help_text)

    async def _cmd_list(self, args: List[str]) -> None:
        """List pending items in the queue."""
        items = await self.queue.list_pending(limit=self.page_size)

        if not items:
            print(self.color("No pending items in queue.", Colors.YELLOW))
            return

        print(self.color(f"\n{'='*80}", Colors.BLUE))
        print(self.color("PENDING APPROVAL QUEUE", Colors.BOLD))
        print(self.color(f"{'='*80}", Colors.BLUE))

        for item in items:
            self._print_item_summary(item)

        print(self.color(f"\nTotal pending: {len(items)}", Colors.CYAN))

    def _print_item_summary(self, item: QueueItem) -> None:
        """Print a summary line for a queue item."""
        proposal = item.proposal

        # Determine color based on recommendation
        if proposal.recommendation == RecommendationType.APPROVE:
            rec_color = Colors.GREEN
        elif proposal.recommendation == RecommendationType.DENY:
            rec_color = Colors.RED
        elif proposal.recommendation == RecommendationType.ESCALATE:
            rec_color = Colors.MAGENTA
        else:
            rec_color = Colors.YELLOW

        # Format urgency
        urgency = proposal.urgency.value.upper()
        if urgency == "CRITICAL":
            urgency = self.color(f"[{urgency}]", Colors.RED + Colors.BOLD)
        elif urgency == "HIGH":
            urgency = self.color(f"[{urgency}]", Colors.YELLOW)
        else:
            urgency = f"[{urgency}]"

        # Time remaining
        remaining = (item.expires_at - datetime.utcnow()).total_seconds() / 60
        if remaining < 0:
            time_str = self.color("EXPIRED", Colors.RED)
        elif remaining < 60:
            time_str = f"{int(remaining)}m"
        else:
            time_str = f"{int(remaining/60)}h"

        print(f"\n{self.color(item.item_id[:8], Colors.CYAN)} | "
              f"{proposal.kill_report.target_module:20} | "
              f"{self.color(proposal.recommendation.value.upper(), rec_color):15} | "
              f"Risk: {proposal.decision.risk_score:.0%} | "
              f"{urgency} | "
              f"Expires: {time_str}")

    async def _cmd_show(self, args: List[str]) -> None:
        """Show details of a specific item."""
        if not args:
            print(self.color("Usage: show <item_id>", Colors.YELLOW))
            return

        item_id = args[0]

        # Find item with partial ID match
        items = await self.queue.list_pending(limit=100)
        item = None
        for i in items:
            if i.item_id.startswith(item_id):
                item = i
                break

        if not item:
            # Try exact match
            item = await self.queue.get_item(item_id)

        if not item:
            print(self.color(f"Item not found: {item_id}", Colors.RED))
            return

        # Display full proposal
        print(item.proposal.get_display_summary())

        # Show additional details
        print(self.color("\nAdditional Context:", Colors.BOLD))
        print(f"  Created: {item.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Expires: {item.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Priority: {item.priority}")

        # Show reasoning
        print(self.color("\nDecision Reasoning:", Colors.BOLD))
        for i, reason in enumerate(item.proposal.decision.reasoning, 1):
            print(f"  {i}. {reason}")

        # Show pre-checks
        if item.proposal.suggested_pre_checks:
            print(self.color("\nSuggested Pre-Checks:", Colors.BOLD))
            for check in item.proposal.suggested_pre_checks:
                print(f"  [ ] {check}")

        # Prompt for action
        print(self.color(f"\nActions: approve {item_id[:8]} | deny {item_id[:8]} <reason>", Colors.CYAN))

    async def _cmd_approve(self, args: List[str]) -> None:
        """Approve a resurrection proposal."""
        if not args:
            print(self.color("Usage: approve <item_id>", Colors.YELLOW))
            return

        item_id = args[0]

        # Find item with partial ID match
        items = await self.queue.list_pending(limit=100)
        full_id = None
        for item in items:
            if item.item_id.startswith(item_id):
                full_id = item.item_id
                break

        if not full_id:
            print(self.color(f"Item not found: {item_id}", Colors.RED))
            return

        # Confirm
        item = await self.queue.get_item(full_id)
        print(f"\nAbout to approve resurrection of: "
              f"{self.color(item.proposal.kill_report.target_module, Colors.BOLD)}")
        print(f"Risk: {item.proposal.decision.risk_level.value} ({item.proposal.decision.risk_score:.0%})")

        confirm = input("Confirm approval? (yes/no): ").strip().lower()
        if confirm not in ("yes", "y"):
            print("Approval cancelled.")
            return

        # Optional notes
        notes = input("Add notes (optional, press Enter to skip): ").strip()
        if not notes:
            notes = None

        try:
            request = await self.queue.approve(full_id, self.operator_name, notes)
            print(self.color(f"\nApproved! Request ID: {request.request_id}", Colors.GREEN))

            # Execute resurrection if resurrector is available
            if self.resurrector:
                print("Executing resurrection...")
                result = await self.resurrector.resurrect(request)
                if result.success:
                    print(self.color("Resurrection successful!", Colors.GREEN))

                    # Start monitoring if monitor is available
                    if self.monitor:
                        monitor_id = await self.monitor.start_monitoring(
                            request,
                            duration_minutes=30,
                        )
                        print(f"Monitoring started: {monitor_id[:8]}")
                else:
                    print(self.color(f"Resurrection failed: {result.error_message}", Colors.RED))

        except ValueError as e:
            print(self.color(f"Error: {e}", Colors.RED))

    async def _cmd_deny(self, args: List[str]) -> None:
        """Deny a resurrection proposal."""
        if len(args) < 2:
            print(self.color("Usage: deny <item_id> <reason>", Colors.YELLOW))
            return

        item_id = args[0]
        reason = " ".join(args[1:]).strip('"\'')

        # Find item with partial ID match
        items = await self.queue.list_pending(limit=100)
        full_id = None
        for item in items:
            if item.item_id.startswith(item_id):
                full_id = item.item_id
                break

        if not full_id:
            print(self.color(f"Item not found: {item_id}", Colors.RED))
            return

        # Confirm
        item = await self.queue.get_item(full_id)
        print(f"\nAbout to deny resurrection of: "
              f"{self.color(item.proposal.kill_report.target_module, Colors.BOLD)}")
        print(f"Reason: {reason}")

        confirm = input("Confirm denial? (yes/no): ").strip().lower()
        if confirm not in ("yes", "y"):
            print("Denial cancelled.")
            return

        try:
            await self.queue.deny(full_id, self.operator_name, reason)
            print(self.color(f"\nDenied.", Colors.YELLOW))
        except ValueError as e:
            print(self.color(f"Error: {e}", Colors.RED))

    async def _cmd_stats(self, args: List[str]) -> None:
        """Display queue statistics."""
        stats = await self.queue.get_stats()

        print(self.color("\n=== Queue Statistics ===", Colors.BOLD))
        print(f"Total items: {stats['total_items']}")
        print(f"Pending: {stats['pending_items']}")
        print(f"Capacity: {stats['capacity']}")
        print(f"Utilization: {stats['utilization']:.0%}")

        if stats.get('by_status'):
            print(self.color("\nBy Status:", Colors.BOLD))
            for status, count in stats['by_status'].items():
                print(f"  {status}: {count}")

        if stats.get('by_urgency'):
            print(self.color("\nPending by Urgency:", Colors.BOLD))
            for urgency, count in stats['by_urgency'].items():
                print(f"  {urgency}: {count}")

    async def _cmd_refresh(self, args: List[str]) -> None:
        """Refresh the display."""
        # Clear screen
        print("\033[2J\033[H", end="")
        await self._cmd_list(args)


def create_cli(
    approval_queue: ApprovalQueue,
    config: Dict[str, Any],
    resurrector: Optional[Any] = None,
    monitor: Optional[Any] = None,
) -> CLIInterface:
    """Factory function to create CLI interface."""
    cli_config = config.get("interfaces", {}).get("cli", {})
    return CLIInterface(
        approval_queue=approval_queue,
        resurrector=resurrector,
        monitor=monitor,
        config=cli_config,
    )


async def run_cli_async(
    approval_queue: ApprovalQueue,
    config: Dict[str, Any],
    resurrector: Optional[Any] = None,
    monitor: Optional[Any] = None,
) -> None:
    """Run the CLI asynchronously."""
    cli = create_cli(approval_queue, config, resurrector, monitor)
    await cli.run_interactive()


def main():
    """CLI entry point for standalone use."""
    parser = argparse.ArgumentParser(description="Medic Agent CLI")
    parser.add_argument("--operator", "-o", default="operator", help="Operator name")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    args = parser.parse_args()

    # Create minimal config
    config = {
        "interfaces": {
            "cli": {
                "operator": args.operator,
                "use_colors": not args.no_color,
            },
            "approval_queue": {
                "max_pending": 100,
            },
        },
    }

    # Create queue
    from interfaces.approval_queue import InMemoryApprovalQueue
    queue = InMemoryApprovalQueue(config["interfaces"]["approval_queue"])

    # Run CLI
    asyncio.run(run_cli_async(queue, config))


if __name__ == "__main__":
    main()
