"""Command definitions and display helpers for the bot CLI."""
from dataclasses import dataclass
from typing import Iterable, List


@dataclass(frozen=True)
class BotCommand:
    """Represents a single bot command."""

    name: str
    description: str


DEFAULT_COMMANDS: List[BotCommand] = [
    BotCommand(name="help", description="Show a list of available commands."),
    BotCommand(name="start", description="Activate the bot and begin monitoring."),
    BotCommand(name="status", description="Show the current monitoring status."),
    BotCommand(name="stop", description="Deactivate monitoring and free resources."),
]


def format_commands(commands: Iterable[BotCommand] = DEFAULT_COMMANDS) -> str:
    """Return a human-friendly command list for chat help output.

    The function keeps the command listing in one place so the bot cannot forget to
    show commands when users ask for help.
    """

    return "\n".join(f"/{cmd.name} — {cmd.description}" for cmd in commands)
