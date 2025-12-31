"""CLI helpers for NovaShieldBot.

The bot lists commands and retrieves the anti-cheat API key without logging it.
"""
from __future__ import annotations

import os
from typing import Dict

from .commands import DEFAULT_COMMANDS, format_commands


class MissingAPIKeyError(RuntimeError):
    """Raised when the anti-cheat API key is not configured."""


def get_anticheat_key(env: os._Environ[str] | None = None) -> str:
    """Return the anti-cheat API key from the environment.

    The function avoids logging or printing the key to keep it out of chat history.
    """

    env = env or os.environ
    key = env.get("ANTICHEAT_API_KEY")
    if not key:
        raise MissingAPIKeyError("ANTICHEAT_API_KEY is required for anti-cheat access.")
    return key


def build_auth_headers(env: os._Environ[str] | None = None) -> Dict[str, str]:
    """Construct headers for authenticated anti-cheat API calls."""

    token = get_anticheat_key(env)
    return {"Authorization": f"Bearer {token}"}


def display_commands() -> str:
    """Return the formatted command list for chat output."""

    return format_commands(DEFAULT_COMMANDS)


if __name__ == "__main__":  # pragma: no cover
    print("Available commands:")
    print(display_commands())
