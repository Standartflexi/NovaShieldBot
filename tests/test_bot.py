import os

import pytest

from src.bot import build_auth_headers, display_commands, get_anticheat_key, MissingAPIKeyError


def test_display_commands_lists_all_defaults():
    output = display_commands()

    assert "help" in output
    assert "start" in output
    assert "status" in output
    assert "stop" in output


def test_get_anticheat_key_requires_env_var():
    with pytest.raises(MissingAPIKeyError):
        get_anticheat_key(env={})


def test_build_auth_headers_includes_token_without_logging():
    token = "example-token"
    env = {"ANTICHEAT_API_KEY": token}

    headers = build_auth_headers(env)

    assert headers["Authorization"] == f"Bearer {token}"
    # Ensure the token is not echoed anywhere else by the helper.
    assert token not in display_commands()
