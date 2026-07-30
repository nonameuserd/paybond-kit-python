"""Argument-parsing coverage for `paybond mcp serve` (stdio/http dispatch).

Deliberately does not exercise the branches that launch a real transport
(stdio blocks reading stdin forever; `--transport http` binds a real OS
socket) — mirrors the equivalent TypeScript coverage in
kit/ts/tests/cli/mcp-serve.test.ts, which stops at the same boundary.
"""

from __future__ import annotations

import io

from paybond_kit.cli.commands import mcp_serve_argv_matches, run_mcp_serve_command_sync


def test_mcp_serve_argv_matches_after_global_flags() -> None:
    assert mcp_serve_argv_matches(["mcp", "serve"]) is True
    assert mcp_serve_argv_matches(["--env-file", ".env.local", "mcp", "serve"]) is True
    assert mcp_serve_argv_matches(["doctor", "--agent"]) is False


def test_mcp_serve_help_mentions_transport_flag() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = run_mcp_serve_command_sync(["mcp", "serve", "--help"], stdout=stdout, stderr=stderr)
    assert code == 0
    assert "paybond mcp serve" in stdout.getvalue()
    assert "--transport" in stdout.getvalue()


def test_mcp_serve_rejects_invalid_transport_value() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = run_mcp_serve_command_sync(
        ["mcp", "serve", "--transport", "carrier-pigeon"], stdout=stdout, stderr=stderr
    )
    assert code == 2
    assert "invalid --transport" in stderr.getvalue()


def test_mcp_serve_rejects_unexpected_arguments_after_transport() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = run_mcp_serve_command_sync(
        ["mcp", "serve", "--transport", "http", "extra"], stdout=stdout, stderr=stderr
    )
    assert code == 2
    assert "unexpected arguments" in stderr.getvalue()


def test_mcp_serve_rejects_legacy_unexpected_arguments() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = run_mcp_serve_command_sync(["mcp", "serve", "extra"], stdout=stdout, stderr=stderr)
    assert code == 2
    assert "unexpected arguments" in stderr.getvalue()
