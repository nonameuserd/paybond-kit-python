from __future__ import annotations

import io
import json
from unittest.mock import AsyncMock

import pytest

from paybond_kit.cli import router
from paybond_kit.cli.router import run_cli
from paybond_kit.cli.core import EXIT_AUTH


@pytest.mark.asyncio
async def test_run_cli_catches_generic_exception_and_suggests_doctor(monkeypatch):
    # Simulate _dispatch raising an unexpected exception.
    async def _bad_dispatch(ctx, command):
        raise Exception("something exploded")

    monkeypatch.setattr(router, "_dispatch", _bad_dispatch)
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = await run_cli(["--format", "json", "help"], stdout=stdout, stderr=stderr)
    assert code == 1
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert "paybond doctor" in payload["error"]["message"]


@pytest.mark.asyncio
async def test_run_cli_maps_systemexit_missing_api_key(monkeypatch):
    async def _exit_dispatch(ctx, command):
        raise SystemExit("PAYBOND_API_KEY is required; run paybond-kit-login")

    monkeypatch.setattr(router, "_dispatch", _exit_dispatch)
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = await run_cli(["--format", "json", "help"], stdout=stdout, stderr=stderr)
    # Missing API key should map to auth exit code
    assert code == EXIT_AUTH
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert "PAYBOND_API_KEY" in payload["error"]["message"]
    assert "paybond login" in payload["error"]["message"] or "paybond-kit-login" in payload["error"]["message"]


@pytest.mark.asyncio
async def test_run_cli_boundary_valueerror_adds_command_hint(monkeypatch):
    async def _bad_dispatch(ctx, command):
        raise ValueError("policy file is malformed")

    monkeypatch.setattr(router, "_dispatch", _bad_dispatch)
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = await run_cli(["--format", "json", "policy", "preview"], stdout=stdout, stderr=stderr)
    assert code == 1
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert payload["error"]["category"] == "validation"
    assert payload["error"]["code"] == "cli.policy.validation"
    message = payload["error"]["message"]
    assert "policy file is malformed" in message
    assert "paybond policy validate-tools" in message


@pytest.mark.asyncio
async def test_run_cli_boundary_valueerror_generic_command_without_hint(monkeypatch):
    async def _bad_dispatch(ctx, command):
        raise ValueError("bad thing")

    monkeypatch.setattr(router, "_dispatch", _bad_dispatch)
    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "receipts", "list"], stdout=stdout)
    assert code == 1
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == "cli.validation"
    assert payload["error"]["message"] == "bad thing"


@pytest.mark.asyncio
async def test_run_cli_debug_flag_prints_traceback_to_stderr(monkeypatch):
    async def _bad_dispatch(ctx, command):
        raise ValueError("boom")

    monkeypatch.setattr(router, "_dispatch", _bad_dispatch)
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = await run_cli(["--debug", "--format", "json", "policy", "preview"], stdout=stdout, stderr=stderr)
    assert code == 1
    # Friendly JSON envelope still lands on stdout.
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    # Stack trace is emitted to stderr for diagnostics.
    err = stderr.getvalue()
    assert "Traceback (most recent call last)" in err
    assert "ValueError: boom" in err


@pytest.mark.asyncio
async def test_run_cli_no_traceback_by_default(monkeypatch):
    async def _bad_dispatch(ctx, command):
        raise ValueError("boom")

    monkeypatch.setattr(router, "_dispatch", _bad_dispatch)
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = await run_cli(["--format", "json", "policy", "preview"], stdout=stdout, stderr=stderr)
    assert code == 1
    assert "Traceback" not in stderr.getvalue()


@pytest.mark.asyncio
async def test_run_cli_debug_env_var_enables_traceback(monkeypatch):
    async def _bad_dispatch(ctx, command):
        raise Exception("kaboom")

    monkeypatch.setenv("PAYBOND_CLI_DEBUG", "1")
    monkeypatch.setattr(router, "_dispatch", _bad_dispatch)
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = await run_cli(["--format", "json", "help"], stdout=stdout, stderr=stderr)
    assert code == 1
    assert "Traceback (most recent call last)" in stderr.getvalue()


@pytest.mark.asyncio
async def test_run_cli_debug_traceback_on_argv_parse_error(monkeypatch):
    monkeypatch.setenv("PAYBOND_CLI_DEBUG", "1")
    stdout = io.StringIO()
    stderr = io.StringIO()
    # Unknown global flag is rejected during argv parsing (before globals exist).
    code = await run_cli(["--not-a-flag", "help"], stdout=stdout, stderr=stderr)
    assert code != 0
    assert "Traceback (most recent call last)" in stderr.getvalue()

