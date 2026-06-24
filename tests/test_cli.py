from __future__ import annotations

import io

import pytest

from paybond_kit.cli.router import run_cli


@pytest.mark.asyncio
async def test_cli_root_help_lists_canonical_commands() -> None:
    stdout = io.StringIO()
    code = await run_cli(["--help"], stdout=stdout)
    output = stdout.getvalue()
    assert code == 0
    assert "Getting started:" in output
    assert "login" in output
    assert "init guardrail" in output
    assert "mcp serve|install|verify-config|tools" in output
    assert "audit exports list|get|verify|delete" in output
    assert "paybond help <command>" in output


@pytest.mark.asyncio
async def test_cli_rejects_tenant_override_flag() -> None:
    stderr = io.StringIO()
    code = await run_cli(["--tenant-id", "tenant-a", "whoami"], stderr=stderr)
    assert code == 1
    assert "tenant scope comes from authenticated credentials" in stderr.getvalue()
