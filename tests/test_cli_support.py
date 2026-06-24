from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from paybond_kit.cli.router import run_cli

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


@pytest.mark.asyncio
async def test_version_prints_package_version(tmp_path: Path) -> None:
    stdout = io.StringIO()
    code = await run_cli(["version"], stdout=stdout)
    assert code == 0
    assert stdout.getvalue().strip().count(".") == 2


@pytest.mark.asyncio
async def test_version_verbose_json_includes_redacted_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)
    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "version", "--verbose", "--request-id", "01VERSIONVERBOSE01"],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    data = payload["data"]
    assert data["package_name"] == "paybond-kit"
    assert data["request_id"] == "01VERSIONVERBOSE01"
    assert data["mcp_tool_count"] > 0
    assert data["credential_source"]["source"] == "process_env"
    assert "..." in data["credential_source"]["key_masked"]
    assert RAW_KEY not in stdout.getvalue()


@pytest.mark.asyncio
async def test_diagnose_requires_redacted_flag(tmp_path: Path) -> None:
    stderr = io.StringIO()
    code = await run_cli(["diagnose"], stderr=stderr)
    assert code == 1
    assert "requires --redacted" in stderr.getvalue()


@pytest.mark.asyncio
async def test_diagnose_redacted_never_prints_raw_key(tmp_path: Path) -> None:
    env_path = tmp_path / ".env.local"
    env_path.write_text(f"PAYBOND_API_KEY={RAW_KEY}\n", encoding="utf-8")
    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "--env-file", str(env_path), "diagnose", "--redacted"],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["redacted"] is True
    assert payload["data"]["diagnostics"]["credential_source"]["source"] == "env_file"
    assert RAW_KEY not in stdout.getvalue()
