from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

from paybond_kit.cli.doctor_agent import run_agent_mcp_checks
from paybond_kit.cli.router import run_cli

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


@pytest.mark.asyncio
async def test_mcp_install_requires_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stderr = io.StringIO()
    code = await run_cli(["mcp", "install"], stderr=stderr)
    assert code == 1
    assert "missing --host" in stderr.getvalue()


@pytest.mark.asyncio
async def test_mcp_install_json_uses_env_file_reference(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "mcp", "install", "--host", "generic", "--scope", "project", "--env-file", ".env.local"],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is True
    assert payload["data"]["host"] == "generic"
    config_path = tmp_path / ".paybond" / "mcp.json"
    body = json.loads(config_path.read_text(encoding="utf-8"))
    assert body["mcpServers"]["paybond"]["env"]["PAYBOND_ENV_FILE"] == ".env.local"
    assert "PAYBOND_API_KEY" not in body["mcpServers"]["paybond"]["env"]


@pytest.mark.asyncio
async def test_mcp_install_local_scope_json_includes_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "mcp", "install", "--host", "generic", "--scope", "local", "--env-file", ".env.local"],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is True
    assert payload["data"]["printed"] is True
    assert "payload" in payload["data"]
    body = json.loads(payload["data"]["payload"])
    assert body["mcpServers"]["paybond"]["env"]["PAYBOND_ENV_FILE"] == ".env.local"


@pytest.mark.asyncio
async def test_doctor_agent_runs_mcp_checks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    env_path = tmp_path / ".env.local"
    env_path.write_text(f"PAYBOND_API_KEY={RAW_KEY}\n", encoding="utf-8")

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        assert method == "GET"
        assert path == "/v1/auth/principal"
        return {
            "tenant_id": "tenant-sandbox",
            "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "environment": "sandbox",
            "service_account_role": "operator",
        }

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "doctor", "--agent", "--env-file", ".env.local"],
        stdout=stdout,
    )
    assert code in (0, 1)
    payload = json.loads(stdout.getvalue())
    names = {check["name"] for check in payload["data"]["checks"]}
    assert "runtime" in names
    assert "package" in names
    assert "env_file" in names
    assert "key_shape" in names
    assert "principal" in names
    assert "mcp_host_config" in names
    assert "mcp_env_resolution" in names
    assert "mcp_launch" in names
    assert "mcp_initialize" in names
    assert "mcp_tools_list" in names
    assert "mcp_tool_schemas" in names
    assert "mcp_stdout_purity" in names


def test_run_agent_mcp_checks_does_not_block_on_open_stdout(tmp_path: Path) -> None:
    """Regression: blocking stdout.read() hung doctor after MCP initialize succeeded."""

    env_path = tmp_path / ".env.local"
    env_path.write_text(f"PAYBOND_API_KEY={RAW_KEY}\n", encoding="utf-8")

    start = time.monotonic()
    checks = run_agent_mcp_checks(
        env_file=".env.local",
        cwd=tmp_path,
        timeout_seconds=15.0,
    )
    elapsed = time.monotonic() - start

    assert elapsed < 20.0
    names = {check.name for check in checks}
    assert names >= {
        "mcp_launch",
        "mcp_initialize",
        "mcp_tools_list",
        "mcp_tool_schemas",
        "mcp_stdout_purity",
    }
