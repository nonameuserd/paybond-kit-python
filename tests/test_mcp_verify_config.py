from __future__ import annotations

import json
from pathlib import Path

import pytest

from paybond_kit.cli.mcp_install import serialize_mcp_install_payload, build_mcp_server_entry, default_mcp_server_command
from paybond_kit.mcp_policy import parse_mcp_tool_policy
from paybond_kit.cli.mcp_verify_config import validate_mcp_host_config, verify_mcp_install_plan


def test_verify_config_accepts_generated_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    env_path = tmp_path / ".env.local"
    env_path.write_text("PAYBOND_API_KEY=paybond_sk_sandbox_x\n", encoding="utf-8")
    result = verify_mcp_install_plan(
        host="generic",
        scope="local",
        fmt="json",
        env_file=".env.local",
        cwd=tmp_path,
        home=tmp_path,
    )
    assert result.ok is True
    assert result.source == "generated"


def test_verify_config_rejects_embedded_api_key(tmp_path: Path) -> None:
    entry = build_mcp_server_entry(".env.local", default_mcp_server_command())
    entry = type(entry)(command=entry.command, args=entry.args, env={**entry.env, "PAYBOND_API_KEY": "secret"})
    payload = serialize_mcp_install_payload("json", entry)
    result = validate_mcp_host_config(
        host="generic",
        fmt="json",
        payload=payload,
        cwd=tmp_path,
        expected_env_file=".env.local",
    )
    assert result.ok is False
    assert any(issue.field == "env" for issue in result.issues)


def test_verify_config_accepts_tool_policy_env(tmp_path: Path) -> None:
    env_path = tmp_path / ".env.local"
    env_path.write_text("PAYBOND_API_KEY=paybond_sk_sandbox_x\n", encoding="utf-8")
    entry = build_mcp_server_entry(
        ".env.local",
        default_mcp_server_command(),
        tool_policy=parse_mcp_tool_policy("readonly"),
    )
    payload = serialize_mcp_install_payload("json", entry)
    body = json.loads(payload)
    assert body["mcpServers"]["paybond"]["env"]["PAYBOND_MCP_TOOL_POLICY"] == "readonly"
    result = validate_mcp_host_config(
        host="generic",
        fmt="json",
        payload=payload,
        cwd=tmp_path,
        expected_env_file=".env.local",
    )
    assert result.ok is True
    assert result.tool_policy is not None
    assert result.tool_policy.policy == "readonly"
