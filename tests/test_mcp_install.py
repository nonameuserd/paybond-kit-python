from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from paybond_kit.cli.mcp_install import (
    build_mcp_server_entry,
    default_mcp_install_format,
    default_mcp_server_command,
    parse_mcp_install_format,
    parse_mcp_install_host,
    plan_mcp_install,
    resolve_package_local_mcp_server_command,
    serialize_mcp_install_payload,
)


def test_json_payload_references_env_file_not_raw_key() -> None:
    entry = build_mcp_server_entry(".env.local", default_mcp_server_command())
    body = json.loads(serialize_mcp_install_payload("json", entry))
    server = body["mcpServers"]["paybond"]
    assert server["env"]["PAYBOND_ENV_FILE"] == ".env.local"
    assert server["env"]["PAYBOND_MCP_TOOL_POLICY"] == "spend-write"
    assert "PAYBOND_API_KEY" not in server["env"]


def test_package_local_server_command_uses_colocated_paybond_or_module() -> None:
    command = resolve_package_local_mcp_server_command()
    assert command
    paybond = Path(sys.executable).resolve().parent / "paybond"
    if paybond.is_file():
        assert command == [str(paybond), "mcp", "serve"]
    elif command[0] == sys.executable:
        assert command[1:] == ["-m", "paybond_kit.mcp_server"]
    else:
        assert command[-2:] == ["mcp", "serve"]
        assert command[0].endswith("paybond")


def test_codex_defaults_to_toml_format() -> None:
    assert default_mcp_install_format("codex") == "toml"
    assert parse_mcp_install_format(None, host="codex") == "toml"


def test_generic_defaults_to_json_format() -> None:
    assert default_mcp_install_format("generic") == "json"
    assert parse_mcp_install_format(None, host="generic") == "json"


def test_parse_host_rejects_unknown_labels() -> None:
    with pytest.raises(ValueError, match="invalid --host"):
        parse_mcp_install_host("cursor")
    with pytest.raises(ValueError, match="missing --host"):
        parse_mcp_install_host(None)


def test_project_scope_uses_host_neutral_path(tmp_path: Path) -> None:
    plan = plan_mcp_install(
        host="claude",
        scope="project",
        fmt="json",
        env_file=".env.local",
        out=None,
        cwd=tmp_path,
        home=Path("/home/user"),
    )
    assert plan.config_path == str(tmp_path / ".paybond" / "mcp.json")
    assert plan.printed is False


def test_local_scope_prints_only(tmp_path: Path) -> None:
    plan = plan_mcp_install(
        host="generic",
        scope="local",
        fmt="json",
        env_file=".env.local",
        out=None,
        cwd=tmp_path,
        home=Path("/home/user"),
    )
    assert plan.config_path is None
    assert plan.printed is True


def test_toml_format_for_codex(tmp_path: Path) -> None:
    plan = plan_mcp_install(
        host="codex",
        scope="project",
        fmt="toml",
        env_file=".env.local",
        out=None,
        cwd=tmp_path,
        home=Path("/home/user"),
    )
    assert plan.config_path == str(tmp_path / ".paybond" / "mcp.toml")
    assert "[mcp_servers.paybond]" in plan.payload


def test_restricted_key_omits_tool_policy_env(tmp_path: Path) -> None:
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        "PAYBOND_API_KEY=paybond_rk_sandbox_keyid_secretmaterialsecretmaterialsecretmaterialsecretmaterialsecretmaterial\n",
        encoding="utf-8",
    )
    entry = build_mcp_server_entry(
        str(env_file),
        default_mcp_server_command(),
        key_kind="restricted",
    )
    assert "PAYBOND_MCP_TOOL_POLICY" not in entry.env
    assert entry.env["PAYBOND_ENV_FILE"] == str(env_file)

    from paybond_kit.cli.mcp_install import (
        RESTRICTED_KEY_TOOL_POLICY_ERROR,
        assert_tool_policy_allowed_for_key_kind,
    )

    with pytest.raises(ValueError, match="restricted"):
        assert_tool_policy_allowed_for_key_kind("restricted", True)
    assert_tool_policy_allowed_for_key_kind("restricted", False)
    assert "paybond_rk_" in RESTRICTED_KEY_TOOL_POLICY_ERROR
