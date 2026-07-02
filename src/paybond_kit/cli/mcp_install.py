from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from paybond_kit.mcp_policy import McpToolPolicyConfig, mcp_tool_policy_env, resolve_mcp_tool_policy

McpInstallFormat = Literal["json", "toml"]
McpInstallScope = Literal["local", "project", "user"]
McpInstallHost = Literal["claude", "codex", "openai", "generic"]

MCP_INSTALL_HOSTS: tuple[McpInstallHost, ...] = ("claude", "codex", "openai", "generic")


@dataclass(frozen=True)
class McpServerEntry:
    command: str
    args: list[str]
    env: dict[str, str]


@dataclass(frozen=True)
class McpInstallPlan:
    host: str
    scope: McpInstallScope
    format: McpInstallFormat
    env_file: str
    config_path: str | None
    server_command: list[str]
    payload: str
    printed: bool
    tool_policy: McpToolPolicyConfig | None = None


def resolve_package_local_mcp_server_command() -> list[str]:
    """Return the installed package's canonical stdio MCP server launch command."""

    entry = shutil.which("paybond-mcp-server")
    if entry:
        return [entry]
    return [sys.executable, "-m", "paybond_kit.mcp_server"]


def default_mcp_server_command() -> list[str]:
    return resolve_package_local_mcp_server_command()


def build_mcp_server_entry(
    env_file: str,
    server_command: list[str],
    *,
    tool_policy: McpToolPolicyConfig | None = None,
) -> McpServerEntry:
    env = {"PAYBOND_ENV_FILE": env_file, **mcp_tool_policy_env(resolve_mcp_tool_policy(tool_policy or McpToolPolicyConfig()))}
    return McpServerEntry(
        command=server_command[0],
        args=server_command[1:],
        env=env,
    )


def serialize_mcp_install_payload(fmt: McpInstallFormat, entry: McpServerEntry) -> str:
    if fmt == "toml":
        env_lines = "\n".join(f"{key} = {json.dumps(value)}" for key, value in entry.env.items())
        return (
            "# Paybond MCP stdio server — merge into your host MCP config\n"
            "[mcp_servers.paybond]\n"
            f'command = {json.dumps(entry.command)}\n'
            f"args = {json.dumps(entry.args)}\n"
            "\n"
            "[mcp_servers.paybond.env]\n"
            f"{env_lines}\n"
        )
    return json.dumps({"mcpServers": {"paybond": {"command": entry.command, "args": entry.args, "env": entry.env}}}, indent=2) + "\n"


def resolve_mcp_install_path(
    scope: McpInstallScope,
    fmt: McpInstallFormat,
    out: str | None,
    cwd: Path,
    home: Path,
) -> Path | None:
    if out and out.strip():
        return Path(out.strip())
    if scope == "local":
        return None
    ext = "toml" if fmt == "toml" else "json"
    base = home if scope == "user" else cwd
    return base / ".paybond" / f"mcp.{ext}"


def default_mcp_install_format(host: McpInstallHost) -> McpInstallFormat:
    return "toml" if host == "codex" else "json"


def plan_mcp_install(
    *,
    host: McpInstallHost,
    scope: McpInstallScope,
    fmt: McpInstallFormat,
    env_file: str,
    out: str | None,
    cwd: Path,
    home: Path,
    server_command: list[str] | None = None,
    tool_policy: McpToolPolicyConfig | None = None,
) -> McpInstallPlan:
    command = server_command or default_mcp_server_command()
    entry = build_mcp_server_entry(env_file, command, tool_policy=tool_policy)
    payload = serialize_mcp_install_payload(fmt, entry)
    config_path = resolve_mcp_install_path(scope, fmt, out, cwd, home)
    return McpInstallPlan(
        host=host,
        scope=scope,
        format=fmt,
        env_file=env_file,
        config_path=str(config_path) if config_path is not None else None,
        server_command=command,
        payload=payload,
        printed=config_path is None,
        tool_policy=tool_policy,
    )


def parse_mcp_install_host(raw: str | None) -> McpInstallHost:
    value = (raw or "").strip().lower()
    if not value:
        raise ValueError("missing --host (expected claude|codex|openai|generic)")
    if value in MCP_INSTALL_HOSTS:
        return value  # type: ignore[return-value]
    raise ValueError("invalid --host (expected claude|codex|openai|generic)")


def parse_mcp_install_format(raw: str | None, *, host: McpInstallHost) -> McpInstallFormat:
    if raw is None or not raw.strip():
        return default_mcp_install_format(host)
    value = raw.strip().lower()
    if value in ("json", "toml"):
        return value  # type: ignore[return-value]
    raise ValueError("invalid --format (expected json|toml)")


def parse_mcp_install_scope(raw: str | None) -> McpInstallScope:
    value = (raw or "project").strip().lower()
    if value in ("local", "project", "user"):
        return value  # type: ignore[return-value]
    raise ValueError("invalid --scope (expected local|project|user)")
