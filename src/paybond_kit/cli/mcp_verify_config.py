from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from paybond_kit.cli.mcp_install import (
    McpInstallFormat,
    McpInstallHost,
    McpInstallScope,
    McpServerEntry,
    default_mcp_server_command,
    parse_mcp_install_scope,
    plan_mcp_install,
)
from paybond_kit.mcp_policy import (
    MCP_TOOL_ALLOWLIST_ENV,
    MCP_TOOL_POLICY_ENV,
    McpToolPolicyConfig,
    merge_mcp_tool_policy,
    parse_mcp_tool_allowlist,
    parse_mcp_tool_policy,
)

McpConfigSource = Literal["generated", "file"]


@dataclass(frozen=True)
class McpConfigValidationIssue:
    field: str
    message: str


@dataclass(frozen=True)
class McpConfigValidationResult:
    ok: bool
    host: str
    source: McpConfigSource
    config_path: str | None
    issues: tuple[McpConfigValidationIssue, ...]
    entry: McpServerEntry | None = None
    tool_policy: McpToolPolicyConfig | None = None

    @property
    def message(self) -> str:
        if self.ok:
            return "MCP host config is valid"
        first = self.issues[0].message if self.issues else "invalid MCP config"
        return first


def _parse_toml_paybond_entry(payload: str) -> dict[str, Any]:
    section = "[mcp_servers.paybond]"
    if section not in payload:
        raise ValueError("missing [mcp_servers.paybond] section")
    block = payload.split(section, 1)[1]
    env_section = "[mcp_servers.paybond.env]"
    if env_section in block:
        block, env_block = block.split(env_section, 1)
    else:
        env_block = ""
    command_match = re.search(r'command\s*=\s*(.+)', block)
    args_match = re.search(r"args\s*=\s*(\[.*\])", block, re.DOTALL)
    if command_match is None:
        raise ValueError("missing paybond command")
    command = json.loads(command_match.group(1).strip())
    args = json.loads(args_match.group(1).strip()) if args_match else []
    env: dict[str, str] = {}
    for line in env_block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = json.loads(value.strip())
    return {"command": command, "args": args, "env": env}


def parse_mcp_host_entry(payload: str, fmt: McpInstallFormat) -> McpServerEntry:
    if fmt == "toml":
        parsed = _parse_toml_paybond_entry(payload)
    else:
        body = json.loads(payload)
        if not isinstance(body, dict):
            raise ValueError("config root must be an object")
        servers = body.get("mcpServers")
        if not isinstance(servers, dict):
            raise ValueError("missing mcpServers object")
        paybond = servers.get("paybond")
        if not isinstance(paybond, dict):
            raise ValueError("missing mcpServers.paybond entry")
        parsed = paybond
    command = parsed.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("missing paybond command")
    args = parsed.get("args", [])
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise ValueError("paybond args must be a string array")
    env = parsed.get("env", {})
    if not isinstance(env, dict):
        raise ValueError("paybond env must be an object")
    return McpServerEntry(command=command, args=[str(item) for item in args], env={str(k): str(v) for k, v in env.items()})


def _validate_entry(
    entry: McpServerEntry,
    *,
    cwd: Path,
    expected_env_file: str | None,
) -> tuple[list[McpConfigValidationIssue], McpToolPolicyConfig | None]:
    issues: list[McpConfigValidationIssue] = []
    if "PAYBOND_API_KEY" in entry.env:
        issues.append(McpConfigValidationIssue("env", "config must reference PAYBOND_ENV_FILE, not PAYBOND_API_KEY"))
    env_file = entry.env.get("PAYBOND_ENV_FILE", "").strip()
    if not env_file:
        issues.append(McpConfigValidationIssue("env", "missing PAYBOND_ENV_FILE"))
    elif expected_env_file and env_file != expected_env_file:
        issues.append(
            McpConfigValidationIssue(
                "env",
                f"PAYBOND_ENV_FILE mismatch: config={env_file!r} expected={expected_env_file!r}",
            )
        )
    resolved_env = Path(env_file) if env_file and Path(env_file).is_absolute() else cwd / env_file
    if env_file and not resolved_env.is_file():
        issues.append(McpConfigValidationIssue("env", f"env file not found: {resolved_env}"))
    if not entry.command.strip():
        issues.append(McpConfigValidationIssue("command", "missing MCP server command"))

    tool_policy: McpToolPolicyConfig | None = None
    raw_policy = entry.env.get(MCP_TOOL_POLICY_ENV, "").strip()
    raw_allowlist = entry.env.get(MCP_TOOL_ALLOWLIST_ENV, "").strip()
    if raw_policy or raw_allowlist:
        try:
            tool_policy = merge_mcp_tool_policy(
                parse_mcp_tool_policy(raw_policy or None),
                allowlist=parse_mcp_tool_allowlist(raw_allowlist or None) or None,
            )
        except ValueError as exc:
            issues.append(McpConfigValidationIssue("tool_policy", str(exc)))

    return issues, tool_policy


def validate_mcp_host_config(
    *,
    host: McpInstallHost,
    fmt: McpInstallFormat,
    payload: str,
    cwd: Path,
    expected_env_file: str | None = None,
    source: McpConfigSource = "generated",
    config_path: str | None = None,
) -> McpConfigValidationResult:
    try:
        entry = parse_mcp_host_entry(payload, fmt)
    except (ValueError, json.JSONDecodeError) as exc:
        return McpConfigValidationResult(
            ok=False,
            host=host,
            source=source,
            config_path=config_path,
            issues=(McpConfigValidationIssue("config", str(exc)),),
        )
    issues, tool_policy = _validate_entry(entry, cwd=cwd, expected_env_file=expected_env_file)
    return McpConfigValidationResult(
        ok=len(issues) == 0,
        host=host,
        source=source,
        config_path=config_path,
        issues=tuple(issues),
        entry=entry,
        tool_policy=tool_policy,
    )


def verify_mcp_install_plan(
    *,
    host: McpInstallHost,
    scope: McpInstallScope | str,
    fmt: McpInstallFormat,
    env_file: str,
    cwd: Path,
    home: Path,
    out: str | None = None,
    tool_policy: McpToolPolicyConfig | None = None,
    config_path: str | None = None,
    payload: str | None = None,
) -> McpConfigValidationResult:
    resolved_scope: McpInstallScope = (
        scope
        if isinstance(scope, str) and scope in ("local", "project", "user")
        else parse_mcp_install_scope(str(scope) if scope else "local")
    )
    if payload is None:
        plan = plan_mcp_install(
            host=host,
            scope=resolved_scope,  # type: ignore[arg-type]
            fmt=fmt,
            env_file=env_file,
            out=out,
            cwd=cwd,
            home=home,
            server_command=default_mcp_server_command(),
            tool_policy=tool_policy,
        )
        payload = plan.payload
        source: McpConfigSource = "generated"
        resolved_path = config_path or plan.config_path
    else:
        source = "file"
        resolved_path = config_path
    return validate_mcp_host_config(
        host=host,
        fmt=fmt,
        payload=payload,
        cwd=cwd,
        expected_env_file=env_file,
        source=source,
        config_path=resolved_path,
    )
