from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from paybond_kit.mcp_policy import McpToolPolicyConfig, mcp_tool_policy_env, resolve_mcp_tool_policy
from paybond_kit.mcp_scope_catalog import PaybondApiKeyKind, classify_paybond_api_key

McpInstallFormat = Literal["json", "toml"]
McpInstallScope = Literal["local", "project", "user"]
McpInstallHost = Literal["claude", "codex", "openai", "generic"]

MCP_INSTALL_HOSTS: tuple[McpInstallHost, ...] = ("claude", "codex", "openai", "generic")

RESTRICTED_KEY_TOOL_POLICY_ERROR = (
    "--tool-policy/--tool-allowlist are not supported for restricted paybond_rk_ keys: "
    "MCP tool scopes come from the key (paybond keys create --kind restricted --preset ...)"
)


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
    key_kind: PaybondApiKeyKind = "unknown"


def mcp_runtime_available() -> bool:
    """Return True when the optional MCP SDK dependency is importable in this environment."""

    try:
        import mcp.server.fastmcp  # noqa: F401
    except ImportError:
        return False
    return True


def _resolve_colocated_paybond_executable() -> str | None:
    candidate = Path(sys.executable).resolve().parent / "paybond"
    if candidate.is_file():
        return str(candidate)
    return shutil.which("paybond")


def resolve_package_local_mcp_server_command() -> list[str]:
    """Return the installed package's canonical stdio MCP server launch command."""

    paybond = _resolve_colocated_paybond_executable()
    if paybond:
        return [paybond, "mcp", "serve"]
    return [sys.executable, "-m", "paybond_kit.mcp_server"]


def default_mcp_server_command() -> list[str]:
    return resolve_package_local_mcp_server_command()


def assert_tool_policy_allowed_for_key_kind(
    key_kind: PaybondApiKeyKind,
    tool_policy_requested: bool,
) -> None:
    """Reject env tool-policy flags when the credential is a restricted key."""

    if key_kind == "restricted" and tool_policy_requested:
        raise ValueError(RESTRICTED_KEY_TOOL_POLICY_ERROR)


def _read_env_file_value(path: Path, key: str) -> str:
    try:
        body = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    prefix = f"{key}="
    export_prefix = f"export {key}="
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith(export_prefix):
            value = line[len(export_prefix) :].strip()
        elif line.startswith(prefix):
            value = line[len(prefix) :].strip()
        else:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        return value.strip()
    return ""


def detect_env_file_api_key_kind(env_file: str, cwd: Path) -> PaybondApiKeyKind:
    """Classify the credential a generated MCP host config will use at runtime."""

    import os

    candidate = Path(env_file)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    from_file = _read_env_file_value(candidate, "PAYBOND_API_KEY")
    if from_file:
        return classify_paybond_api_key(from_file)
    from_process = (os.environ.get("PAYBOND_API_KEY") or "").strip()
    return classify_paybond_api_key(from_process) if from_process else "unknown"


def build_mcp_server_entry(
    env_file: str,
    server_command: list[str],
    *,
    tool_policy: McpToolPolicyConfig | None = None,
    key_kind: PaybondApiKeyKind = "unknown",
) -> McpServerEntry:
    policy_env = (
        {}
        if key_kind == "restricted"
        else mcp_tool_policy_env(resolve_mcp_tool_policy(tool_policy or McpToolPolicyConfig()))
    )
    env = {"PAYBOND_ENV_FILE": env_file, **policy_env}
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
    key_kind: PaybondApiKeyKind | None = None,
) -> McpInstallPlan:
    command = server_command or default_mcp_server_command()
    resolved_kind = key_kind if key_kind is not None else detect_env_file_api_key_kind(env_file, cwd)
    entry = build_mcp_server_entry(
        env_file,
        command,
        tool_policy=tool_policy,
        key_kind=resolved_kind,
    )
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
        tool_policy=tool_policy if resolved_kind != "restricted" else None,
        key_kind=resolved_kind,
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
