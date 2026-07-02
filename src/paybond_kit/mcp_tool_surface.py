"""MCP host runner helper — stdio server config for coding-agent integrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal

from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.cli.mcp_install import (
    McpServerEntry,
    build_mcp_server_entry,
    default_mcp_server_command,
    serialize_mcp_install_payload,
)
from paybond_kit.mcp_policy import McpToolPolicyConfig

McpInstallFormat = Literal["json", "toml"]


@dataclass(frozen=True, slots=True)
class PaybondMcpToolSurface:
    """Stdio MCP host configuration derived from ``paybond mcp install`` patterns."""

    server_config: McpServerEntry
    install_payload: Callable[[McpInstallFormat], str]


def create_paybond_mcp_tool_surface(
    _run: PaybondAgentRun,
    *,
    env_file: str = ".env.local",
    server_command: list[str] | None = None,
    tool_policy: McpToolPolicyConfig | None = None,
) -> PaybondMcpToolSurface:
    """
    Framework runner helper for external MCP hosts (Claude Desktop, Codex, generic stdio).

    The bound :class:`PaybondAgentRun` establishes tenant/intent context for your app;
    the returned ``server_config`` is the stdio entry coding-agent hosts consume via
    ``PAYBOND_ENV_FILE`` (never raw API keys in host config files).
    """
    resolved_env_file = env_file.strip() or ".env.local"
    command = server_command if server_command is not None else default_mcp_server_command()
    server_config = build_mcp_server_entry(resolved_env_file, command, tool_policy=tool_policy)

    return PaybondMcpToolSurface(
        server_config=server_config,
        install_payload=lambda fmt="json": serialize_mcp_install_payload(fmt, server_config),
    )


__all__ = [
    "PaybondMcpToolSurface",
    "create_paybond_mcp_tool_surface",
]
