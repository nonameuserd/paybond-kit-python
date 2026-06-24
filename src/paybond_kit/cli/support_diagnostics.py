from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any

from paybond_kit.cli.core import CliContext, config_file_path, describe_credential_source
from paybond_kit.cli.doctor_agent import package_version
from paybond_kit.mcp_server import _mcp_tool_selection_metadata


class _ToolAnnotations:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


def _resolved_env_file_path(ctx: CliContext) -> str:
    env_file = ctx.globals.env_file
    path = Path(env_file)
    if path.is_absolute():
        return str(path.resolve())
    return str((ctx.cwd / env_file).resolve())


def _mcp_tool_count() -> int:
    return len(_mcp_tool_selection_metadata(_ToolAnnotations))


def build_support_diagnostics(ctx: CliContext) -> dict[str, Any]:
    return {
        "package_name": "paybond-kit",
        "package_version": package_version(),
        "runtime": f"python {sys.version.split()[0]}",
        "platform": {
            "os": sys.platform,
            "arch": platform.machine(),
        },
        "config_path": str(config_file_path()),
        "env_file_path": _resolved_env_file_path(ctx),
        "gateway_url": ctx.globals.gateway,
        "request_id": ctx.globals.request_id,
        "mcp_tool_count": _mcp_tool_count(),
        "credential_source": describe_credential_source(ctx.globals, ctx.cwd),
    }


def format_support_diagnostics_table(diagnostics: dict[str, Any]) -> list[str]:
    credential = diagnostics.get("credential_source", {})
    platform_info = diagnostics.get("platform", {})
    lines = [
        f"package: {diagnostics['package_name']} {diagnostics['package_version']}",
        f"runtime: {diagnostics['runtime']}",
        f"platform: {platform_info.get('os', '')} {platform_info.get('arch', '')}".strip(),
        f"config_path: {diagnostics['config_path']}",
        f"env_file_path: {diagnostics['env_file_path']}",
        f"gateway_url: {diagnostics['gateway_url']}",
        f"request_id: {diagnostics['request_id']}",
        f"mcp_tool_count: {diagnostics['mcp_tool_count']}",
        f"credential_source: {credential}",
    ]
    profile = credential.get("profile") if isinstance(credential, dict) else None
    if profile:
        lines.append(f"profile: {profile}")
    return lines
