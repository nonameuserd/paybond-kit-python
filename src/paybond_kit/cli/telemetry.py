"""Opt-out CLI adoption telemetry for local dev commands."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx

from paybond_kit.cli.core import CliContext, load_config_file, save_config_file
from paybond_kit.cli.doctor_agent import package_version
from paybond_kit.credentials import is_local_gateway_host

INSTALL_ID_HASH_PREFIX = "paybond-kit-cli:"
CliTelemetryCommand = str


def _telemetry_env_disabled() -> bool:
    raw = os.environ.get("PAYBOND_TELEMETRY", "").strip().lower()
    return raw in {"0", "false", "off", "no"}


def _telemetry_env_forced() -> bool:
    raw = os.environ.get("PAYBOND_TELEMETRY", "").strip().lower()
    return raw in {"1", "true", "on", "yes"}


def _is_ci_environment() -> bool:
    return os.environ.get("CI", "").strip().lower() in {"true", "1"}


def _is_local_gateway(gateway: str) -> bool:
    try:
        hostname = urlparse(gateway).hostname or ""
    except Exception:
        return True
    return is_local_gateway_host(hostname)


def hash_cli_install_id(install_id: str) -> str:
    digest = hashlib.sha256(f"{INSTALL_ID_HASH_PREFIX}{install_id}".encode("utf-8")).hexdigest()
    return digest


def resolve_cli_install_id() -> str:
    config = load_config_file()
    existing = str(config.get("install_id", "")).strip()
    if existing:
        return existing
    install_id = str(uuid.uuid4())
    config["install_id"] = install_id
    save_config_file(config)
    return install_id


def cli_telemetry_enabled(gateway: str) -> bool:
    if _telemetry_env_disabled() or _is_ci_environment():
        return False
    if _telemetry_env_forced():
        return True
    config = load_config_file()
    if config.get("telemetry") is False:
        return False
    return not _is_local_gateway(gateway)


async def report_cli_command_success(
    ctx: CliContext,
    *,
    command_path: CliTelemetryCommand,
    offline: bool,
) -> None:
    if not cli_telemetry_enabled(ctx.globals.gateway):
        return

    install_id = resolve_cli_install_id()
    body: dict[str, Any] = {
        "command_path": command_path,
        "success": True,
        "offline": offline,
        "kit_version": package_version(),
        "runtime": "python",
        "install_id_sha256": hash_cli_install_id(install_id),
        "os_name": platform.system().lower(),
        "client_context": {"format": ctx.globals.format},
    }
    url = f"{ctx.globals.gateway.rstrip('/')}/v1/public/analytics/kit-cli"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(url, json=body, headers={"content-type": "application/json"})
    except Exception:
        # Telemetry must never block or fail the CLI command.
        return


async def schedule_cli_command_telemetry(
    ctx: CliContext,
    *,
    command_path: CliTelemetryCommand,
    offline: bool,
) -> None:
    await report_cli_command_success(ctx, command_path=command_path, offline=offline)
