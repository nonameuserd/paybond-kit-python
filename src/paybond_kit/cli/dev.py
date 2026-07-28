"""paybond dev subcommands."""

from __future__ import annotations

import asyncio
import os
import signal
import threading
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from paybond_kit.cli.agent import handle_agent_sandbox_smoke
from paybond_kit.cli.commands import handle_login
from paybond_kit.cli.core import (
    CliContext,
    CliError,
    GlobalOptions,
    consume_boolean_flag,
    consume_flag,
    describe_credential_source,
    read_env_file_value,
)
from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.policy import handle_policy_init, handle_policy_validate_tools
from paybond_kit.cli.telemetry import schedule_cli_command_telemetry
from paybond_kit.dev.offline_gateway import is_production_api_key, offline_dev_http_context
from paybond_kit.dev.trace_buffer import (
    DEV_DEFAULT_POLICY_FILE,
    DEV_DEFAULT_PRESET,
    activate_dev_trace_collector,
    append_dev_audit_log,
    build_dev_startup_banner_lines,
    dev_trace_url,
    finalize_dev_trace_collector,
    record_smoke_trace_event,
)
from paybond_kit.dev.trace_server import start_dev_trace_server
from paybond_kit.dev.wiremock_up import run_dev_wiremock_up
from paybond_kit.solution_catalog import get_solution_smoke_defaults


def _dev_cli_error(
    message: str,
    *,
    code: str,
    category: str = "validation",
    details: dict[str, Any] | None = None,
) -> CliError:
    return CliError(message, category=category, code=code, details=details or {})


def _append_dev_loop_trace_line(
    checklist_lines: list[str],
    trace_url: str,
    globals_: GlobalOptions,
) -> list[str]:
    use_color = should_use_color(globals_)
    return [*checklist_lines, colorize(f"✓ Trace → {trace_url}", "green", use_color)]


def _write_dev_startup_banner(ctx: CliContext) -> None:
    for line in build_dev_startup_banner_lines():
        ctx.stderr.write(f"{line}\n")


def _reject_offline_with_production_key(api_key: str | None) -> None:
    trimmed = (api_key or "").strip()
    if trimmed and is_production_api_key(trimmed):
        raise _dev_cli_error(
            "offline dev mode cannot be used with production API keys (paybond_sk_live_...); "
            "unset PAYBOND_API_KEY or use a sandbox key",
            code="cli.dev.offline_production_key",
        )


def _assert_offline_dev_credentials_safe(ctx: CliContext) -> None:
    from_process = os.environ.get("PAYBOND_API_KEY", "").strip()
    _reject_offline_with_production_key(from_process or None)
    if from_process:
        return
    env_file = ctx.globals.env_file
    env_path = Path(env_file) if Path(env_file).is_absolute() else Path(ctx.cwd) / env_file
    try:
        body = env_path.read_text(encoding="utf-8")
    except OSError:
        body = ""
    _reject_offline_with_production_key(read_env_file_value(body, "PAYBOND_API_KEY"))


async def _finalize_smoke_result(
    ctx: CliContext,
    preset: str,
    smoke_data: dict[str, Any],
    *,
    offline: bool = False,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    bind = dict(smoke_data.get("bind") or {})
    execute = dict(smoke_data.get("execute") or {})
    defaults = get_solution_smoke_defaults(preset)
    tool_result = execute.get("tool_result")
    if isinstance(tool_result, dict):
        result_body = dict(tool_result)
    else:
        result_body = dict(defaults["result_body"])
    trace_event = finalize_dev_trace_collector(result_body, Path(ctx.cwd)) or record_smoke_trace_event(
        preset=preset,
        bind=bind,
        execute=execute,
        result_body=result_body,
        cwd=ctx.cwd,
    )
    audit_log = append_dev_audit_log(
        Path(ctx.cwd),
        {
            "kind": "dev.smoke",
            "recorded_at": trace_event["recorded_at"],
            "preset": preset,
            "bind": bind,
            "execute": execute,
            "offline": offline,
        },
    )
    trace_url = f"{dev_trace_url()}/runs/{trace_event['id']}"
    return {
        **smoke_data,
        "offline": offline,
        "trace_url": trace_url,
        "audit_log": audit_log,
        **({"warnings": warnings} if warnings else {}),
    }


async def _run_dev_smoke_core(ctx: CliContext, preset: str, *, offline: bool) -> dict[str, Any]:
    activate_dev_trace_collector(preset=preset, cwd=ctx.cwd)
    smoke_data = await handle_agent_sandbox_smoke(ctx, ["--preset", preset])
    return await _finalize_smoke_result(ctx, preset, smoke_data, offline=offline)


async def handle_dev_smoke(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    offline, argv = consume_boolean_flag(argv, "--offline")
    _, preset_value, argv = consume_flag(argv, "--preset")
    if argv:
        raise _dev_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    preset = (preset_value or "").strip() or DEV_DEFAULT_PRESET
    if offline:
        _assert_offline_dev_credentials_safe(ctx)
        with offline_dev_http_context():
            result = await _run_dev_smoke_core(ctx, preset, offline=True)
            await schedule_cli_command_telemetry(ctx, command_path="dev smoke", offline=True)
            return result
    result = await _run_dev_smoke_core(ctx, preset, offline=False)
    await schedule_cli_command_telemetry(ctx, command_path="dev smoke", offline=False)
    return result


async def handle_dev_trace(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    _, port_raw, argv = consume_flag(argv, "--port")
    if argv:
        raise _dev_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    port = int(port_raw) if port_raw else 9477
    if port <= 0 or port > 65535:
        raise _dev_cli_error("dev trace --port must be a valid TCP port", code="cli.usage.invalid_port", category="usage")

    credentials = describe_credential_source(ctx.globals, ctx.cwd)
    if credentials["source"] == "missing":
        ctx.stderr.write(
            "No PAYBOND_API_KEY configured. Run paybond dev smoke --offline or paybond login, then paybond dev smoke.\n"
        )

    server = start_dev_trace_server(
        port=port,
        cwd=ctx.cwd,
        env_file=ctx.globals.env_file,
        has_credentials=credentials["source"] != "missing",
    )
    trace_url = dev_trace_url(port)
    ctx.stderr.write(f"Paybond dev trace dashboard listening on {trace_url}\n")
    ctx.stderr.write("Press Ctrl+C to stop.\n")

    loop = asyncio.get_running_loop()
    shutdown_started = False

    def _shutdown_server() -> None:
        nonlocal shutdown_started
        if shutdown_started:
            return
        shutdown_started = True
        threading.Thread(target=server.shutdown, daemon=True).start()

    registered: list[signal.Signals] = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown_server)
            registered.append(sig)
        except (NotImplementedError, ValueError, RuntimeError):
            signal.signal(sig, lambda *_args, _sig=sig: _shutdown_server())

    try:
        await loop.run_in_executor(None, server.serve_forever)
    except asyncio.CancelledError:
        _shutdown_server()
        raise
    finally:
        for sig in registered:
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, ValueError, RuntimeError):
                pass
        server.server_close()

    ctx.stderr.write("Trace dashboard stopped.\n")
    return {"trace_url": trace_url, "port": str(port), "events": []}


async def handle_dev_up(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    down, argv = consume_boolean_flag(argv, "--down")
    _, port_raw, argv = consume_flag(argv, "--port")
    if argv:
        raise _dev_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    port = int(port_raw) if port_raw else None
    if port is not None and (port <= 0 or port > 65535):
        raise _dev_cli_error("dev up --port must be a valid TCP port", code="cli.usage.invalid_port", category="usage")

    try:
        result = run_dev_wiremock_up(port=port, down=down)
    except RuntimeError as exc:
        raise _dev_cli_error(str(exc), code="cli.dev.wiremock_failed") from exc

    if result["status"] == "stopped":
        ctx.stderr.write(f"Stopped WireMock container {result['container_name']}.\n")
    elif result["status"] == "already_running":
        ctx.stderr.write(f"WireMock already running at {result['gateway_url']}\n")
    else:
        ctx.stderr.write(f"WireMock Gateway listening at {result['gateway_url']}\n")
        ctx.stderr.write(f"Mappings loaded from {result['wiremock_dir']}\n")
    if result["next_commands"]:
        ctx.stderr.write("Next:\n")
        for command in result["next_commands"]:
            ctx.stderr.write(f"  {command}\n")
    return result


async def handle_dev_loop(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    offline, argv = consume_boolean_flag(argv, "--offline")
    _, policy_file, argv = consume_flag(argv, "--policy-file")
    no_login, argv = consume_boolean_flag(argv, "--no-login")
    if argv:
        raise _dev_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )

    policy_path = (policy_file or "").strip() or DEV_DEFAULT_POLICY_FILE
    steps: list[dict[str, Any]] = []
    banner_lines = build_dev_startup_banner_lines()

    _write_dev_startup_banner(ctx)

    if offline:
        _assert_offline_dev_credentials_safe(ctx)

    offline_context: AbstractContextManager[None] | None = offline_dev_http_context() if offline else None
    if offline_context is not None:
        offline_context.__enter__()

    try:
        if offline:
            steps.append(
                {
                    "name": "login",
                    "ok": True,
                    "skipped": True,
                    "message": "offline mode (no PAYBOND_API_KEY required)",
                }
            )
        else:
            credentials = describe_credential_source(ctx.globals, ctx.cwd)
            if credentials["source"] == "missing" and not no_login:
                login_data = await handle_login(ctx, [])
                steps.append({"name": "login", "ok": True, "data": login_data})
            else:
                steps.append(
                    {
                        "name": "login",
                        "ok": credentials["source"] != "missing",
                        "skipped": credentials["source"] != "missing",
                        "message": "missing credentials; run paybond login"
                        if credentials["source"] == "missing"
                        else "credentials present",
                    }
                )
                if credentials["source"] == "missing":
                    raise _dev_cli_error(
                        "dev loop requires sandbox credentials; run paybond login, pass --offline, or omit --no-login",
                        code="cli.dev.missing_credentials",
                        details={"steps": steps},
                    )

        init_data = handle_policy_init(
            ctx,
            ["--preset", DEV_DEFAULT_PRESET, "--out", policy_path, "--force"],
        )
        steps.append({"name": "policy_init", "ok": True, "data": init_data})

        validate_data = handle_policy_validate_tools(
            ctx,
            ["--file", policy_path, "--local-only"],
        )
        steps.append({"name": "validate_tools", "ok": validate_data.get("valid") is True, "data": validate_data})
        if validate_data.get("valid") is not True:
            raise _dev_cli_error(
                "dev loop failed policy validate-tools --local-only",
                code="cli.dev.validate_failed",
                details={"steps": steps},
            )

        smoke_data = await _run_dev_smoke_core(ctx, DEV_DEFAULT_PRESET, offline=offline)
        steps.append({"name": "smoke", "ok": True, "data": smoke_data})

        trace_url = str(smoke_data.get("trace_url") or dev_trace_url())
        audit_log = str(smoke_data.get("audit_log") or str(Path(ctx.cwd) / ".paybond/dev-audit.jsonl"))
        smoke_checklist = list(smoke_data.get("checklist_lines") or [])
        await schedule_cli_command_telemetry(ctx, command_path="dev loop", offline=offline)
        return {
            "offline": offline,
            "steps": steps,
            "smoke": smoke_data,
            "trace_url": trace_url,
            "audit_log": audit_log,
            "banner_lines": banner_lines,
            "checklist_lines": _append_dev_loop_trace_line(smoke_checklist, trace_url, ctx.globals),
        }
    finally:
        if offline_context is not None:
            offline_context.__exit__(None, None, None)


async def handle_dev(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "smoke":
        return await handle_dev_smoke(ctx, argv)
    if subcommand == "trace":
        return await handle_dev_trace(ctx, argv)
    if subcommand == "loop":
        return await handle_dev_loop(ctx, argv)
    if subcommand == "up":
        return await handle_dev_up(ctx, argv)
    raise _dev_cli_error(
        f"unknown dev subcommand: dev {subcommand}",
        code="cli.usage.unknown_command",
        category="usage",
    )
