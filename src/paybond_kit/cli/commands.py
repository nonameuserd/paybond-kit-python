from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, IO
from urllib.parse import quote

import httpx

from paybond_kit.cli.automation import (
    build_list_query_params,
    extract_next_cursor,
    partial_results_warning,
    write_atomic_file,
)
from paybond_kit.audit.exports import PaybondAuditExports
from paybond_kit.audit.verify import verify_audit_bundle_local
from paybond_kit.cli.core import (
    CliContext,
    CliError,
    assert_api_key_shape,
    consume_boolean_flag,
    consume_flag,
    gateway_request,
    gateway_url,
    list_config_entries,
    mask_api_key,
    parse_optional_non_negative_int,
    parse_cli_argv,
    parse_required_non_negative_int,
    require_confirmation,
    resolve_api_key,
    resolve_config_value,
    set_config_value,
    unset_config_value,
)
from paybond_kit.cli.body import resolve_json_body
from paybond_kit.cli.redact import redact_config_value, redact_sensitive_fields
from paybond_kit.cli.doctor_agent import package_version, run_agent_mcp_checks
from paybond_kit.cli.doctor_agent_middleware import run_agent_middleware_doctor_check
from paybond_kit.cli.install_hints import run_install_context_doctor_checks
from paybond_kit.doctor_completion import run_completion_catalog_doctor_checks
from paybond_kit.cli.support_diagnostics import build_support_diagnostics, format_support_diagnostics_table
from paybond_kit.init import run_init_guardrail
from paybond_kit.project_init import (
    FRAMEWORK_ALIASES,
    ProjectInitFramework,
    ProjectInitLanguage,
    ProjectInitOptions,
    ProjectInitSolution,
    SOLUTION_ALIASES,
    parse_project_init_argv,
    run_project_init,
)
from paybond_kit.template_init import (
    CopyTemplateOptions,
    copy_template_to_directory,
    normalize_template_id,
    template_init_usage,
)
from paybond_kit.completion_catalog import list_completion_preset_ids
from paybond_kit.completion_init import scaffold_completion_init
from paybond_kit.login import LoginOptions, LoginResult, PaybondLoginError, parse_args as parse_login_args, run_login
from paybond_kit.mcp_server import _mcp_tool_selection_metadata


def _stdout_line_writer(stdout: IO[str]) -> Callable[[str], None]:
    def write(line: str) -> None:
        stdout.write(f"{line}\n")

    return write


class _ToolAnnotations:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


def _list_mcp_tools() -> list[dict[str, str]]:
    metadata = _mcp_tool_selection_metadata(_ToolAnnotations)
    return [
        {
            "name": name,
            "title": str(meta.get("title", name)),
            "description": str(meta.get("description", "")),
        }
        for name, meta in metadata.items()
    ]


def _login_result_data(result: LoginResult) -> dict[str, Any]:
    data: dict[str, Any] = {
        "env_file": str(result.env_path),
        "key_masked": result.key_masked,
        "key_written": result.key_written,
        "environment": result.environment,
        "tenant_id": result.tenant_id,
        "tenant_uuid": result.tenant_uuid,
        "verification_uri": result.verification_uri,
        "user_code": result.user_code,
    }
    if result.expires_at:
        data["expires_at"] = result.expires_at
    return data


async def handle_login(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    try:
        options = parse_login_args(argv)
    except PaybondLoginError as exc:
        raise CliError(str(exc), category="validation", code="cli.login.rejected") from exc
    options = LoginOptions(
        env_file=ctx.globals.env_file,
        gateway=ctx.globals.gateway,
        environment=options.environment,
        no_open=ctx.globals.no_open,
        force=options.force,
    )
    try:
        result = await run_login(
            options,
            cwd=ctx.cwd,
            stdout=ctx.stdout,
            human_output=ctx.globals.format != "json",
        )
    except PaybondLoginError as exc:
        raise CliError(str(exc), category="validation", code="cli.login.failed") from exc
    return _login_result_data(result)


def handle_init_wizard(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    try:
        args = parse_project_init_argv(argv)
    except SystemExit as exc:
        raise CliError("invalid init arguments", category="usage", code="cli.usage.invalid_init", exit_code=int(exc.code or 2)) from exc
    if args.help:
        raise CliError(template_init_usage(), category="usage", code="cli.help")
    if args.template:
        try:
            return copy_template_to_directory(
                CopyTemplateOptions(
                    cwd=ctx.cwd,
                    template_id=normalize_template_id(args.template),
                    framework=args.framework,
                    force=args.force,
                    write_stdout=(
                        _stdout_line_writer(ctx.stdout)
                        if ctx.globals.format != "json"
                        else None
                    ),
                )
            )
        except (RuntimeError, ValueError) as exc:
            raise CliError(str(exc), category="validation", code="cli.init.failed") from exc
    solution: ProjectInitSolution | None = None
    if args.solution:
        normalized = SOLUTION_ALIASES.get(args.solution.strip().lower())
        if not normalized:
            raise CliError(f"invalid --solution: {args.solution}", category="usage", code="cli.usage.invalid_init")
        solution = normalized
    framework: ProjectInitFramework | None = None
    if args.framework:
        normalized = FRAMEWORK_ALIASES.get(args.framework.strip().lower())
        if not normalized:
            raise CliError(f"invalid --framework: {args.framework}", category="usage", code="cli.usage.invalid_init")
        framework = normalized
    language: ProjectInitLanguage | None = None
    if args.language:
        value = args.language.strip().lower()
        if value in {"typescript", "ts"}:
            language = "typescript"
        elif value in {"python", "py"}:
            language = "python"
        else:
            raise CliError(f"invalid --language: {args.language}", category="usage", code="cli.usage.invalid_init")
    try:
        return run_project_init(
            ProjectInitOptions(
                cwd=ctx.cwd,
                solution=solution,
                max_spend_usd=args.max_spend_usd,
                framework=framework,
                language=language,
                non_interactive=args.non_interactive,
                force=args.force,
                write_stdout=(
                    _stdout_line_writer(ctx.stdout)
                    if ctx.globals.format != "json"
                    else None
                ),
            )
        )
    except RuntimeError as exc:
        raise CliError(str(exc), category="validation", code="cli.init.failed") from exc


def handle_init_guardrail(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    return _handle_init_scaffold(argv, "paid-tool-guard", "paybond_paid_tool_guard.py")


def handle_init_agent_middleware(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    return _handle_init_scaffold(
        ["--preset", "agent-middleware", *argv],
        "agent-middleware",
        "paybond_agent_middleware.py",
    )


def _handle_init_scaffold(argv: list[str], default_preset: str, default_out: str) -> dict[str, Any]:
    code = run_init_guardrail(argv)
    if code != 0:
        raise CliError(f"init {default_preset} failed", category="validation", code="cli.init.failed", exit_code=code)
    _, out, _ = consume_flag(argv, "--out")
    _, framework, _ = consume_flag(argv, "--framework")
    _, preset, _ = consume_flag(argv, "--preset")
    resolved_preset = preset or default_preset
    default_framework = "generic" if resolved_preset == "agent-middleware" else "provider-agnostic"
    return {
        "out": out or default_out,
        "preset": resolved_preset,
        "framework": framework or default_framework,
        "bytes_written": True,
        "completion_preset": "cost_and_completion",
    }


def handle_init_completion(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    presets = list_completion_preset_ids()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--preset", choices=presets)
    parser.add_argument("--out", default="")
    parser.add_argument("--force", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        raise CliError("invalid init completion arguments", category="usage", code="cli.usage.invalid_init_completion", exit_code=int(exc.code or 2)) from exc
    if not args.preset:
        raise CliError("missing --preset", category="usage", code="cli.usage.missing_args")
    out = Path(args.out or f"paybond_completion_{args.preset}.py")
    try:
        scaffold_completion_init(preset_id=args.preset, out=out, force=args.force)
    except FileExistsError as exc:
        raise CliError(str(exc), category="validation", code="cli.init.failed") from exc
    return {
        "out": str(out),
        "preset": args.preset,
        "bytes_written": True,
    }


def mcp_serve_argv_matches(argv: list[str]) -> bool:
    """Return True when argv resolves to ``mcp serve`` (after global flags)."""

    try:
        _, command = parse_cli_argv(argv)
    except CliError:
        return False
    return len(command) >= 2 and command[0] == "mcp" and command[1] == "serve"


def run_mcp_serve_command_sync(
    argv: list[str],
    *,
    stdout: IO[str],
    stderr: IO[str],
) -> int:
    """Run the blocking MCP stdio server. Must not run inside asyncio.run()."""

    from paybond_kit.cli.help_text import help_for_command
    from paybond_kit.mcp_server import run_mcp_stdio

    try:
        _, command = parse_cli_argv(argv)
    except CliError as exc:
        stderr.write(f"{exc.message}\n")
        return exc.exit_code

    help_parts = [part for part in command if part not in ("--help", "-h")]
    if not command or "--help" in command or "-h" in command:
        stdout.write(f"{help_for_command(' '.join(help_parts) or 'mcp serve')}\n")
        return 0

    rest = command[2:]
    if rest and rest[0] not in ("--help", "-h"):
        stderr.write(f"unexpected arguments: {' '.join(rest)}\n")
        return 2

    stderr.write("Starting Paybond MCP stdio server (stdout is reserved for MCP JSON-RPC).\n")
    return run_mcp_stdio([])


def handle_mcp_serve(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    raise CliError(
        "mcp serve must run via the sync CLI entrypoint (not the async dispatcher)",
        category="internal",
        code="cli.mcp.serve_async_forbidden",
    )


def handle_mcp_tools(ctx: CliContext) -> dict[str, Any]:
    return {"tools": _list_mcp_tools()}


def handle_mcp_install(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    from pathlib import Path

    from paybond_kit.cli.mcp_install import (
        parse_mcp_install_format,
        parse_mcp_install_host,
        parse_mcp_install_scope,
        plan_mcp_install,
    )
    from paybond_kit.mcp_policy import merge_mcp_tool_policy, parse_mcp_tool_allowlist, parse_mcp_tool_policy, resolve_mcp_tool_policy

    _, host, rest = consume_flag(argv, "--host")
    _, fmt, rest = consume_flag(rest, "--format")
    _, scope, rest = consume_flag(rest, "--scope")
    _, out, rest = consume_flag(rest, "--out")
    _, env_file, rest = consume_flag(rest, "--env-file")
    _, tool_policy_raw, rest = consume_flag(rest, "--tool-policy")
    _, tool_allowlist_raw, _ = consume_flag(rest, "--tool-allowlist")
    try:
        install_host = parse_mcp_install_host(host)
        install_format = parse_mcp_install_format(fmt, host=install_host)
        install_scope = parse_mcp_install_scope(scope)
        tool_policy = merge_mcp_tool_policy(
            parse_mcp_tool_policy(tool_policy_raw),
            allowlist=parse_mcp_tool_allowlist(tool_allowlist_raw) or None,
        )
    except ValueError as exc:
        raise CliError(str(exc), code="cli.usage.invalid_mcp_install") from exc
    plan = plan_mcp_install(
        host=install_host,
        scope=install_scope,
        fmt=install_format,
        env_file=env_file or ctx.globals.env_file,
        out=out,
        cwd=ctx.cwd,
        home=Path.home(),
        tool_policy=resolve_mcp_tool_policy(tool_policy),
    )
    if plan.printed:
        if ctx.globals.format != "json":
            ctx.stdout.write(plan.payload)
    else:
        config_path = Path(plan.config_path or "")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        from paybond_kit.cli.automation import write_atomic_file

        write_atomic_file(config_path, plan.payload, mode=0o600)
    result: dict[str, Any] = {
        "host": plan.host,
        "scope": plan.scope,
        "format": plan.format,
        "config_path": plan.config_path,
        "server_command": " ".join(plan.server_command),
        "printed": plan.printed,
    }
    if plan.tool_policy and plan.tool_policy.policy:
        result["tool_policy"] = plan.tool_policy.policy
        if plan.tool_policy.allowlist:
            result["tool_allowlist"] = list(plan.tool_policy.allowlist)
    if plan.printed and ctx.globals.format == "json":
        result["payload"] = plan.payload
    return result


def handle_mcp_verify_config(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    from pathlib import Path

    from paybond_kit.cli.mcp_install import default_mcp_install_format, parse_mcp_install_format, parse_mcp_install_host
    from paybond_kit.cli.mcp_verify_config import verify_mcp_install_plan

    _, host, rest = consume_flag(argv, "--host")
    _, fmt, rest = consume_flag(rest, "--format")
    _, env_file, rest = consume_flag(rest, "--env-file")
    _, config_path, _ = consume_flag(rest, "--config")
    try:
        install_host = parse_mcp_install_host(host)
        install_format = parse_mcp_install_format(fmt, host=install_host) if fmt else default_mcp_install_format(install_host)
    except ValueError as exc:
        raise CliError(str(exc), code="cli.usage.invalid_mcp_verify_config") from exc

    payload = None
    if config_path:
        payload = Path(config_path).read_text(encoding="utf-8")
    result = verify_mcp_install_plan(
        host=install_host,
        scope="local",
        fmt=install_format,
        env_file=env_file or ctx.globals.env_file,
        cwd=ctx.cwd,
        home=Path.home(),
        config_path=config_path,
        payload=payload,
    )
    return {
        "ok": result.ok,
        "host": result.host,
        "source": result.source,
        "config_path": result.config_path,
        "message": result.message,
        "issues": [{"field": issue.field, "message": issue.message} for issue in result.issues],
        "tool_policy": result.tool_policy.policy if result.tool_policy and result.tool_policy.policy else None,
    }


async def handle_doctor(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    agent, rest = consume_boolean_flag(argv, "--agent")
    _, host, _ = consume_flag(rest, "--host")
    checks: list[dict[str, Any]] = [
        {"name": "runtime", "ok": True, "message": f"python {sys.version.split()[0]}"},
        {
            "name": "package",
            "ok": True,
            "message": "paybond-kit",
            "details": {"version": package_version()},
        },
    ]
    env_path = Path(ctx.globals.env_file) if Path(ctx.globals.env_file).is_absolute() else ctx.cwd / ctx.globals.env_file
    if env_path.is_file():
        checks.append({"name": "env_file", "ok": True, "message": str(env_path)})
    else:
        checks.append({"name": "env_file", "ok": False, "message": f"env file not found: {env_path}"})

    api_key = ""
    try:
        api_key = resolve_api_key(ctx.globals, ctx.cwd)
        assert_api_key_shape(api_key)
        checks.append({"name": "key_shape", "ok": True, "message": mask_api_key(api_key)})
    except CliError as exc:
        checks.append({"name": "key_shape", "ok": False, "message": exc.message})

    if api_key:
        try:
            gateway_request(ctx, "GET", "/v1/auth/principal")
            checks.append({"name": "principal", "ok": True, "message": "principal lookup succeeded"})
        except CliError as exc:
            checks.append({"name": "principal", "ok": False, "message": exc.message})

    if agent:
        for item in run_install_context_doctor_checks():
            entry = {"name": item.name, "ok": item.ok, "message": item.message}
            if item.details:
                entry["details"] = item.details
            checks.append(entry)
        if not api_key:
            for name, message in (
                ("mcp_host_config", "skipped MCP probe (missing API key)"),
                ("mcp_env_resolution", "skipped MCP probe (missing API key)"),
                ("mcp_launch", "skipped MCP probe (missing API key)"),
                ("mcp_initialize", "skipped MCP probe (missing API key)"),
                ("mcp_tools_list", "skipped MCP probe (missing API key)"),
                ("mcp_tool_schemas", "skipped MCP probe (missing API key)"),
                ("mcp_stdout_purity", "skipped MCP probe (missing API key)"),
            ):
                checks.append({"name": name, "ok": False, "message": message})
        else:
            install_host = host or "generic"
            for item in run_agent_mcp_checks(
                env_file=ctx.globals.env_file,
                cwd=ctx.cwd,
                host=install_host,
            ):
                entry: dict[str, Any] = {"name": item.name, "ok": item.ok, "message": item.message}
                if item.details:
                    entry["details"] = item.details
                checks.append(entry)
        if api_key:
            smoke = await run_agent_middleware_doctor_check(ctx, api_key)
            entry = {"name": smoke.name, "ok": smoke.ok, "message": smoke.message}
            if smoke.details:
                entry["details"] = smoke.details
            checks.append(entry)
        else:
            checks.append(
                {
                    "name": "agent_middleware_smoke",
                    "ok": False,
                    "message": "skipped (missing API key)",
                }
            )

    gateway_get = None
    if api_key:
        gateway_get = lambda path: gateway_request(ctx, "GET", path)
    checks.extend(
        run_completion_catalog_doctor_checks(cwd=ctx.cwd, gateway_get=gateway_get)
    )

    summary = "pass" if all(item["ok"] for item in checks) else "fail"
    return {"checks": checks, "summary": summary}


def handle_config(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "list":
        return {"entries": list_config_entries(ctx.globals.profile)}
    if subcommand == "get":
        key = argv[0] if argv else ""
        if not key:
            raise CliError("config get requires <key>", code="cli.usage.missing_key")
        value = resolve_config_value(key, ctx.globals.profile)
        if value is None:
            raise CliError(f"config key not found: {key}", category="not_found", code="cli.config.not_found")
        return {"key": key, "value": redact_config_value(key, value)}
    if subcommand == "set":
        if len(argv) < 2:
            raise CliError("config set requires <key> <value>", code="cli.usage.missing_args")
        set_config_value(argv[0], argv[1], ctx.globals.profile)
        return {"key": argv[0], "set": True}
    if subcommand == "unset":
        key = argv[0] if argv else ""
        if not key:
            raise CliError("config unset requires <key>", code="cli.usage.missing_key")
        return {"key": key, "removed": unset_config_value(key, ctx.globals.profile)}
    raise CliError(f"unknown config subcommand: {subcommand}", code="cli.usage.unknown_command")


def handle_whoami(ctx: CliContext) -> dict[str, Any]:
    principal = gateway_request(ctx, "GET", "/v1/auth/principal")
    stripped = dict(principal)
    stripped.pop("access_token", None)
    stripped.pop("refresh_token", None)
    return {
        "tenant_id": str(principal.get("tenant_id", "")),
        "tenant_uuid": str(principal.get("tenant_uuid", "")),
        "environment": str(principal.get("environment", "")),
        "service_account_role": str(principal.get("service_account_role", "")),
        "principal": stripped,
    }


def handle_version(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    verbose, rest = consume_boolean_flag(argv, "--verbose")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    if verbose:
        return build_support_diagnostics(ctx)
    return {"version": package_version()}


def handle_diagnose(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    redacted, rest = consume_boolean_flag(argv, "--redacted")
    if rest:
        raise CliError(f"unexpected arguments: {' '.join(rest)}", code="cli.usage.unexpected_args")
    if not redacted:
        raise CliError(
            "paybond diagnose requires --redacted for support bundles",
            code="cli.diagnose.redacted_required",
        )
    diagnostics = build_support_diagnostics(ctx)
    return {
        "redacted": True,
        "diagnostics": diagnostics,
        "lines": format_support_diagnostics_table(diagnostics),
    }


def handle_keys(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "list":
        _, limit, rest = consume_flag(argv, "--limit")
        _, cursor, _ = consume_flag(rest, "--cursor")
        params = build_list_query_params(limit, cursor, default_limit="50")
        body = gateway_request(ctx, "GET", f"/v1/admin/api-keys?{params}")
        keys = []
        for item in body.get("items", []):
            if not isinstance(item, dict):
                continue
            keys.append(
                {
                    "key_id": str(item.get("key_id") or item.get("id") or ""),
                    "key_masked": mask_api_key(f"paybond_sk_{item.get('environment', 'sandbox')}_{item.get('key_id', 'redacted')}_redacted"),
                    "role": str(item.get("service_account_role", "")),
                    "created_at": str(item.get("created_at", "")),
                    "expires_at": item.get("expires_at"),
                    "status": "revoked" if item.get("revoked_at") else "active",
                }
            )
        result: dict[str, Any] = {"keys": keys}
        next_cursor = extract_next_cursor(body)
        if next_cursor:
            result["next_cursor"] = next_cursor
        return result
    if subcommand == "create":
        _, name, rest = consume_flag(argv, "--name")
        _, role, rest = consume_flag(rest, "--role")
        _, label, _ = consume_flag(rest, "--label")
        if not name or not role:
            raise CliError("keys create requires --name and --role", code="cli.usage.missing_args")
        body = gateway_request(
            ctx,
            "POST",
            "/v1/admin/api-keys",
            {"service_account_name": name, "service_account_role": role, "label": label or ""},
        )
        item = body.get("item", {})
        raw_api_key = str(body.get("api_key", "")) if body.get("api_key") else ""
        created: dict[str, Any] = {
            "key_id": str(item.get("key_id") or item.get("id") or ""),
            "key_masked": mask_api_key(raw_api_key) if raw_api_key else mask_api_key(""),
            "role": str(item.get("service_account_role", role)),
            "created_at": str(item.get("created_at", "")),
            "status": "active",
        }
        if raw_api_key:
            created["api_key"] = raw_api_key
        return created
    key_id = argv[0] if argv else ""
    if not key_id:
        raise CliError(f"keys {subcommand} requires <key_id>", code="cli.usage.missing_key_id")
    if subcommand == "rotate":
        require_confirmation(ctx.globals, "rotate API key")
        body = gateway_request(ctx, "POST", f"/v1/admin/api-keys/{quote(key_id, safe='')}/rotate")
        item = body.get("item", {})
        raw_api_key = str(body.get("api_key", "")) if body.get("api_key") else ""
        result = {
            "key_id": str(item.get("key_id") or key_id),
            "key_masked": mask_api_key(raw_api_key) if raw_api_key else mask_api_key(""),
            "rotated": True,
        }
        if raw_api_key:
            result["api_key"] = raw_api_key
        return result
    if subcommand == "revoke":
        require_confirmation(ctx.globals, "revoke API key")
        gateway_request(ctx, "DELETE", f"/v1/admin/api-keys/{key_id}")
        return {"key_id": key_id, "revoked": True}
    raise CliError(f"unknown keys subcommand: {subcommand}", code="cli.usage.unknown_command")


def _redact_intent_response(body: dict[str, Any]) -> dict[str, Any]:
    redacted = redact_sensitive_fields(body)
    return redacted if isinstance(redacted, dict) else body


async def _handle_intents_create(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    from paybond_kit.agent_recognition import sign_harbor_create_recognition_proof
    from paybond_kit.cli.agent_paybond import with_paybond_cli
    from paybond_kit.cli.intents_harbor_mutation import parse_harbor_mutation_flags, resolve_harbor_recognition

    flags = parse_harbor_mutation_flags(argv)
    payload, _ = resolve_json_body(
        flags.rest_argv,
        stdin=ctx.stdin,
        missing_message="intents create requires --body <json-file> or --stdin",
    )
    body = dict(payload or {})

    async def _run(paybond, _warnings: list[str]) -> dict[str, Any]:
        recognition = resolve_harbor_recognition(
            ctx,
            recognition_key_id=flags.recognition_key_id,
            recognition_seed_hex=flags.recognition_seed_hex,
        )
        tenant_id = paybond.harbor.tenant_id
        recognition_proof = sign_harbor_create_recognition_proof(
            tenant_id=tenant_id,
            intent_body=body,
            key_id=recognition["agent_recognition_key_id"],
            signing_seed=recognition["agent_recognition_signing_seed"],
        )
        result = await paybond.harbor.create_intent(
            body,
            recognition_proof=recognition_proof,
            idempotency_key=(flags.idempotency_key or "").strip() or None,
        )
        return _redact_intent_response(result)

    return await with_paybond_cli(ctx, _run)


async def _handle_intents_fund(
    ctx: CliContext,
    intent_id: str,
    argv: list[str],
) -> dict[str, Any]:
    from uuid import UUID

    from paybond_kit.agent_recognition import sign_harbor_fund_recognition_proof
    from paybond_kit.cli.agent_paybond import with_paybond_cli
    from paybond_kit.cli.intents_harbor_mutation import (
        DEPRECATED_INTENTS_FUND_BODY_WARNING,
        fund_body_shim_used,
        parse_harbor_mutation_flags,
        resolve_fund_payment_signature_from_body,
        resolve_harbor_recognition,
    )

    flags = parse_harbor_mutation_flags(argv)
    _, payment_signature, rest = consume_flag(flags.rest_argv, "--payment-signature")
    payment_signature = payment_signature.strip() if payment_signature else None
    body_shim_used = fund_body_shim_used(rest)
    payload, _ = resolve_json_body(rest, stdin=ctx.stdin, required=False)
    if body_shim_used:
        ctx.stderr.write(f"{DEPRECATED_INTENTS_FUND_BODY_WARNING}\n")
        if not payment_signature:
            payment_signature = resolve_fund_payment_signature_from_body(payload or {})

    async def _run(paybond, _warnings: list[str]) -> dict[str, Any]:
        recognition = resolve_harbor_recognition(
            ctx,
            recognition_key_id=flags.recognition_key_id,
            recognition_seed_hex=flags.recognition_seed_hex,
        )
        tenant_id = paybond.harbor.tenant_id
        recognition_proof = sign_harbor_fund_recognition_proof(
            tenant_id=tenant_id,
            intent_id=intent_id,
            key_id=recognition["agent_recognition_key_id"],
            signing_seed=recognition["agent_recognition_signing_seed"],
        )
        result = await paybond.harbor.fund_intent(
            UUID(intent_id),
            recognition_proof=recognition_proof,
            payment_signature=payment_signature,
            idempotency_key=(flags.idempotency_key or "").strip() or None,
        )
        return _redact_fund_intent_response(result)

    return await with_paybond_cli(ctx, _run)


def _redact_fund_intent_response(result: Any) -> dict[str, Any]:
    from dataclasses import asdict, is_dataclass

    if not is_dataclass(result) or isinstance(result, type):
        redacted = redact_sensitive_fields(result)
        return redacted if isinstance(redacted, dict) else {"value": redacted}
    payload = asdict(result)
    if "intent_id" in payload:
        payload["intent_id"] = str(payload["intent_id"])
    redacted = redact_sensitive_fields(payload)
    return redacted if isinstance(redacted, dict) else payload


async def _handle_intents_evidence(
    ctx: CliContext,
    intent_id: str,
    argv: list[str],
) -> dict[str, Any]:
    from uuid import UUID

    from paybond_kit.agent_recognition import sign_harbor_evidence_submit_recognition_proof
    from paybond_kit.cli.agent_paybond import with_paybond_cli
    from paybond_kit.cli.intents_harbor_mutation import parse_harbor_mutation_flags, resolve_harbor_recognition

    flags = parse_harbor_mutation_flags(argv)
    payload, _ = resolve_json_body(
        flags.rest_argv,
        stdin=ctx.stdin,
        missing_message="intents evidence requires --body <json-file> or --stdin",
    )
    body = dict(payload or {})

    async def _run(paybond, _warnings: list[str]) -> dict[str, Any]:
        recognition = resolve_harbor_recognition(
            ctx,
            recognition_key_id=flags.recognition_key_id,
            recognition_seed_hex=flags.recognition_seed_hex,
        )
        tenant_id = paybond.harbor.tenant_id
        recognition_proof = sign_harbor_evidence_submit_recognition_proof(
            tenant_id=tenant_id,
            intent_id=intent_id,
            evidence_body=body,
            key_id=recognition["agent_recognition_key_id"],
            signing_seed=recognition["agent_recognition_signing_seed"],
        )
        result = await paybond.harbor.submit_evidence(
            UUID(intent_id),
            body,
            recognition_proof=recognition_proof,
            idempotency_key=(flags.idempotency_key or "").strip() or None,
        )
        return _redact_intent_response(result)

    return await with_paybond_cli(ctx, _run)


async def _handle_intents_settlement_confirm(
    ctx: CliContext,
    intent_id: str,
    argv: list[str],
) -> dict[str, Any]:
    from paybond_kit.agent_recognition import sign_harbor_settlement_confirm_recognition_proof
    from paybond_kit.cli.agent_paybond import with_paybond_cli
    from paybond_kit.cli.intents_harbor_mutation import parse_harbor_mutation_flags, resolve_harbor_recognition

    flags = parse_harbor_mutation_flags(argv)
    payload, _ = resolve_json_body(flags.rest_argv, stdin=ctx.stdin, required=False)
    body = dict(payload or {})

    async def _run(paybond, _warnings: list[str]) -> dict[str, Any]:
        recognition = resolve_harbor_recognition(
            ctx,
            recognition_key_id=flags.recognition_key_id,
            recognition_seed_hex=flags.recognition_seed_hex,
        )
        tenant_id = paybond.harbor.tenant_id
        recognition_proof = sign_harbor_settlement_confirm_recognition_proof(
            tenant_id=tenant_id,
            intent_id=intent_id,
            body=body,
            key_id=recognition["agent_recognition_key_id"],
            signing_seed=recognition["agent_recognition_signing_seed"],
        )
        result = await paybond.intents.confirm_settlement(
            intent_id,
            body=body,
            recognition_proof=recognition_proof,
            idempotency_key=(flags.idempotency_key or "").strip() or None,
        )
        return _redact_intent_response(result)

    return await with_paybond_cli(ctx, _run)


async def handle_intents(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "list":
        _, status, rest = consume_flag(argv, "--status")
        _, limit, rest = consume_flag(rest, "--limit")
        _, cursor, _ = consume_flag(rest, "--cursor")
        params = build_list_query_params(limit, cursor)
        query = f"{params}&status={quote(status, safe='')}" if status else params
        body = gateway_request(ctx, "GET", f"/harbor/operator/v1/intents?{query}")
        redacted = _redact_intent_response(body)
        next_cursor = extract_next_cursor(redacted)
        if next_cursor and "next_cursor" not in redacted:
            redacted["next_cursor"] = next_cursor
        return redacted
    intent_id = argv[0] if argv else ""
    if subcommand == "get":
        if not intent_id:
            raise CliError("intents get requires <intent_id>", code="cli.usage.missing_intent_id")
        return _redact_intent_response(gateway_request(ctx, "GET", f"/harbor/operator/v1/intents/{intent_id}"))
    if subcommand == "create":
        return await _handle_intents_create(ctx, argv)
    if not intent_id:
        raise CliError(f"intents {subcommand} requires <intent_id>", code="cli.usage.missing_intent_id")
    if subcommand == "fund":
        return await _handle_intents_fund(ctx, intent_id, argv[1:])
    if subcommand == "evidence":
        return await _handle_intents_evidence(ctx, intent_id, argv[1:])
    if subcommand == "settlement-confirm":
        return await _handle_intents_settlement_confirm(ctx, intent_id, argv)
    raise CliError(f"unknown intents subcommand: {subcommand}", code="cli.usage.unknown_command")


def handle_guardrails(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "bootstrap":
        _, operation, rest = consume_flag(argv, "--operation")
        _, spend, rest = consume_flag(rest, "--requested-spend-cents")
        _, completion_preset, _ = consume_flag(rest, "--completion-preset")
        if not operation or not spend:
            raise CliError("guardrails bootstrap requires --operation and --requested-spend-cents", code="cli.usage.missing_args")
        spend_cents = parse_required_non_negative_int(spend, field="--requested-spend-cents")
        payload: dict[str, Any] = {"operation": operation, "requested_spend_cents": spend_cents}
        if completion_preset:
            payload["completion_preset"] = completion_preset
        body = gateway_request(
            ctx,
            "POST",
            "/v1/sandbox/guardrails/bootstrap",
            payload,
        )
        return _redact_intent_response(
            {
                "tenant_id": str(body.get("tenant_id", "")),
                "intent_id": str(body.get("intent_id", "")),
                "capability_token": str(body.get("capability_token", "")),
                "operation": str(body.get("operation", operation)),
                "requested_spend_cents": int(body.get("requested_spend_cents", spend_cents)),
                "sandbox_lifecycle_status": str(body.get("sandbox_lifecycle_status", "")),
            }
        )
    if subcommand == "evidence":
        _, intent_id, rest = consume_flag(argv, "--intent-id")
        if not intent_id:
            raise CliError("guardrails evidence requires --intent-id and --body <json-file>", code="cli.usage.missing_args")
        payload, _ = resolve_json_body(
            rest,
            stdin=ctx.stdin,
            missing_message="guardrails evidence requires --intent-id and --body <json-file> or --stdin",
        )
        return gateway_request(ctx, "POST", f"/v1/sandbox/guardrails/{intent_id}/evidence", payload)
    raise CliError(f"unknown guardrails subcommand: {subcommand}", code="cli.usage.unknown_command")


def handle_spend_authorize(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    _, intent_id, rest = consume_flag(argv, "--intent-id")
    _, token, rest = consume_flag(rest, "--token")
    _, operation, rest = consume_flag(rest, "--operation")
    _, spend, _ = consume_flag(rest, "--requested-spend-cents")
    if not intent_id or not token or not operation:
        raise CliError("spend authorize requires --intent-id, --token, and --operation", code="cli.usage.missing_args")
    spend_cents = parse_optional_non_negative_int(spend, field="--requested-spend-cents")
    body = gateway_request(
        ctx,
        "POST",
        "/verify",
        {
            "intent_id": intent_id,
            "token": token,
            "operation": operation,
            "requested_spend_cents": spend_cents,
        },
    )
    return {
        "authorized": bool(body.get("allow")),
        "intent_id": str(body.get("intent_id", intent_id)),
        "operation": operation,
        "requested_spend_cents": spend_cents,
        "deny_reason": None if body.get("allow") else str(body.get("message") or body.get("code") or "denied"),
    }


def handle_signal(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "portfolio":
        return gateway_request(ctx, "GET", "/signal/v1/portfolio/summary")
    _, did, _ = consume_flag(argv, "--did")
    if not did:
        raise CliError(f"signal {subcommand} requires --did", code="cli.usage.missing_did")
    if subcommand == "reputation":
        return gateway_request(ctx, "GET", f"/reputation/{quote(did, safe='')}")
    if subcommand == "fraud":
        return gateway_request(
            ctx,
            "GET",
            f"/signal/v1/operators/{quote(did, safe='')}/review-status",
        )
    raise CliError(f"unknown signal subcommand: {subcommand}", code="cli.usage.unknown_command")


def handle_receipts(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    receipt_id = argv[0] if argv else ""
    if not receipt_id:
        raise CliError(f"receipts {subcommand} requires <receipt_id>", code="cli.usage.missing_receipt_id")
    _, kind, rest = consume_flag(argv[1:], "--kind")
    receipt_kind = (kind or "protocol").strip().lower()
    if receipt_kind == "agent":
        if subcommand == "get":
            return gateway_request(ctx, "GET", f"/protocol/v2/agent-receipts/{receipt_id}")
        if subcommand == "verify":
            fetched = gateway_request(ctx, "GET", f"/protocol/v2/agent-receipts/{receipt_id}")
            return gateway_request(ctx, "POST", "/protocol/v2/agent-receipts/verify", fetched)
    if subcommand == "get":
        return gateway_request(ctx, "GET", f"/protocol/v2/receipts/{receipt_id}")
    if subcommand == "verify":
        return gateway_request(ctx, "POST", "/protocol/v2/receipts/verify", {"receipt_id": receipt_id})
    raise CliError(f"unknown receipts subcommand: {subcommand}", code="cli.usage.unknown_command")


def handle_mandates(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    payload, _ = resolve_json_body(
        argv,
        stdin=ctx.stdin,
        missing_message=f"mandates {subcommand} requires --body <json-file> or --stdin",
    )
    if subcommand == "verify":
        return gateway_request(ctx, "POST", "/protocol/v2/mandates/verify", payload)
    if subcommand == "import":
        return gateway_request(ctx, "POST", "/protocol/v2/mandates", payload)
    raise CliError(f"unknown mandates subcommand: {subcommand}", code="cli.usage.unknown_command")


def handle_a2a(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "card":
        return gateway_request(ctx, "GET", "/.well-known/agent-card.json")
    if subcommand == "contracts":
        _, contract_id, rest = consume_flag(argv, "--contract-id")
        if contract_id:
            return gateway_request(ctx, "GET", f"/protocol/v2/a2a/task-contracts/{contract_id}")
        _, limit, rest = consume_flag(rest, "--limit")
        _, cursor, _ = consume_flag(rest, "--cursor")
        params = build_list_query_params(limit, cursor)
        body = gateway_request(ctx, "GET", f"/protocol/v2/a2a/task-contracts?{params}")
        next_cursor = extract_next_cursor(body)
        if next_cursor and "next_cursor" not in body:
            body["next_cursor"] = next_cursor
        return body
    raise CliError(f"unknown a2a subcommand: {subcommand}", code="cli.usage.unknown_command")


def _cli_audit_exports_gateway(ctx: CliContext) -> PaybondAuditExports:
    class _Gateway:
        async def get_json(self, path: str) -> dict[str, Any]:
            return gateway_request(ctx, "GET", path)

        async def delete_json(self, path: str) -> dict[str, Any]:
            return gateway_request(ctx, "DELETE", path)

    return PaybondAuditExports.from_gateway(_Gateway())


def handle_audit_exports(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "verify":
        path = argv[0] if argv else ""
        if not path:
            raise CliError("audit exports verify requires <path>", code="cli.usage.missing_path")
        try:
            return verify_audit_bundle_local(path, ctx.cwd)
        except ValueError as exc:
            raise CliError(str(exc), category="validation", code="cli.audit.invalid_manifest") from exc
        except RuntimeError as exc:
            raise CliError(str(exc), category="validation", code="cli.audit.bundle_read_failed") from exc
    exports = _cli_audit_exports_gateway(ctx)
    if subcommand == "list":
        _, limit, rest = consume_flag(argv, "--limit")
        _, cursor, _ = consume_flag(rest, "--cursor")
        page = asyncio.run(
            exports.list(
                limit=int(limit) if limit else None,
                cursor=cursor,
            )
        )
        result: dict[str, Any] = {
            "exports": [
                {
                    "job_id": item.id,
                    "status": item.status,
                    "created_at": item.created_at,
                    "expires_at": item.expires_at,
                }
                for item in page.jobs
            ]
        }
        if page.next_cursor:
            result["next_cursor"] = page.next_cursor
        return result
    job_id = argv[0] if argv else ""
    if not job_id:
        raise CliError(f"audit exports {subcommand} requires <job_id>", code="cli.usage.missing_job_id")
    if subcommand == "get":
        issue_download = "--issue-download" in argv
        _, output_path, _ = consume_flag(argv[1:], "--output")
        body = asyncio.run(exports.get(job_id, issue_download=issue_download))
        if output_path:
            token = str(body.job.download_token or "")
            if not token:
                raise CliError("audit exports get --output requires a ready export with --issue-download", category="validation", code="cli.audit.missing_download_token")
            url = gateway_url(ctx.globals.gateway, f"/v1/compliance/audit-exports/{job_id}/bundle")
            client = ctx.client or httpx.Client(timeout=30.0)
            owns_client = ctx.client is None
            try:
                response = client.post(
                    url,
                    headers={
                        "authorization": f"Bearer {token}",
                        "x-request-id": ctx.globals.request_id,
                    },
                )
                response.raise_for_status()
                content = response.content
                write_atomic_file(output_path, content, mode=0o600)
            finally:
                if owns_client:
                    client.close()
            return {"job_id": job_id, "output": output_path, "bytes_written": len(content)}
        return {"job": body.job.__dict__}
    if subcommand == "delete":
        require_confirmation(ctx.globals, "delete audit export job")
        return asyncio.run(exports.delete(job_id))
    raise CliError(f"unknown audit exports subcommand: {subcommand}", code="cli.usage.unknown_command")
