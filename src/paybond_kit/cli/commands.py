from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from paybond_kit.cli.automation import (
    build_list_query_params,
    extract_next_cursor,
    partial_results_warning,
    write_atomic_file,
)
from paybond_kit.cli.audit_export import audit_verify_result
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
from paybond_kit.cli.support_diagnostics import build_support_diagnostics, format_support_diagnostics_table
from paybond_kit.init import run_init_guardrail
from paybond_kit.login import LoginOptions, LoginResult, PaybondLoginError, parse_args as parse_login_args, run_login
from paybond_kit.mcp_server import _mcp_tool_selection_metadata


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


def handle_init_guardrail(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    code = run_init_guardrail(argv)
    if code != 0:
        raise CliError("init guardrail failed", category="validation", code="cli.init.failed", exit_code=code)
    _, out, _ = consume_flag(argv, "--out")
    _, framework, _ = consume_flag(argv, "--framework")
    _, preset, _ = consume_flag(argv, "--preset")
    return {
        "out": out or "paybond_paid_tool_guard.py",
        "preset": preset or "paid-tool-guard",
        "framework": framework or "provider-agnostic",
        "bytes_written": True,
    }


def handle_mcp_serve(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] not in ("--help", "-h"):
        raise CliError(f"unexpected arguments: {' '.join(argv)}", code="cli.usage.unexpected_args")
    from paybond_kit.mcp_server import run_mcp_stdio

    ctx.stderr.write("Starting Paybond MCP stdio server (stdout is reserved for MCP JSON-RPC).\n")
    code = run_mcp_stdio([])
    if code != 0:
        raise CliError("mcp serve failed", category="internal", code="cli.mcp.serve_failed", exit_code=code)
    return {"started": True}


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
    from paybond_kit.mcp_policy import merge_mcp_tool_policy, parse_mcp_tool_allowlist, parse_mcp_tool_policy

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
        tool_policy=tool_policy if tool_policy.policy else None,
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


def handle_doctor(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
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


def handle_intents(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
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
        payload, _ = resolve_json_body(
            argv,
            stdin=ctx.stdin,
            missing_message="intents create requires --body <json-file> or --stdin",
        )
        return _redact_intent_response(gateway_request(ctx, "POST", "/harbor/intents", payload))
    if not intent_id:
        raise CliError(f"intents {subcommand} requires <intent_id>", code="cli.usage.missing_intent_id")
    if subcommand == "fund":
        payload, _ = resolve_json_body(argv, stdin=ctx.stdin, required=False)
        return _redact_intent_response(gateway_request(ctx, "POST", f"/harbor/intents/{intent_id}/fund", payload))
    if subcommand == "evidence":
        payload, _ = resolve_json_body(
            argv,
            stdin=ctx.stdin,
            missing_message="intents evidence requires --body <json-file> or --stdin",
        )
        return _redact_intent_response(gateway_request(ctx, "POST", f"/harbor/intents/{intent_id}/evidence", payload))
    if subcommand == "settlement-confirm":
        payload, _ = resolve_json_body(argv, stdin=ctx.stdin, required=False)
        return _redact_intent_response(
            gateway_request(ctx, "POST", f"/harbor/intents/{intent_id}/settlement/confirm", payload)
        )
    raise CliError(f"unknown intents subcommand: {subcommand}", code="cli.usage.unknown_command")


def handle_guardrails(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "bootstrap":
        _, operation, rest = consume_flag(argv, "--operation")
        _, spend, _ = consume_flag(rest, "--requested-spend-cents")
        if not operation or not spend:
            raise CliError("guardrails bootstrap requires --operation and --requested-spend-cents", code="cli.usage.missing_args")
        spend_cents = parse_required_non_negative_int(spend, field="--requested-spend-cents")
        body = gateway_request(
            ctx,
            "POST",
            "/v1/sandbox/guardrails/bootstrap",
            {"operation": operation, "requested_spend_cents": spend_cents},
        )
        return {
            "tenant_id": str(body.get("tenant_id", "")),
            "intent_id": str(body.get("intent_id", "")),
            "capability_token": str(body.get("capability_token", "")),
            "operation": str(body.get("operation", operation)),
            "requested_spend_cents": int(body.get("requested_spend_cents", spend_cents)),
            "sandbox_lifecycle_status": str(body.get("sandbox_lifecycle_status", "")),
        }
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
    principal = gateway_request(ctx, "GET", "/v1/auth/principal")
    tenant_id = str(principal.get("tenant_id", ""))
    if subcommand == "portfolio":
        return gateway_request(ctx, "GET", f"/signal/v1/tenants/{tenant_id}/portfolio/summary")
    _, did, _ = consume_flag(argv, "--did")
    if not did:
        raise CliError(f"signal {subcommand} requires --did", code="cli.usage.missing_did")
    if subcommand == "reputation":
        return gateway_request(ctx, "GET", f"/signal/v1/tenants/{quote(tenant_id, safe='')}/reputation/{quote(did, safe='')}")
    if subcommand == "fraud":
        return gateway_request(ctx, "GET", f"/fraud/v1/tenants/{quote(tenant_id, safe='')}/assessments/{quote(did, safe='')}")
    raise CliError(f"unknown signal subcommand: {subcommand}", code="cli.usage.unknown_command")


def handle_receipts(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    receipt_id = argv[0] if argv else ""
    if not receipt_id:
        raise CliError(f"receipts {subcommand} requires <receipt_id>", code="cli.usage.missing_receipt_id")
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
        return gateway_request(ctx, "POST", "/protocol/v2/mandates/import", payload)
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


def _read_manifest_from_bundle(path: str, cwd: Path) -> str:
    if path.endswith(".zip"):
        result = subprocess.run(["unzip", "-p", path, "manifest.json"], cwd=str(cwd), capture_output=True, text=True, check=False)
        if result.returncode != 0 or not result.stdout.strip():
            raise CliError(result.stderr.strip() or "unable to read manifest.json from ZIP bundle", category="validation", code="cli.audit.bundle_read_failed")
        return result.stdout
    manifest_path = Path(path)
    if manifest_path.name != "manifest.json":
        manifest_path = manifest_path / "manifest.json"
    return manifest_path.read_text(encoding="utf-8")


def handle_audit_exports(ctx: CliContext, subcommand: str, argv: list[str]) -> dict[str, Any]:
    if subcommand == "verify":
        path = argv[0] if argv else ""
        if not path:
            raise CliError("audit exports verify requires <path>", code="cli.usage.missing_path")
        manifest_raw = _read_manifest_from_bundle(path, ctx.cwd)
        manifest = json.loads(manifest_raw)
        if not isinstance(manifest, dict):
            raise CliError("manifest.json must be a JSON object", category="validation", code="cli.audit.invalid_manifest")
        return audit_verify_result(manifest, path=path)
    if subcommand == "list":
        _, limit, rest = consume_flag(argv, "--limit")
        _, cursor, _ = consume_flag(rest, "--cursor")
        params = build_list_query_params(limit, cursor, default_limit="50")
        body = gateway_request(ctx, "GET", f"/v1/compliance/audit-exports?{params}")
        exports = body.get("jobs") or body.get("items") or body.get("exports") or []
        result: dict[str, Any] = {
            "exports": [
                {
                    "job_id": str(item.get("job_id") or item.get("id") or ""),
                    "status": str(item.get("status", "")),
                    "created_at": str(item.get("created_at", "")),
                    "expires_at": item.get("expires_at"),
                    "scope": item.get("scope"),
                }
                for item in exports
                if isinstance(item, dict)
            ]
        }
        next_cursor = extract_next_cursor(body)
        if next_cursor:
            result["next_cursor"] = next_cursor
        return result
    job_id = argv[0] if argv else ""
    if not job_id:
        raise CliError(f"audit exports {subcommand} requires <job_id>", code="cli.usage.missing_job_id")
    if subcommand == "get":
        issue_download = "--issue-download" in argv
        _, output_path, _ = consume_flag(argv[1:], "--output")
        query = "?issue_download=1" if issue_download else ""
        body = gateway_request(ctx, "GET", f"/v1/compliance/audit-exports/{job_id}{query}")
        if output_path:
            job = body.get("job", body)
            if not isinstance(job, dict):
                raise CliError("audit exports get --output requires a ready export with --issue-download", category="validation", code="cli.audit.missing_download_token")
            token = str(job.get("download_token", ""))
            if not token:
                raise CliError("audit exports get --output requires a ready export with --issue-download", category="validation", code="cli.audit.missing_download_token")
            api_key = resolve_api_key(ctx.globals, ctx.cwd)
            url = gateway_url(ctx.globals.gateway, f"/v1/compliance/audit-exports/{job_id}/bundle?token={token}")
            client = ctx.client or httpx.Client(timeout=30.0)
            owns_client = ctx.client is None
            try:
                response = client.get(url, headers={"authorization": f"Bearer {api_key}", "x-request-id": ctx.globals.request_id})
                response.raise_for_status()
                content = response.content
                write_atomic_file(output_path, content, mode=0o600)
            finally:
                if owns_client:
                    client.close()
            return {"job_id": job_id, "output": output_path, "bytes_written": len(content)}
        return body
    if subcommand == "delete":
        require_confirmation(ctx.globals, "delete audit export job")
        gateway_request(ctx, "DELETE", f"/v1/compliance/audit-exports/{job_id}")
        return {"job_id": job_id, "deleted": True}
    raise CliError(f"unknown audit exports subcommand: {subcommand}", code="cli.usage.unknown_command")
