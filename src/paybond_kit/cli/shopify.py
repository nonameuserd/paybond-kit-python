"""paybond shopify subcommands (Python parity)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from paybond_kit.cli.agent import handle_agent_sandbox_smoke
from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.core import (
    CliContext,
    CliError,
    GlobalOptions,
    consume_boolean_flag,
    consume_flag,
    gateway_request,
    resolve_api_key,
)
from paybond_kit.solution_catalog import get_solution_smoke_defaults


def _shopify_cli_error(
    message: str,
    *,
    code: str,
    category: str = "validation",
    details: dict[str, Any] | None = None,
) -> CliError:
    return CliError(message, category=category, code=code, details=details or {})


def _which_executable(name: str) -> str | None:
    return shutil.which(name)


def _read_shopify_app_toml(cwd: Path) -> dict[str, Any]:
    path = cwd / "shopify.app.toml"
    if not path.is_file():
        return {"exists": False}
    content = path.read_text(encoding="utf-8")
    client_id = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("client_id"):
            _, _, value = stripped.partition("=")
            client_id = value.strip().strip('"')
            break
    return {"exists": True, "client_id": client_id, "path": str(path)}


def _resolve_shop_domain(raw: str | None, cwd: Path) -> str | None:
    if raw and raw.strip():
        return raw.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
    from_env = os.environ.get("SHOPIFY_DEV_STORE", "").strip()
    if from_env:
        return from_env.removeprefix("https://").removeprefix("http://").rstrip("/")
    return None


def _secure_gateway_origin(origin: str) -> str:
    parsed = urlparse(origin.strip().rstrip("/"))
    if parsed.scheme not in ("https", "http"):
        raise _shopify_cli_error(f"invalid gateway URL: {origin}", code="cli.shopify.invalid_gateway")
    return f"{parsed.scheme}://{parsed.netloc}"


def resolve_shopify_webhook_address(gateway_base: str, tunnel: str | None = None) -> str:
    origin = _secure_gateway_origin(tunnel or gateway_base)
    return f"{origin}/webhooks/sandbox/shopify"


def build_shopify_webhook_trigger_command(*, topic: str, address: str, client_id: str | None) -> list[str]:
    args = ["app", "webhook", "trigger", f"--topic={topic}", f"--address={address}"]
    if client_id and not client_id.startswith("env:"):
        args.append(f"--client-id={client_id}")
    return args


def _fetch_settlement_config(ctx: CliContext) -> dict[str, Any] | None:
    try:
        resolve_api_key(ctx.globals, ctx.cwd)
    except CliError:
        return None
    try:
        return gateway_request(ctx, "GET", "/v1/admin/settlement/config")
    except CliError:
        return None


def _rail_readiness_for_shopify(config: dict[str, Any] | None) -> dict[str, Any]:
    readiness_list = config.get("rail_readiness") if config else None
    if not isinstance(readiness_list, list):
        return {
            "name": "rail_readiness",
            "ok": False,
            "message": "shopify_authorized_order readiness unavailable (login and link a shop)",
        }
    for entry in readiness_list:
        if isinstance(entry, dict) and entry.get("rail") == "shopify_authorized_order":
            ready = entry.get("ready") is True
            return {
                "name": "rail_readiness",
                "ok": ready,
                "message": entry.get("message")
                or ("shopify_authorized_order ready" if ready else "not ready"),
                "details": {"rail": entry.get("rail"), "ready": entry.get("ready")},
            }
    return {
        "name": "rail_readiness",
        "ok": False,
        "message": "shopify_authorized_order readiness unavailable (login and link a shop)",
    }


async def run_shopify_doctor_checks(ctx: CliContext) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    shopify_path = _which_executable("shopify")
    if shopify_path:
        version = subprocess.run(
            [shopify_path, "version"],
            capture_output=True,
            text=True,
            check=False,
        )
        message = (version.stdout or version.stderr).strip() or "shopify CLI found"
        checks.append(
            {
                "name": "shopify_cli",
                "ok": version.returncode == 0,
                "message": message.splitlines()[0] if message else message,
                "details": {"path": shopify_path},
            }
        )
    else:
        checks.append(
            {
                "name": "shopify_cli",
                "ok": False,
                "message": "not on PATH — install: npm install -g @shopify/cli@latest",
            }
        )

    ucp_path = _which_executable("ucp")
    if ucp_path:
        version = subprocess.run(
            [ucp_path, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        message = (version.stdout or version.stderr).strip() or "ucp CLI found"
        checks.append(
            {
                "name": "ucp_cli",
                "ok": version.returncode == 0,
                "message": message.splitlines()[0] if message else message,
                "details": {"path": ucp_path},
            }
        )
    else:
        checks.append(
            {
                "name": "ucp_cli",
                "ok": False,
                "message": "not on PATH (optional) — install: npm install -g @shopify/ucp-cli",
            }
        )

    app_toml = _read_shopify_app_toml(ctx.cwd)
    checks.append(
        {
            "name": "shopify_app_toml",
            "ok": app_toml.get("exists") is True,
            "message": (
                f"found {app_toml.get('path', 'shopify.app.toml')}"
                if app_toml.get("exists")
                else "shopify.app.toml not found in cwd — run shopify app config link"
            ),
            **({"details": {"client_id": app_toml["client_id"]}} if app_toml.get("client_id") else {}),
        }
    )

    shop_domain = _resolve_shop_domain(None, ctx.cwd)
    checks.append(
        {
            "name": "dev_store",
            "ok": bool(shop_domain),
            "message": (
                f"SHOPIFY_DEV_STORE={shop_domain}"
                if shop_domain
                else "set SHOPIFY_DEV_STORE in .env.local or pass --shop"
            ),
        }
    )

    settlement = _fetch_settlement_config(ctx)
    checks.append(
        {
            "name": "paybond_shop_linked",
            "ok": settlement is not None and settlement.get("shopify_linked_shop_configured") is True,
            "message": (
                f"linked shop {settlement.get('shopify_shop_domain_masked', '(masked)')}"
                if settlement and settlement.get("shopify_linked_shop_configured")
                else "link a shop in Console → Configuration → Settlement"
            ),
        }
    )
    checks.append(
        {
            "name": "manual_capture",
            "ok": bool(settlement) and settlement.get("shopify_manual_capture_required") is not True,
            "message": (
                "enable manual payment capture in Shopify Admin (required for shopify_authorized_order)"
                if settlement and settlement.get("shopify_manual_capture_required")
                else (
                    "manual capture prerequisite satisfied or not required"
                    if settlement
                    else "skipped (missing settlement config)"
                )
            ),
        }
    )
    checks.append(_rail_readiness_for_shopify(settlement))
    return checks


def _format_doctor_checklist(checks: list[dict[str, Any]], globals_: GlobalOptions) -> list[str]:
    use_color = should_use_color(globals_)
    lines: list[str] = []
    for check in checks:
        prefix = colorize("✓", "green", use_color) if check.get("ok") else colorize("✗", "yellow", use_color)
        lines.append(f"{prefix} {check['name']}: {check['message']}")
    summary = "pass" if all(check.get("ok") for check in checks) else "fail"
    lines.append(colorize(f"shopify doctor: {summary}", "green" if summary == "pass" else "yellow", use_color))
    return lines


async def handle_shopify_doctor(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    if argv:
        raise _shopify_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    checks = await run_shopify_doctor_checks(ctx)
    return {
        "checks": checks,
        "summary": "pass" if all(check.get("ok") for check in checks) else "fail",
        "checklist_lines": _format_doctor_checklist(checks, ctx.globals),
    }


async def handle_shopify_webhook_trigger(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    rest = argv
    _, topic, rest = consume_flag(rest, "--topic")
    _, gateway, rest = consume_flag(rest, "--gateway")
    _, address, rest = consume_flag(rest, "--address")
    dry_run, rest = consume_boolean_flag(rest, "--dry-run")
    if rest:
        raise _shopify_cli_error(
            f"unexpected arguments: {' '.join(rest)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    topic_value = (topic or "orders/paid").strip()
    address_value = (address or "").strip() or resolve_shopify_webhook_address(
        gateway or ctx.globals.gateway,
        None,
    )
    app_toml = _read_shopify_app_toml(ctx.cwd)
    client_id = app_toml.get("client_id")
    if isinstance(client_id, str) and client_id.startswith("env:"):
        client_id = os.environ.get("SHOPIFY_FLAG_CLIENT_ID", "").strip() or None
    shopify_path = _which_executable("shopify")
    if not shopify_path:
        raise _shopify_cli_error(
            "shopify CLI not on PATH — install: npm install -g @shopify/cli@latest",
            code="cli.shopify.missing_cli",
            category="environment",
        )
    trigger_args = build_shopify_webhook_trigger_command(
        topic=topic_value,
        address=address_value,
        client_id=client_id if isinstance(client_id, str) else None,
    )
    command_line = f"shopify {' '.join(trigger_args)}"
    if dry_run:
        return {
            "topic": topic_value,
            "address": address_value,
            "command": command_line,
            "dry_run": True,
        }
    result = subprocess.run(
        [shopify_path, *trigger_args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise _shopify_cli_error(
            (result.stderr or result.stdout or "shopify webhook trigger failed").strip(),
            code="cli.shopify.webhook_trigger_failed",
            details={"command": command_line, "exit_code": result.returncode},
        )
    return {
        "topic": topic_value,
        "address": address_value,
        "command": command_line,
        "stdout": (result.stdout or "").strip(),
    }


async def handle_shopify_checkout_smoke(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    rest = argv
    _, shop, rest = consume_flag(rest, "--shop")
    _, spend, rest = consume_flag(rest, "--requested-spend-cents")
    offline, rest = consume_boolean_flag(rest, "--offline")
    if rest:
        raise _shopify_cli_error(
            f"unexpected arguments: {' '.join(rest)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    defaults = get_solution_smoke_defaults("shopping")
    shop_domain = _resolve_shop_domain(shop, ctx.cwd) or "paybond-agent-commerce-dev.myshopify.com"
    spend_cents = int(spend) if spend else defaults["requested_spend_cents"]
    if spend_cents <= 0:
        raise _shopify_cli_error("invalid --requested-spend-cents", code="cli.usage.invalid_spend", category="usage")
    result_body = {
        **defaults["result_body"],
        "order_id": "gid://shopify/Order/123",
        "shop": shop_domain,
    }
    smoke_argv = [
        "--preset",
        "shopping",
        "--operation",
        defaults["operation"],
        "--requested-spend-cents",
        str(spend_cents),
        "--evidence-preset",
        defaults["evidence_preset"],
        "--result-body",
        json.dumps(result_body),
    ]
    if offline:
        smoke_argv.append("--offline")
    smoke_result = await handle_agent_sandbox_smoke(ctx, smoke_argv)
    ucp_path = _which_executable("ucp")
    use_color = should_use_color(ctx.globals)
    lines = [
        colorize("shopify checkout smoke", "cyan", use_color),
        (
            colorize("ucp CLI detected — use createCheckoutWithBinding for live UCP checkout", "dim", use_color)
            if ucp_path
            else colorize("ucp CLI not on PATH — used paybond agent sandbox smoke fallback", "dim", use_color)
        ),
        f"shop: {shop_domain}",
        "binding note_attributes: paybond_intent_id + tenant_id (injected by Kit on live checkout)",
    ]
    checklist = smoke_result.get("checklist_lines")
    if isinstance(checklist, list):
        lines.extend(str(line) for line in checklist)
    return {
        **smoke_result,
        "shop": shop_domain,
        "ucp_available": bool(ucp_path),
        "checklist_lines": lines,
    }


async def handle_shopify_payments_doctor(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    if argv:
        raise _shopify_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    checks = await run_shopify_payments_doctor_checks(ctx)
    return {
        "checks": checks,
        "summary": "pass" if all(check.get("ok") for check in checks) else "fail",
        "checklist_lines": _format_payments_doctor_checklist(checks, ctx.globals),
    }


def _format_payments_doctor_checklist(checks: list[dict[str, Any]], globals_: GlobalOptions) -> list[str]:
    use_color = should_use_color(globals_)
    lines: list[str] = []
    for check in checks:
        prefix = colorize("✓", "green", use_color) if check.get("ok") else colorize("✗", "yellow", use_color)
        lines.append(f"{prefix} {check['name']}: {check['message']}")
    summary = "pass" if all(check.get("ok") for check in checks) else "fail"
    lines.append(colorize(f"shopify payments doctor: {summary}", "green" if summary == "pass" else "yellow", use_color))
    return lines


async def run_shopify_payments_doctor_checks(ctx: CliContext) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    shopify_path = _which_executable("shopify")
    checks.append(
        {
            "name": "shopify_cli",
            "ok": bool(shopify_path),
            "message": f"found at {shopify_path}" if shopify_path else "not on PATH",
        }
    )
    app_toml = _read_shopify_payments_app_toml(ctx.cwd)
    checks.append(
        {
            "name": "payments_app_toml",
            "ok": app_toml.get("exists") is True,
            "message": (
                f"found {app_toml.get('path', 'shopify.app.toml')}"
                if app_toml.get("exists")
                else "shopify.app.toml not found — run: cd apps/shopify-payments && shopify app config link"
            ),
        }
    )
    shop_domain = _resolve_shop_domain(None, ctx.cwd)
    checks.append(
        {
            "name": "dev_store",
            "ok": bool(shop_domain),
            "message": f"SHOPIFY_DEV_STORE={shop_domain}" if shop_domain else "set SHOPIFY_DEV_STORE",
        }
    )
    settlement = _fetch_settlement_config(ctx)
    checks.append(
        {
            "name": "payments_app_linked",
            "ok": settlement is not None and settlement.get("shopify_payments_linked") is True,
            "message": (
                "Paybond Payments app linked"
                if settlement and settlement.get("shopify_payments_linked")
                else "link the Paybond Payments app in Console"
            ),
        }
    )
    readiness_list = settlement.get("rail_readiness") if settlement else None
    readiness = next(
        (entry for entry in readiness_list or [] if isinstance(entry, dict) and entry.get("rail") == "shopify_payments_app"),
        None,
    )
    checks.append(
        {
            "name": "payments_rail_readiness",
            "ok": isinstance(readiness, dict) and readiness.get("ready") is True,
            "message": (
                readiness.get("message", "shopify_payments_app ready")
                if isinstance(readiness, dict) and readiness.get("ready")
                else "shopify_payments_app not ready"
            ),
        }
    )
    return checks


def _read_shopify_payments_app_toml(cwd: Path) -> dict[str, Any]:
    for path in (cwd / "shopify.app.toml", cwd / "apps" / "shopify-payments" / "shopify.app.toml"):
        if path.is_file():
            return _read_shopify_app_toml(path.parent)
    return {"exists": False}


async def handle_shopify_payments_smoke(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    return await handle_shopify_checkout_smoke(ctx, argv)


async def handle_shopify_payments_session_show(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    session_id = argv[0].strip() if argv else ""
    rest = argv[1:]
    _, shop, rest = consume_flag(rest, "--shop")
    if not session_id or rest:
        raise _shopify_cli_error(
            "usage: paybond shopify payments session show <id> [--shop <domain>]",
            code="cli.usage.invalid_args",
            category="usage",
        )
    try:
        resolve_api_key(ctx.globals, ctx.cwd)
    except CliError as err:
        raise _shopify_cli_error("session show requires paybond login", code="cli.shopify.missing_credentials") from err
    session = gateway_request(
        ctx,
        "GET",
        f"/v1/admin/shopify/payments/sessions/{session_id}",
    )
    if shop and isinstance(session, dict) and session.get("shop_domain") != shop.strip():
        raise _shopify_cli_error(
            "session shop_domain does not match --shop",
            code="cli.shopify.session_shop_mismatch",
        )
    return {"session": session}


async def handle_shopify(ctx: CliContext, second: str, third: str | None, fourth: str | None, argv: list[str]) -> dict[str, Any]:
    if second == "payments":
        if third == "doctor":
            return await handle_shopify_payments_doctor(ctx, argv)
        if third == "smoke":
            return await handle_shopify_payments_smoke(ctx, argv)
        if third == "session" and fourth == "show":
            return await handle_shopify_payments_session_show(ctx, argv)
        raise _shopify_cli_error(
            f"unknown shopify payments subcommand: shopify payments {third or ''}",
            code="cli.usage.unknown_command",
            category="usage",
        )
    if second == "doctor":
        return await handle_shopify_doctor(ctx, argv)
    if second == "webhook" and third == "trigger":
        return await handle_shopify_webhook_trigger(ctx, argv)
    if second == "checkout" and third == "smoke":
        return await handle_shopify_checkout_smoke(ctx, argv)
    raise _shopify_cli_error(
        f"unknown shopify subcommand: shopify {second}",
        code="cli.usage.unknown_command",
        category="usage",
    )
