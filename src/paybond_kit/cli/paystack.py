"""paybond paystack subcommands (Python parity with kit/ts CLI)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.core import (
    CliContext,
    CliError,
    gateway_request,
    resolve_api_key,
)

# Destination / vault fields that must never appear on argv (CWE-214 / SEC-011).
# Upsert is Console write-only; ready/doctor only read masked settlement config.
# Paystack has no separate webhook secret — the same secret_key verifies the
# X-Paystack-Signature HMAC-SHA512, so only the secret key and environment are gated.
PAYSTACK_ARGV_BLOCKED_FLAGS = (
    "--secret-key",
    "--environment",
)


def _paystack_cli_error(
    message: str,
    *,
    code: str,
    category: str = "validation",
    details: dict[str, Any] | None = None,
) -> CliError:
    return CliError(message, category=category, code=code, details=details or {})


def rejects_paystack_sensitive_argv_flag(arg: str) -> bool:
    """True when an argv token is a blocked Paystack destination flag (exact or ``--flag=value``)."""
    for flag in PAYSTACK_ARGV_BLOCKED_FLAGS:
        if arg == flag or arg.startswith(f"{flag}="):
            return True
    return False


def assert_no_paystack_sensitive_argv(argv: list[str]) -> None:
    """Reject process-visible Paystack destination material on argv (SEC-011)."""
    for arg in argv:
        if not rejects_paystack_sensitive_argv_flag(arg):
            continue
        flag = next(
            (candidate for candidate in PAYSTACK_ARGV_BLOCKED_FLAGS if arg == candidate or arg.startswith(f"{candidate}=")),
            arg,
        )
        raise _paystack_cli_error(
            f"paystack CLI rejects {flag} on argv (visible in process listings); upsert destination "
            "credentials via Console → Configuration → Settlement (write-only)",
            code="cli.paystack.argv_secret_forbidden",
            category="usage",
            details={
                "flag": flag,
                "write_only": True,
                "console_path": "/console/configuration/settlement",
            },
        )


def _secure_gateway_origin(origin: str) -> str:
    parsed = urlparse(origin.strip().rstrip("/"))
    if parsed.scheme not in ("https", "http"):
        raise _paystack_cli_error(f"invalid gateway URL: {origin}", code="cli.paystack.invalid_gateway")
    return f"{parsed.scheme}://{parsed.netloc}"


def resolve_paystack_webhook_address(gateway_base: str, environment: str = "sandbox") -> str:
    """Resolve Paybond gateway origin to the Paystack webhook base path for live or sandbox."""
    origin = _secure_gateway_origin(gateway_base)
    env = "live" if environment == "live" else "sandbox"
    return f"{origin}/webhooks/{env}/paystack"


def _paystack_rail_readiness(config: dict[str, Any]) -> dict[str, Any] | None:
    readiness_list = config.get("rail_readiness")
    if not isinstance(readiness_list, list):
        return None
    for entry in readiness_list:
        if isinstance(entry, dict) and entry.get("rail") == "paystack_nip":
            return entry
    return None


def build_paystack_ready_checks(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Build settlement-config readiness checks for `paybond paystack ready`."""
    rails_raw = config.get("allowed_rails")
    rails = [str(item) for item in rails_raw] if isinstance(rails_raw, list) else []
    rail_enabled = "paystack_nip" in rails
    destination_ok = config.get("paystack_destination_configured") is True
    secret_key_ok = config.get("paystack_secret_key_configured") is True
    environment = str(config.get("paystack_environment") or "").strip().lower()
    live = environment == "live"
    readiness = _paystack_rail_readiness(config)
    paid_plan_blocked = bool(readiness and readiness.get("reason_code") == "paystack_paid_plan_required")

    checks: list[dict[str, Any]] = [
        {
            "name": "rail_enabled",
            "ok": rail_enabled,
            "message": (
                "paystack_nip is in allowed_rails"
                if rail_enabled
                else "enable paystack_nip in Console → Configuration → Settlement"
            ),
            "details": {"allowed_rails": rails},
        },
        {
            "name": "destination_configured",
            "ok": destination_ok,
            "message": (
                f"destination active ({config.get('paystack_label') or config.get('paystack_currency') or 'Paystack'})"
                if destination_ok
                else "save Paystack destination credentials in Console → Configuration → Settlement"
            ),
            "details": {
                "label": config.get("paystack_label"),
                "currency": config.get("paystack_currency"),
                "environment": config.get("paystack_environment"),
            },
        },
        {
            "name": "secret_key",
            "ok": secret_key_ok,
            "message": (
                "tenant secret key configured (also verifies X-Paystack-Signature HMAC-SHA512)"
                if secret_key_ok
                else "upsert Paystack secret key via Console destination form (write-only; never --secret-key on argv)"
            ),
        },
    ]

    if paid_plan_blocked:
        checks.append(
            {
                "name": "paid_plan",
                "ok": False,
                "message": readiness.get("message")
                if readiness and readiness.get("message")
                else "Live Paystack settlement destinations are only available on paid self-serve plans.",
                "details": {
                    "reason_code": readiness.get("reason_code") if readiness else None,
                    "plan_id": config.get("plan_id"),
                },
            }
        )
    else:
        checks.append(
            {
                "name": "paid_plan",
                "ok": True,
                "message": (
                    "live destination allowed on current plan"
                    if live
                    else "paid-plan gate applies to live Paystack destinations only"
                ),
                "details": {
                    "plan_id": config.get("plan_id"),
                    "environment": config.get("paystack_environment"),
                },
            }
        )

    if readiness is None:
        checks.append(
            {
                "name": "rail_readiness",
                "ok": False,
                "message": "paystack_nip readiness unavailable (login and save a Paystack destination)",
            }
        )
    else:
        ready = readiness.get("ready") is True and rail_enabled
        if readiness.get("ready") is True and rail_enabled:
            default_message = "paystack_nip ready"
        elif readiness.get("ready") is True:
            default_message = "destination ready — enable paystack_nip in allowed_rails"
        else:
            default_message = "paystack_nip not ready"
        checks.append(
            {
                "name": "rail_readiness",
                "ok": ready,
                "message": readiness.get("message") or default_message,
                "details": {
                    "rail": readiness.get("rail"),
                    "ready": readiness.get("ready"),
                    "enabled": readiness.get("enabled"),
                    "status": readiness.get("status"),
                    "reason_code": readiness.get("reason_code"),
                },
            }
        )

    return checks


def build_paystack_doctor_checks(
    config: dict[str, Any],
    *,
    gateway_base: str,
    tenant_environment: str | None = None,
) -> list[dict[str, Any]]:
    """Expand ready checks with webhook URLs, sandbox/live mismatch, and Console pointer."""
    checks = build_paystack_ready_checks(config)
    live_url = resolve_paystack_webhook_address(gateway_base, "live")
    sandbox_url = resolve_paystack_webhook_address(gateway_base, "sandbox")
    paystack_env = str(config.get("paystack_environment") or "").strip().lower()
    base_path = live_url if paystack_env == "live" else sandbox_url
    # The Gateway appends a per-destination token to the webhook path; prefer the
    # configured URL (token-scoped) when a destination is saved.
    configured = str(config.get("paystack_webhook_url") or "").strip()

    checks.append(
        {
            "name": "webhook_endpoint",
            "ok": True,
            "message": (
                f"register webhook at {configured}"
                if configured
                else f"register webhook at {base_path}/<destination-token> (token issued when you save a destination)"
            ),
            "details": {
                "sandbox": sandbox_url,
                "live": live_url,
                "configured": configured or None,
                "events": [
                    "charge.success",
                    "transfer.success",
                    "transfer.failed",
                    "transfer.reversed",
                    "refund.processed",
                ],
            },
        }
    )

    tenant_env = (tenant_environment or "").strip().lower() or None
    if tenant_env and paystack_env:
        mismatch = (tenant_env == "sandbox" and paystack_env == "live") or (
            tenant_env == "live" and paystack_env == "sandbox"
        )
        checks.append(
            {
                "name": "environment_match",
                "ok": not mismatch,
                "message": (
                    f"tenant environment={tenant_env} but Paystack destination environment={paystack_env} — "
                    "use matching sandbox or live credentials"
                    if mismatch
                    else f"tenant environment={tenant_env} matches Paystack destination environment={paystack_env}"
                ),
                "details": {
                    "tenant_environment": tenant_env,
                    "paystack_environment": paystack_env,
                },
            }
        )
    else:
        if tenant_env:
            message = (
                f"tenant environment={tenant_env}; Paystack destination environment unset — save destination in Console"
            )
        elif paystack_env:
            message = (
                f"Paystack destination environment={paystack_env}; principal environment unavailable "
                "(login required for mismatch check)"
            )
        else:
            message = "environment mismatch check skipped (missing principal or destination environment)"
        checks.append(
            {
                "name": "environment_match",
                "ok": True,
                "message": message,
                "details": {
                    "tenant_environment": tenant_env,
                    "paystack_environment": paystack_env or None,
                },
            }
        )

    checks.append(
        {
            "name": "console_destination",
            "ok": config.get("paystack_destination_configured") is True,
            "message": (
                "destination managed in Console → Configuration → Settlement (CLI rejects argv secrets)"
                if config.get("paystack_destination_configured")
                else (
                    "upsert secret key, environment, and currency (NGN) in Console → Configuration → Settlement "
                    "(https://paybond.ai/console/configuration/settlement); never pass them on CLI argv"
                )
            ),
            "details": {
                "console_path": "/console/configuration/settlement",
                "write_only_secrets": True,
                "argv_blocked_flags": list(PAYSTACK_ARGV_BLOCKED_FLAGS),
            },
        }
    )
    return checks


def format_paystack_doctor_checklist(
    checks: list[dict[str, Any]],
    globals_: object,
    label: str = "paystack doctor",
) -> list[str]:
    use_color = should_use_color(globals_)
    lines: list[str] = []
    for check in checks:
        prefix = colorize("✓", "green", use_color) if check.get("ok") else colorize("✗", "yellow", use_color)
        lines.append(f"{prefix} {check['name']}: {check['message']}")
    summary = "pass" if all(check.get("ok") for check in checks) else "fail"
    lines.append(colorize(f"{label}: {summary}", "green" if summary == "pass" else "yellow", use_color))
    return lines


def _fetch_settlement_config(ctx: CliContext) -> dict[str, Any] | None:
    try:
        resolve_api_key(ctx.globals, ctx.cwd)
    except CliError:
        return None
    try:
        body = gateway_request(ctx, "GET", "/v1/admin/settlement/config")
        return body if isinstance(body, dict) else None
    except CliError:
        return None


def _fetch_tenant_environment(ctx: CliContext) -> str | None:
    try:
        resolve_api_key(ctx.globals, ctx.cwd)
    except CliError:
        return None
    try:
        body = gateway_request(ctx, "GET", "/v1/auth/principal")
        if isinstance(body, dict):
            environment = str(body.get("environment") or "").strip()
            return environment or None
        return None
    except CliError:
        return None


async def handle_paystack_ready(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_paystack_sensitive_argv(argv)
    if argv:
        raise _paystack_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    settlement = _fetch_settlement_config(ctx)
    if settlement is None:
        raise _paystack_cli_error(
            "settlement config unavailable — run paybond login",
            code="cli.paystack.missing_settlement",
        )
    checks = build_paystack_ready_checks(settlement)
    ready = all(check.get("ok") for check in checks)
    return {
        "ready": ready,
        "checks": checks,
        "summary": "pass" if ready else "fail",
        "checklist_lines": format_paystack_doctor_checklist(checks, ctx.globals, "paystack ready"),
    }


async def handle_paystack_doctor(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_paystack_sensitive_argv(argv)
    if argv:
        raise _paystack_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    settlement = _fetch_settlement_config(ctx)
    if settlement is None:
        raise _paystack_cli_error(
            "settlement config unavailable — run paybond login",
            code="cli.paystack.missing_settlement",
        )
    checks = build_paystack_doctor_checks(
        settlement,
        gateway_base=ctx.globals.gateway,
        tenant_environment=_fetch_tenant_environment(ctx),
    )
    return {
        "checks": checks,
        "summary": "pass" if all(check.get("ok") for check in checks) else "fail",
        "checklist_lines": format_paystack_doctor_checklist(checks, ctx.globals, "paystack doctor"),
        "next_steps": [
            "Console destination upsert: https://paybond.ai/console/configuration/settlement",
            "Docs: https://docs.paybond.ai/guides/configure-paystack-settlement",
            "Ready: paybond paystack ready",
        ],
    }


async def handle_paystack(ctx: CliContext, second: str, argv: list[str]) -> dict[str, Any]:
    """Dispatch `paybond paystack <subcommand>`."""
    if second == "ready":
        return await handle_paystack_ready(ctx, argv)
    if second == "doctor":
        return await handle_paystack_doctor(ctx, argv)
    raise _paystack_cli_error(
        f"unknown paystack subcommand: paystack {second}",
        code="cli.usage.unknown_command",
        category="usage",
    )
