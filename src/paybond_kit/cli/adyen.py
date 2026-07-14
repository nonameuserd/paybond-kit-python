"""paybond adyen subcommands (Python parity with kit/ts CLI)."""

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
ADYEN_ARGV_BLOCKED_FLAGS = (
    "--live-prefix",
    "--api-key",
    "--hmac-secret",
    "--merchant-account",
    "--environment",
    "--stored-payment-method",
    "--stored-payment-method-id",
)


def _adyen_cli_error(
    message: str,
    *,
    code: str,
    category: str = "validation",
    details: dict[str, Any] | None = None,
) -> CliError:
    return CliError(message, category=category, code=code, details=details or {})


def rejects_adyen_sensitive_argv_flag(arg: str) -> bool:
    """True when an argv token is a blocked Adyen destination flag (exact or ``--flag=value``)."""
    for flag in ADYEN_ARGV_BLOCKED_FLAGS:
        if arg == flag or arg.startswith(f"{flag}="):
            return True
    return False


def assert_no_adyen_sensitive_argv(argv: list[str]) -> None:
    """Reject process-visible Adyen destination material on argv (SEC-011)."""
    for arg in argv:
        if not rejects_adyen_sensitive_argv_flag(arg):
            continue
        flag = next(
            (candidate for candidate in ADYEN_ARGV_BLOCKED_FLAGS if arg == candidate or arg.startswith(f"{candidate}=")),
            arg,
        )
        raise _adyen_cli_error(
            f"adyen CLI rejects {flag} on argv (visible in process listings); upsert destination "
            "credentials and live URL prefix via Console → Configuration → Settlement (write-only)",
            code="cli.adyen.argv_secret_forbidden",
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
        raise _adyen_cli_error(f"invalid gateway URL: {origin}", code="cli.adyen.invalid_gateway")
    return f"{parsed.scheme}://{parsed.netloc}"


def resolve_adyen_webhook_address(gateway_base: str, environment: str = "sandbox") -> str:
    """Resolve Paybond gateway origin to the Adyen webhook path for live or sandbox."""
    origin = _secure_gateway_origin(gateway_base)
    env = "live" if environment == "live" else "sandbox"
    return f"{origin}/webhooks/{env}/adyen"


def _adyen_rail_readiness(config: dict[str, Any]) -> dict[str, Any] | None:
    readiness_list = config.get("rail_readiness")
    if not isinstance(readiness_list, list):
        return None
    for entry in readiness_list:
        if isinstance(entry, dict) and entry.get("rail") == "adyen_manual_capture":
            return entry
    return None


def build_adyen_ready_checks(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Build settlement-config readiness checks for `paybond adyen ready`."""
    rails_raw = config.get("allowed_rails")
    rails = [str(item) for item in rails_raw] if isinstance(rails_raw, list) else []
    rail_enabled = "adyen_manual_capture" in rails
    destination_ok = config.get("adyen_destination_configured") is True
    api_key_ok = config.get("adyen_api_key_configured") is True
    hmac_ok = config.get("adyen_hmac_secret_configured") is True
    stored_pm_ok = config.get("adyen_stored_payment_method_configured") is True
    environment = str(config.get("adyen_environment") or "").strip().lower()
    live = environment == "live"
    live_prefix_ok = (not live) or config.get("adyen_live_prefix_configured") is True
    readiness = _adyen_rail_readiness(config)
    paid_plan_blocked = bool(readiness and readiness.get("reason_code") == "adyen_paid_plan_required")

    checks: list[dict[str, Any]] = [
        {
            "name": "rail_enabled",
            "ok": rail_enabled,
            "message": (
                "adyen_manual_capture is in allowed_rails"
                if rail_enabled
                else "enable adyen_manual_capture in Console → Configuration → Settlement"
            ),
            "details": {"allowed_rails": rails},
        },
        {
            "name": "destination_configured",
            "ok": destination_ok,
            "message": (
                f"destination active ({config.get('adyen_merchant_account_masked', 'masked merchant')})"
                if destination_ok
                else "save Adyen Checkout destination credentials in Console → Configuration → Settlement"
            ),
            "details": {
                "merchant_account_masked": config.get("adyen_merchant_account_masked"),
                "environment": config.get("adyen_environment"),
            },
        },
        {
            "name": "api_key",
            "ok": api_key_ok,
            "message": (
                "Checkout API key configured"
                if api_key_ok
                else "upsert Adyen API key via Console destination form (write-only; never --api-key on argv)"
            ),
        },
        {
            "name": "hmac",
            "ok": hmac_ok,
            "message": (
                "webhook HMAC secret configured"
                if hmac_ok
                else "upsert Adyen webhook HMAC secret via Console destination form (write-only; never --hmac-secret on argv)"
            ),
        },
        {
            "name": "stored_payment_method",
            "ok": stored_pm_ok,
            "message": (
                "tenant stored payment method vaulted for live funding"
                if stored_pm_ok
                else "upsert stored payment method via Console destination form (write-only; never via CLI argv)"
            ),
        },
        {
            "name": "live_prefix",
            "ok": live_prefix_ok,
            "message": (
                (
                    "live URL prefix configured"
                    if live_prefix_ok
                    else "set company live URL prefix via Console → Settlement (write-only; never --live-prefix on argv)"
                )
                if live
                else (
                    f"live prefix not required (environment={config.get('adyen_environment')})"
                    if config.get("adyen_environment")
                    else "live prefix check skipped (no adyen_environment on destination)"
                )
            ),
            "details": {
                "environment": config.get("adyen_environment"),
                "live_prefix_configured": config.get("adyen_live_prefix_configured") is True,
                "write_only": True,
            },
        },
    ]

    if paid_plan_blocked:
        checks.append(
            {
                "name": "paid_plan",
                "ok": False,
                "message": readiness.get("message")
                if readiness and readiness.get("message")
                else "Live Adyen settlement destinations are only available on paid self-serve plans.",
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
                    else "paid-plan gate applies to live Adyen destinations only"
                ),
                "details": {
                    "plan_id": config.get("plan_id"),
                    "environment": config.get("adyen_environment"),
                },
            }
        )

    if readiness is None:
        checks.append(
            {
                "name": "rail_readiness",
                "ok": False,
                "message": "adyen_manual_capture readiness unavailable (login and save an Adyen destination)",
            }
        )
    else:
        ready = readiness.get("ready") is True and rail_enabled
        if readiness.get("ready") is True and rail_enabled:
            default_message = "adyen_manual_capture ready"
        elif readiness.get("ready") is True:
            default_message = "destination ready — enable adyen_manual_capture in allowed_rails"
        else:
            default_message = "adyen_manual_capture not ready"
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


def build_adyen_doctor_checks(
    config: dict[str, Any],
    *,
    gateway_base: str,
    tenant_environment: str | None = None,
) -> list[dict[str, Any]]:
    """Expand ready checks with webhook URLs, sandbox/live mismatch, and Console pointer."""
    checks = build_adyen_ready_checks(config)
    live_url = resolve_adyen_webhook_address(gateway_base, "live")
    sandbox_url = resolve_adyen_webhook_address(gateway_base, "sandbox")
    adyen_env = str(config.get("adyen_environment") or "").strip().lower()
    preferred = live_url if adyen_env == "live" else sandbox_url

    checks.append(
        {
            "name": "webhook_endpoint",
            "ok": True,
            "message": f"register STANDARD webhook at {preferred} (also support live={live_url})",
            "details": {
                "sandbox": sandbox_url,
                "live": live_url,
                "recommended": preferred,
                "events": [
                    "AUTHORISATION",
                    "CAPTURE",
                    "CAPTURE_FAILED",
                    "CANCELLATION",
                    "REFUND",
                    "CHARGEBACK",
                ],
            },
        }
    )

    tenant_env = (tenant_environment or "").strip().lower() or None
    if tenant_env and adyen_env:
        mismatch = (tenant_env == "sandbox" and adyen_env == "live") or (
            tenant_env == "live" and adyen_env == "test"
        )
        checks.append(
            {
                "name": "environment_match",
                "ok": not mismatch,
                "message": (
                    f"tenant environment={tenant_env} but Adyen destination environment={adyen_env} — "
                    "use matching sandbox/test or live credentials"
                    if mismatch
                    else f"tenant environment={tenant_env} matches Adyen destination environment={adyen_env}"
                ),
                "details": {
                    "tenant_environment": tenant_env,
                    "adyen_environment": adyen_env,
                },
            }
        )
    else:
        if tenant_env:
            message = (
                f"tenant environment={tenant_env}; Adyen destination environment unset — save destination in Console"
            )
        elif adyen_env:
            message = (
                f"Adyen destination environment={adyen_env}; principal environment unavailable "
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
                    "adyen_environment": adyen_env or None,
                },
            }
        )

    checks.append(
        {
            "name": "console_destination",
            "ok": config.get("adyen_destination_configured") is True,
            "message": (
                "destination managed in Console → Configuration → Settlement (CLI rejects argv secrets / --live-prefix)"
                if config.get("adyen_destination_configured")
                else (
                    "upsert merchant account, live prefix, API key, and HMAC in Console → Configuration → Settlement "
                    "(https://paybond.ai/console/configuration/settlement); never pass them on CLI argv"
                )
            ),
            "details": {
                "console_path": "/console/configuration/settlement",
                "write_only_secrets": True,
                "argv_blocked_flags": list(ADYEN_ARGV_BLOCKED_FLAGS),
            },
        }
    )
    return checks


def format_adyen_doctor_checklist(
    checks: list[dict[str, Any]],
    globals_: object,
    label: str = "adyen doctor",
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


async def handle_adyen_ready(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_adyen_sensitive_argv(argv)
    if argv:
        raise _adyen_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    settlement = _fetch_settlement_config(ctx)
    if settlement is None:
        raise _adyen_cli_error(
            "settlement config unavailable — run paybond login",
            code="cli.adyen.missing_settlement",
        )
    checks = build_adyen_ready_checks(settlement)
    ready = all(check.get("ok") for check in checks)
    return {
        "ready": ready,
        "checks": checks,
        "summary": "pass" if ready else "fail",
        "checklist_lines": format_adyen_doctor_checklist(checks, ctx.globals, "adyen ready"),
    }


async def handle_adyen_doctor(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_adyen_sensitive_argv(argv)
    if argv:
        raise _adyen_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )
    settlement = _fetch_settlement_config(ctx)
    if settlement is None:
        raise _adyen_cli_error(
            "settlement config unavailable — run paybond login",
            code="cli.adyen.missing_settlement",
        )
    checks = build_adyen_doctor_checks(
        settlement,
        gateway_base=ctx.globals.gateway,
        tenant_environment=_fetch_tenant_environment(ctx),
    )
    return {
        "checks": checks,
        "summary": "pass" if all(check.get("ok") for check in checks) else "fail",
        "checklist_lines": format_adyen_doctor_checklist(checks, ctx.globals, "adyen doctor"),
        "next_steps": [
            "Console destination upsert: https://paybond.ai/console/configuration/settlement",
            "Docs: https://docs.paybond.ai/guides/configure-adyen-settlement",
            "Ready: paybond adyen ready",
        ],
    }


async def handle_adyen(ctx: CliContext, second: str, argv: list[str]) -> dict[str, Any]:
    """Dispatch `paybond adyen <subcommand>`."""
    if second == "ready":
        return await handle_adyen_ready(ctx, argv)
    if second == "doctor":
        return await handle_adyen_doctor(ctx, argv)
    raise _adyen_cli_error(
        f"unknown adyen subcommand: adyen {second}",
        code="cli.usage.unknown_command",
        category="usage",
    )
