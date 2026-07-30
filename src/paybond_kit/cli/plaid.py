"""paybond plaid subcommands: safe Plaid Auth readiness inspection (H4 P2).

Plaid Auth is a tenant-scoped bank-verification input under the existing
`stripe_ach_debit` rail (see `docs/operations/plaid-account-verification-setup.md`
and `.cursor/plans/hardened-plaid-auth-paybond-integration.plan.md`). This module
is read-only operator inspection:

- It never implements `paybond plaid link` and never accepts `public_token`,
  `access_token`, `link_token`, or Stripe processor tokens on argv or stdin.
- It never prints Plaid secrets, Link tokens, decrypted vault material, or raw
  account/routing numbers. Bank metadata mirrors what the Admin console already
  renders for the same authenticated operator (institution, masked account,
  readiness reason) via `GET /v1/admin/plaid/bank-accounts`.
- Reason codes are the same stable strings the Gateway and Admin console use
  (`go/gateway/internal/rails/plaid/reasons.go`): `ready`, `pending_automatic_verification`,
  `attach_retryable`, `relink_required`, `revoked`, `risk_check_required`,
  `risk_check_failed`, `feature_disabled`, `production_not_allowlisted`.
"""

from __future__ import annotations

import uuid
from typing import Any, Protocol
from urllib.parse import urlparse

from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.core import (
    CliContext,
    CliError,
    gateway_request,
    resolve_api_key,
)

# Plaid Link/exchange/processor material must never appear on argv (CWE-214 /
# SEC-011). The CLI has no link/exchange subcommand at all, but this guard is
# defense-in-depth against a caller trying to pass one anyway.
PLAID_ARGV_BLOCKED_FLAGS = (
    "--public-token",
    "--access-token",
    "--link-token",
    "--processor-token",
    "--bank-account-token",
)


class _ColorGlobals(Protocol):
    format: str
    color: str


# Fields the gateway's admin bank-accounts endpoint may return that are safe to
# print. Acts as a second line of defense allowlist: even if the gateway wire
# shape grows, the CLI never forwards unlisted fields (e.g. it can never forward
# an access_token or processor token added to the response by mistake).
_SAFE_BANK_FIELDS = (
    "id",
    "environment",
    "institution_id",
    "verification_status",
    "auth_method",
    "bank_name",
    "bank_mask",
    "bank_last4",
    "account_type",
    "account_subtype",
    "status",
    "ready",
    "readiness_reason",
    "stripe_attach_status",
    "stripe_attach_error_code",
    "relink_required",
    "bank_link_source",
    "created_at",
    "updated_at",
)


def _plaid_cli_error(
    message: str,
    *,
    code: str,
    category: str = "validation",
    details: dict[str, Any] | None = None,
) -> CliError:
    return CliError(message, category=category, code=code, details=details or {})


def rejects_plaid_sensitive_argv_flag(arg: str) -> bool:
    """True when an argv token is a blocked Plaid Link/token flag (exact or ``--flag=value``)."""
    for flag in PLAID_ARGV_BLOCKED_FLAGS:
        if arg == flag or arg.startswith(f"{flag}="):
            return True
    return False


def assert_no_plaid_sensitive_argv(argv: list[str]) -> None:
    """Reject process-visible Plaid Link/token material on argv (SEC-011)."""
    for arg in argv:
        if not rejects_plaid_sensitive_argv_flag(arg):
            continue
        flag = next(
            (candidate for candidate in PLAID_ARGV_BLOCKED_FLAGS if arg == candidate or arg.startswith(f"{candidate}=")),
            arg,
        )
        raise _plaid_cli_error(
            f"plaid CLI rejects {flag} on argv (visible in process listings); Paybond never accepts Plaid "
            "Link, access, or processor tokens outside the server-side exchange endpoint",
            code="cli.plaid.argv_secret_forbidden",
            category="usage",
            details={"flag": flag},
        )


def _secure_gateway_origin(origin: str) -> str:
    parsed = urlparse(origin.strip().rstrip("/"))
    if parsed.scheme not in ("https", "http"):
        raise _plaid_cli_error(f"invalid gateway URL: {origin}", code="cli.plaid.invalid_gateway")
    return f"{parsed.scheme}://{parsed.netloc}"


def resolve_plaid_webhook_address(gateway_base: str) -> str:
    """Resolve the Paybond gateway origin to the corrected Plaid webhook route.

    A single route (``/webhooks/plaid``) serves both sandbox and production; the
    Plaid environment is resolved server-side from the authenticated tenant's
    Item, never from the URL path. Do not reintroduce the retired
    ``/webhooks/production/plaid`` path here or in docs (H2 correction).
    """
    origin = _secure_gateway_origin(gateway_base)
    return f"{origin}/webhooks/plaid"


def _safe_bank_summary(bank: dict[str, Any]) -> dict[str, Any]:
    """Project a bank-account wire object to CLI-safe fields only (allowlist)."""
    return {key: bank[key] for key in _SAFE_BANK_FIELDS if key in bank}


def build_plaid_ready_checks(
    list_body: dict[str, Any] | None,
    fetch_error: CliError | None,
) -> list[dict[str, Any]]:
    """Build readiness checks for `paybond plaid ready` from the bank-accounts response.

    ``fetch_error`` is the CliError raised by the gateway call (e.g. 404
    `feature_disabled` / `production_not_allowlisted`) so the same stable reason
    codes render as an actionable check instead of a bare CLI failure.
    """
    if fetch_error is not None:
        details = fetch_error.details or {}
        return [
            {
                "name": "feature_available",
                "ok": False,
                "message": fetch_error.message,
                "details": {"reason_code": details.get("gateway_code")},
            }
        ]

    body = list_body or {}
    environment = str(body.get("environment") or "unknown")
    banks = [_safe_bank_summary(b) for b in body.get("bank_accounts", []) if isinstance(b, dict)]
    ready_banks = [b for b in banks if b.get("ready") is True]
    not_ready_banks = [b for b in banks if b.get("ready") is not True]

    checks: list[dict[str, Any]] = [
        {
            "name": "feature_available",
            "ok": True,
            "message": f"Plaid Auth is available for this tenant (environment={environment})",
            "details": {"environment": environment},
        },
        {
            "name": "ready_bank_available",
            "ok": len(ready_banks) > 0,
            "message": (
                f"{len(ready_banks)} linked bank(s) ready for ACH debit"
                if ready_banks
                else "no ready Plaid bank yet; link one in Console → Configuration → Settlement, or use Financial Connections"
            ),
            "details": {"banks_total": len(banks), "banks_ready": len(ready_banks)},
        },
    ]
    if not_ready_banks:
        reasons = sorted({str(b.get("readiness_reason") or "not_ready") for b in not_ready_banks})
        checks.append(
            {
                "name": "attention_needed",
                "ok": True,
                "message": f"{len(not_ready_banks)} linked bank(s) need attention: {', '.join(reasons)}",
                "details": {"reason_codes": reasons, "count": len(not_ready_banks)},
            }
        )
    return checks


def build_plaid_doctor_checks(
    list_body: dict[str, Any] | None,
    fetch_error: CliError | None,
    *,
    gateway_base: str,
    tenant_environment: str | None = None,
) -> list[dict[str, Any]]:
    """Expand ready checks with webhook address, environment pairing, and pointers."""
    checks = build_plaid_ready_checks(list_body, fetch_error)
    webhook_address = resolve_plaid_webhook_address(gateway_base)
    checks.append(
        {
            "name": "webhook_endpoint",
            "ok": True,
            "message": (
                f"configure PLAID_WEBHOOK_URL={webhook_address} on the gateway deploy "
                "(one route serves sandbox and production; environment resolves server-side)"
            ),
            "details": {
                "webhook_address": webhook_address,
                "route": "/webhooks/plaid",
                "events": [
                    "AUTOMATICALLY_VERIFIED",
                    "VERIFICATION_EXPIRED",
                    "DEFAULT_UPDATE",
                    "ERROR",
                    "PENDING_DISCONNECT",
                    "USER_PERMISSION_REVOKED",
                    "USER_ACCOUNT_REVOKED",
                ],
            },
        }
    )

    tenant_env = (tenant_environment or "").strip().lower() or None
    plaid_env = str((list_body or {}).get("environment") or "").strip().lower() or None
    if tenant_env and plaid_env:
        message = (
            f"tenant environment={tenant_env} pairs with Plaid environment={plaid_env} "
            "(the gateway enforces this pairing server-side before Link and exchange)"
        )
    else:
        message = "environment pairing check skipped (login required to resolve tenant environment)"
    checks.append(
        {
            "name": "environment_pairing",
            "ok": True,
            "message": message,
            "details": {"tenant_environment": tenant_env, "plaid_environment": plaid_env},
        }
    )

    checks.append(
        {
            "name": "console_and_docs",
            "ok": True,
            "message": (
                "link/manage banks in Console → Configuration → Settlement; "
                "guide: https://paybond.ai/guides/configure-plaid-bank-verification"
            ),
            "details": {
                "console_path": "/console/configuration/settlement",
                "guide_path": "/guides/configure-plaid-bank-verification",
                "sandbox_smoke": "make plaid-auth-sandbox-smoke",
            },
        }
    )
    return checks


def format_plaid_checklist(
    checks: list[dict[str, Any]],
    globals_: _ColorGlobals,
    label: str = "plaid doctor",
) -> list[str]:
    use_color = should_use_color(globals_)
    lines: list[str] = []
    for check in checks:
        prefix = colorize("✓", "green", use_color) if check.get("ok") else colorize("✗", "yellow", use_color)
        lines.append(f"{prefix} {check['name']}: {check['message']}")
    summary = "pass" if all(check.get("ok") for check in checks) else "fail"
    lines.append(colorize(f"{label}: {summary}", "green" if summary == "pass" else "yellow", use_color))
    return lines


def _fetch_bank_accounts(ctx: CliContext) -> tuple[dict[str, Any] | None, CliError | None]:
    """Fetch `GET /v1/admin/plaid/bank-accounts`.

    Missing/invalid credentials raise immediately (not a Plaid readiness state).
    Gateway-side failures (disabled feature, tenant not allowlisted, forbidden)
    are returned as an error so callers can render them as an actionable check.
    """
    resolve_api_key(ctx.globals, ctx.cwd)
    try:
        body = gateway_request(ctx, "GET", "/v1/admin/plaid/bank-accounts")
        return (body if isinstance(body, dict) else {}), None
    except CliError as exc:
        return None, exc


def _fetch_bank_account(ctx: CliContext, bank_id: str) -> tuple[dict[str, Any] | None, CliError | None]:
    """Fetch `GET /v1/admin/plaid/bank-accounts/{id}`: one tenant-scoped bank.

    Issues a single tenant-scoped request for this id instead of downloading the
    whole inventory and filtering client-side, so lookups stay O(1) for tenants
    with many linked banks (H5). Missing/invalid credentials raise immediately.
    Gateway-side failures (unknown/cross-tenant id, disabled feature, tenant not
    allowlisted, forbidden) are returned as an error so the caller can map them.
    """
    resolve_api_key(ctx.globals, ctx.cwd)
    try:
        body = gateway_request(ctx, "GET", f"/v1/admin/plaid/bank-accounts/{bank_id}")
        return (body if isinstance(body, dict) else {}), None
    except CliError as exc:
        return None, exc


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


def _reject_unexpected_plaid_args(argv: list[str]) -> None:
    if argv:
        raise _plaid_cli_error(
            f"unexpected arguments: {' '.join(argv)}",
            code="cli.usage.unexpected_args",
            category="usage",
        )


async def handle_plaid_ready(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_plaid_sensitive_argv(argv)
    _reject_unexpected_plaid_args(argv)
    body, error = _fetch_bank_accounts(ctx)
    checks = build_plaid_ready_checks(body, error)
    ready = all(check.get("ok") for check in checks)
    return {
        "ready": ready,
        "checks": checks,
        "summary": "pass" if ready else "fail",
        "checklist_lines": format_plaid_checklist(checks, ctx.globals, "plaid ready"),
    }


async def handle_plaid_doctor(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_plaid_sensitive_argv(argv)
    _reject_unexpected_plaid_args(argv)
    body, error = _fetch_bank_accounts(ctx)
    checks = build_plaid_doctor_checks(
        body,
        error,
        gateway_base=ctx.globals.gateway,
        tenant_environment=_fetch_tenant_environment(ctx),
    )
    return {
        "checks": checks,
        "summary": "pass" if all(check.get("ok") for check in checks) else "fail",
        "checklist_lines": format_plaid_checklist(checks, ctx.globals, "plaid doctor"),
        "next_steps": [
            "Console: https://paybond.ai/console/configuration/settlement",
            "Docs: https://paybond.ai/guides/configure-plaid-bank-verification",
            "Sandbox smoke: make plaid-auth-sandbox-smoke",
            "Ready: paybond plaid ready",
        ],
    }


async def handle_plaid_banks_list(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_plaid_sensitive_argv(argv)
    _reject_unexpected_plaid_args(argv)
    body, error = _fetch_bank_accounts(ctx)
    if error is not None:
        raise error
    banks = [_safe_bank_summary(b) for b in (body or {}).get("bank_accounts", []) if isinstance(b, dict)]
    return {
        "environment": (body or {}).get("environment"),
        "bank_accounts": banks,
        "count": len(banks),
    }


async def handle_plaid_banks_get(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_plaid_sensitive_argv(argv)
    positional = [arg for arg in argv if not arg.startswith("-")]
    if len(positional) != 1:
        raise _plaid_cli_error(
            "usage: paybond plaid banks get <bank-account-id>",
            code="cli.usage.missing_argument",
            category="usage",
        )
    bank_id = positional[0].strip()
    try:
        uuid.UUID(bank_id)
    except ValueError as exc:
        raise _plaid_cli_error(
            f"invalid bank account id: {bank_id}",
            code="cli.plaid.invalid_bank_id",
        ) from exc

    body, error = _fetch_bank_account(ctx, bank_id)
    if error is not None:
        raise _map_bank_get_error(bank_id, error)
    return {"bank_account": _safe_bank_summary(body or {})}


def _map_bank_get_error(bank_id: str, fetch_error: CliError) -> CliError:
    """Map a `banks get` Gateway failure to a stable CLI error.

    Only a 404 whose reason is unrecognized or explicitly
    ``plaid_bank_not_found`` collapses into ``cli.plaid.bank_not_found`` (unknown
    and cross-tenant ids are indistinguishable by design). A 404 carrying a
    feature-gate reason (``feature_disabled`` / ``production_not_allowlisted``)
    is re-raised unchanged so it stays distinct and actionable via
    ``paybond plaid ready`` / ``paybond plaid doctor``.
    """
    details = fetch_error.details or {}
    gateway_code = details.get("gateway_code")
    if details.get("gateway_status") == 404 and gateway_code in (None, "plaid_bank_not_found"):
        return _plaid_cli_error(
            f"linked bank not found: {bank_id}",
            code="cli.plaid.bank_not_found",
            category="not_found",
            details={"reason_code": "plaid_bank_not_found"},
        )
    return fetch_error


async def handle_plaid_webhook_address(ctx: CliContext, argv: list[str]) -> dict[str, Any]:
    if argv and argv[0] in ("--help", "-h"):
        raise CliError("help", category="usage", code="cli.help")
    assert_no_plaid_sensitive_argv(argv)
    _reject_unexpected_plaid_args(argv)
    address = resolve_plaid_webhook_address(ctx.globals.gateway)
    return {
        "webhook_address": address,
        "route": "/webhooks/plaid",
        "note": (
            "Set PLAID_WEBHOOK_URL to this address on the gateway deploy (https required in production). "
            "For local development, tunnel this route instead of committing a tunnel URL — see "
            "docs/operations/plaid-account-verification-setup.md."
        ),
    }


async def handle_plaid_banks(ctx: CliContext, second: str, argv: list[str]) -> dict[str, Any]:
    """Dispatch `paybond plaid banks <subcommand>`."""
    if second == "list":
        return await handle_plaid_banks_list(ctx, argv)
    if second == "get":
        return await handle_plaid_banks_get(ctx, argv)
    raise _plaid_cli_error(
        f"unknown plaid banks subcommand: banks {second}",
        code="cli.usage.unknown_command",
        category="usage",
    )


async def handle_plaid(ctx: CliContext, second: str, argv: list[str]) -> dict[str, Any]:
    """Dispatch `paybond plaid <subcommand>`."""
    if second == "ready":
        return await handle_plaid_ready(ctx, argv)
    if second == "doctor":
        return await handle_plaid_doctor(ctx, argv)
    if second == "webhook-address":
        return await handle_plaid_webhook_address(ctx, argv)
    raise _plaid_cli_error(
        f"unknown plaid subcommand: plaid {second}",
        code="cli.usage.unknown_command",
        category="usage",
    )
