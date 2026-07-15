"""Unit tests for paybond flutterwave ready/doctor against settlement config fixtures."""

from __future__ import annotations

import pytest

from paybond_kit.cli.flutterwave import (
    FLUTTERWAVE_ARGV_BLOCKED_FLAGS,
    assert_no_flutterwave_sensitive_argv,
    build_flutterwave_doctor_checks,
    build_flutterwave_ready_checks,
    format_flutterwave_doctor_checklist,
    rejects_flutterwave_sensitive_argv_flag,
    resolve_flutterwave_webhook_address,
)
from paybond_kit.cli.core import CliError


READY_FIXTURE = {
    "allowed_rails": ["flutterwave_virtual_account", "stripe_connect"],
    "plan_id": "growth",
    "flutterwave_destination_configured": True,
    "flutterwave_environment": "sandbox",
    "flutterwave_label": "NGN corridor",
    "flutterwave_currency": "NGN",
    "flutterwave_secret_key_configured": True,
    "flutterwave_webhook_secret_configured": True,
    "flutterwave_webhook_url": "https://api.paybond.ai/webhooks/sandbox/flutterwave/abcd1234",
    "rail_readiness": [
        {
            "rail": "flutterwave_virtual_account",
            "ready": True,
            "enabled": True,
            "status": "ready",
            "message": "Flutterwave destination credentials are active for virtual-account settlement.",
        }
    ],
}

INCOMPLETE_FIXTURE = {
    "allowed_rails": [],
    "flutterwave_destination_configured": False,
    "flutterwave_secret_key_configured": False,
    "flutterwave_webhook_secret_configured": False,
    "rail_readiness": [
        {
            "rail": "flutterwave_virtual_account",
            "ready": False,
            "enabled": False,
            "status": "not_configured",
            "reason_code": "flutterwave_destination_missing",
            "message": "Save Flutterwave secret key and webhook secret before enabling virtual-account settlement.",
        }
    ],
}

LIVE_UNPAID_FIXTURE = {
    "allowed_rails": ["flutterwave_virtual_account"],
    "plan_id": "free",
    "flutterwave_destination_configured": True,
    "flutterwave_environment": "live",
    "flutterwave_label": "Live NGN",
    "flutterwave_currency": "NGN",
    "flutterwave_secret_key_configured": True,
    "flutterwave_webhook_secret_configured": True,
    "rail_readiness": [
        {
            "rail": "flutterwave_virtual_account",
            "ready": False,
            "enabled": True,
            "status": "plan_upgrade_needed",
            "reason_code": "flutterwave_paid_plan_required",
            "message": "Live Flutterwave settlement destinations are only available on paid self-serve plans.",
        }
    ],
}


class _Globals:
    color = "never"
    format = "table"


def test_resolve_flutterwave_webhook_address() -> None:
    assert (
        resolve_flutterwave_webhook_address("https://api.paybond.ai", "sandbox")
        == "https://api.paybond.ai/webhooks/sandbox/flutterwave"
    )
    assert (
        resolve_flutterwave_webhook_address("https://api.paybond.ai/", "live")
        == "https://api.paybond.ai/webhooks/live/flutterwave"
    )


def test_ready_passes_complete_fixture() -> None:
    checks = build_flutterwave_ready_checks(READY_FIXTURE)
    assert all(check["ok"] for check in checks)
    assert [check["name"] for check in checks] == [
        "rail_enabled",
        "destination_configured",
        "secret_key",
        "webhook_secret",
        "paid_plan",
        "rail_readiness",
    ]


def test_ready_fails_incomplete_fixture() -> None:
    checks = build_flutterwave_ready_checks(INCOMPLETE_FIXTURE)
    by_name = {check["name"]: check for check in checks}
    assert by_name["rail_enabled"]["ok"] is False
    assert by_name["destination_configured"]["ok"] is False
    assert by_name["secret_key"]["ok"] is False
    assert by_name["webhook_secret"]["ok"] is False
    assert by_name["rail_readiness"]["ok"] is False


def test_ready_surfaces_paid_plan_block() -> None:
    checks = build_flutterwave_ready_checks(LIVE_UNPAID_FIXTURE)
    paid_plan = next(check for check in checks if check["name"] == "paid_plan")
    assert paid_plan["ok"] is False
    assert "paid self-serve" in paid_plan["message"]


def test_doctor_expands_with_webhook_and_console() -> None:
    checks = build_flutterwave_doctor_checks(
        READY_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    webhook = next(check for check in checks if check["name"] == "webhook_endpoint")
    assert "/webhooks/sandbox/flutterwave/abcd1234" in webhook["message"]
    assert next(check for check in checks if check["name"] == "environment_match")["ok"] is True
    assert next(check for check in checks if check["name"] == "console_destination")["ok"] is True
    assert all(check["ok"] for check in checks)


def test_doctor_token_hint_without_destination() -> None:
    checks = build_flutterwave_doctor_checks(
        INCOMPLETE_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    webhook = next(check for check in checks if check["name"] == "webhook_endpoint")
    assert "/webhooks/sandbox/flutterwave/<destination-token>" in webhook["message"]


def test_doctor_flags_environment_mismatch() -> None:
    checks = build_flutterwave_doctor_checks(
        LIVE_UNPAID_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    env = next(check for check in checks if check["name"] == "environment_match")
    assert env["ok"] is False
    assert "tenant environment=sandbox" in env["message"]


def test_format_checklist_summary() -> None:
    checks = build_flutterwave_ready_checks(INCOMPLETE_FIXTURE)
    lines = format_flutterwave_doctor_checklist(checks, _Globals(), "flutterwave ready")
    assert lines[-1] == "flutterwave ready: fail"
    assert any("rail_enabled" in line for line in lines)


def test_rejects_flutterwave_destination_material_on_argv() -> None:
    for flag in FLUTTERWAVE_ARGV_BLOCKED_FLAGS:
        assert rejects_flutterwave_sensitive_argv_flag(flag) is True
        assert rejects_flutterwave_sensitive_argv_flag(f"{flag}=value") is True
        with pytest.raises(CliError) as exc_info:
            assert_no_flutterwave_sensitive_argv([f"{flag}=secret"])
        assert exc_info.value.code == "cli.flutterwave.argv_secret_forbidden"
        assert flag in exc_info.value.message
        assert "write-only" in exc_info.value.message
    assert rejects_flutterwave_sensitive_argv_flag("--format") is False
    assert_no_flutterwave_sensitive_argv([])


def test_doctor_console_pointer_lists_argv_blocked_flags() -> None:
    checks = build_flutterwave_doctor_checks(
        READY_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    console = next(check for check in checks if check["name"] == "console_destination")
    assert console["details"]["argv_blocked_flags"] == list(FLUTTERWAVE_ARGV_BLOCKED_FLAGS)
    assert "Console" in console["message"]
