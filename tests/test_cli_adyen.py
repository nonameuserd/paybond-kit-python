"""Unit tests for paybond adyen ready/doctor against settlement config fixtures."""

from __future__ import annotations

import pytest

from paybond_kit.cli.adyen import (
    ADYEN_ARGV_BLOCKED_FLAGS,
    assert_no_adyen_sensitive_argv,
    build_adyen_doctor_checks,
    build_adyen_ready_checks,
    format_adyen_doctor_checklist,
    rejects_adyen_sensitive_argv_flag,
    resolve_adyen_webhook_address,
)
from paybond_kit.cli.core import CliError


READY_FIXTURE = {
    "allowed_rails": ["adyen_manual_capture", "stripe_connect"],
    "plan_id": "growth",
    "adyen_destination_configured": True,
    "adyen_merchant_account_masked": "Payb***Demo",
    "adyen_environment": "test",
    "adyen_live_prefix_configured": False,
    "adyen_api_key_configured": True,
    "adyen_hmac_secret_configured": True,
    "adyen_stored_payment_method_configured": True,
    "rail_readiness": [
        {
            "rail": "adyen_manual_capture",
            "ready": True,
            "enabled": True,
            "status": "ready",
            "message": "Adyen Checkout destination credentials are active for manual-capture settlement.",
        }
    ],
}

INCOMPLETE_FIXTURE = {
    "allowed_rails": [],
    "adyen_destination_configured": False,
    "adyen_api_key_configured": False,
    "adyen_hmac_secret_configured": False,
    "adyen_stored_payment_method_configured": False,
    "adyen_live_prefix_configured": False,
    "rail_readiness": [
        {
            "rail": "adyen_manual_capture",
            "ready": False,
            "enabled": False,
            "status": "not_configured",
            "reason_code": "adyen_destination_missing",
            "message": "Save Adyen Checkout merchant credentials before enabling manual-capture settlement.",
        }
    ],
}

LIVE_UNPAID_FIXTURE = {
    "allowed_rails": ["adyen_manual_capture"],
    "plan_id": "free",
    "adyen_destination_configured": True,
    "adyen_merchant_account_masked": "Live***Acct",
    "adyen_environment": "live",
    "adyen_live_prefix_configured": True,
    "adyen_api_key_configured": True,
    "adyen_hmac_secret_configured": True,
    "adyen_stored_payment_method_configured": True,
    "rail_readiness": [
        {
            "rail": "adyen_manual_capture",
            "ready": False,
            "enabled": True,
            "status": "plan_upgrade_needed",
            "reason_code": "adyen_paid_plan_required",
            "message": "Live Adyen settlement destinations are only available on paid self-serve plans.",
        }
    ],
}


class _Globals:
    color = "never"
    format = "table"


def test_resolve_adyen_webhook_address() -> None:
    assert (
        resolve_adyen_webhook_address("https://api.paybond.ai", "sandbox")
        == "https://api.paybond.ai/webhooks/sandbox/adyen"
    )
    assert (
        resolve_adyen_webhook_address("https://api.paybond.ai/", "live")
        == "https://api.paybond.ai/webhooks/live/adyen"
    )


def test_ready_passes_complete_fixture() -> None:
    checks = build_adyen_ready_checks(READY_FIXTURE)
    assert all(check["ok"] for check in checks)
    assert [check["name"] for check in checks] == [
        "rail_enabled",
        "destination_configured",
        "api_key",
        "hmac",
        "stored_payment_method",
        "live_prefix",
        "paid_plan",
        "rail_readiness",
    ]


def test_ready_fails_incomplete_fixture() -> None:
    checks = build_adyen_ready_checks(INCOMPLETE_FIXTURE)
    by_name = {check["name"]: check for check in checks}
    assert by_name["rail_enabled"]["ok"] is False
    assert by_name["destination_configured"]["ok"] is False
    assert by_name["api_key"]["ok"] is False
    assert by_name["hmac"]["ok"] is False
    assert by_name["rail_readiness"]["ok"] is False


def test_ready_surfaces_paid_plan_block() -> None:
    checks = build_adyen_ready_checks(LIVE_UNPAID_FIXTURE)
    paid_plan = next(check for check in checks if check["name"] == "paid_plan")
    assert paid_plan["ok"] is False
    assert "paid self-serve" in paid_plan["message"]


def test_doctor_expands_with_webhook_and_console() -> None:
    checks = build_adyen_doctor_checks(
        READY_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    webhook = next(check for check in checks if check["name"] == "webhook_endpoint")
    assert "/webhooks/sandbox/adyen" in webhook["message"]
    assert next(check for check in checks if check["name"] == "environment_match")["ok"] is True
    assert next(check for check in checks if check["name"] == "console_destination")["ok"] is True
    assert all(check["ok"] for check in checks)


def test_doctor_flags_environment_mismatch() -> None:
    checks = build_adyen_doctor_checks(
        LIVE_UNPAID_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    env = next(check for check in checks if check["name"] == "environment_match")
    assert env["ok"] is False
    assert "tenant environment=sandbox" in env["message"]


def test_format_checklist_summary() -> None:
    checks = build_adyen_ready_checks(INCOMPLETE_FIXTURE)
    lines = format_adyen_doctor_checklist(checks, _Globals(), "adyen ready")
    assert lines[-1] == "adyen ready: fail"
    assert any("rail_enabled" in line for line in lines)


def test_rejects_adyen_destination_material_on_argv() -> None:
    for flag in ADYEN_ARGV_BLOCKED_FLAGS:
        assert rejects_adyen_sensitive_argv_flag(flag) is True
        assert rejects_adyen_sensitive_argv_flag(f"{flag}=value") is True
        with pytest.raises(CliError) as exc_info:
            assert_no_adyen_sensitive_argv([f"{flag}=secret"])
        assert exc_info.value.code == "cli.adyen.argv_secret_forbidden"
        assert flag in exc_info.value.message
        assert "write-only" in exc_info.value.message
    assert rejects_adyen_sensitive_argv_flag("--format") is False
    assert_no_adyen_sensitive_argv([])


def test_doctor_console_pointer_lists_argv_blocked_flags() -> None:
    checks = build_adyen_doctor_checks(
        READY_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    console = next(check for check in checks if check["name"] == "console_destination")
    assert console["details"]["argv_blocked_flags"] == list(ADYEN_ARGV_BLOCKED_FLAGS)
    assert "--live-prefix" in console["message"]
