"""Unit tests for paybond paystack ready/doctor against settlement config fixtures."""

from __future__ import annotations

import pytest

from paybond_kit.cli.paystack import (
    PAYSTACK_ARGV_BLOCKED_FLAGS,
    assert_no_paystack_sensitive_argv,
    build_paystack_doctor_checks,
    build_paystack_ready_checks,
    format_paystack_doctor_checklist,
    rejects_paystack_sensitive_argv_flag,
    resolve_paystack_webhook_address,
)
from paybond_kit.cli.core import CliError


READY_FIXTURE = {
    "allowed_rails": ["paystack_nip", "stripe_connect"],
    "plan_id": "growth",
    "paystack_destination_configured": True,
    "paystack_environment": "sandbox",
    "paystack_label": "NGN corridor",
    "paystack_currency": "NGN",
    "paystack_secret_key_configured": True,
    "paystack_webhook_url": "https://api.paybond.ai/webhooks/sandbox/paystack/abcd1234",
    "rail_readiness": [
        {
            "rail": "paystack_nip",
            "ready": True,
            "enabled": True,
            "status": "ready",
            "message": "Paystack destination credentials are active for NIP settlement.",
        }
    ],
}

INCOMPLETE_FIXTURE = {
    "allowed_rails": [],
    "paystack_destination_configured": False,
    "paystack_secret_key_configured": False,
    "rail_readiness": [
        {
            "rail": "paystack_nip",
            "ready": False,
            "enabled": False,
            "status": "not_configured",
            "reason_code": "paystack_destination_missing",
            "message": "Save Paystack secret key before enabling NIP settlement.",
        }
    ],
}

LIVE_UNPAID_FIXTURE = {
    "allowed_rails": ["paystack_nip"],
    "plan_id": "free",
    "paystack_destination_configured": True,
    "paystack_environment": "live",
    "paystack_label": "Live NGN",
    "paystack_currency": "NGN",
    "paystack_secret_key_configured": True,
    "rail_readiness": [
        {
            "rail": "paystack_nip",
            "ready": False,
            "enabled": True,
            "status": "plan_upgrade_needed",
            "reason_code": "paystack_paid_plan_required",
            "message": "Live Paystack settlement destinations are only available on paid self-serve plans.",
        }
    ],
}


class _Globals:
    color = "never"
    format = "table"


def test_resolve_paystack_webhook_address() -> None:
    assert (
        resolve_paystack_webhook_address("https://api.paybond.ai", "sandbox")
        == "https://api.paybond.ai/webhooks/sandbox/paystack"
    )
    assert (
        resolve_paystack_webhook_address("https://api.paybond.ai/", "live")
        == "https://api.paybond.ai/webhooks/live/paystack"
    )


def test_ready_passes_complete_fixture() -> None:
    checks = build_paystack_ready_checks(READY_FIXTURE)
    assert all(check["ok"] for check in checks)
    assert [check["name"] for check in checks] == [
        "rail_enabled",
        "destination_configured",
        "secret_key",
        "paid_plan",
        "rail_readiness",
    ]


def test_ready_fails_incomplete_fixture() -> None:
    checks = build_paystack_ready_checks(INCOMPLETE_FIXTURE)
    by_name = {check["name"]: check for check in checks}
    assert by_name["rail_enabled"]["ok"] is False
    assert by_name["destination_configured"]["ok"] is False
    assert by_name["secret_key"]["ok"] is False
    assert by_name["rail_readiness"]["ok"] is False


def test_ready_surfaces_paid_plan_block() -> None:
    checks = build_paystack_ready_checks(LIVE_UNPAID_FIXTURE)
    paid_plan = next(check for check in checks if check["name"] == "paid_plan")
    assert paid_plan["ok"] is False
    assert "paid self-serve" in paid_plan["message"]


def test_doctor_expands_with_webhook_and_console() -> None:
    checks = build_paystack_doctor_checks(
        READY_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    webhook = next(check for check in checks if check["name"] == "webhook_endpoint")
    assert "/webhooks/sandbox/paystack/abcd1234" in webhook["message"]
    assert next(check for check in checks if check["name"] == "environment_match")["ok"] is True
    assert next(check for check in checks if check["name"] == "console_destination")["ok"] is True
    assert all(check["ok"] for check in checks)


def test_doctor_token_hint_without_destination() -> None:
    checks = build_paystack_doctor_checks(
        INCOMPLETE_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    webhook = next(check for check in checks if check["name"] == "webhook_endpoint")
    assert "/webhooks/sandbox/paystack/<destination-token>" in webhook["message"]


def test_doctor_flags_environment_mismatch() -> None:
    checks = build_paystack_doctor_checks(
        LIVE_UNPAID_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    env = next(check for check in checks if check["name"] == "environment_match")
    assert env["ok"] is False
    assert "tenant environment=sandbox" in env["message"]


def test_format_checklist_summary() -> None:
    checks = build_paystack_ready_checks(INCOMPLETE_FIXTURE)
    lines = format_paystack_doctor_checklist(checks, _Globals(), "paystack ready")
    assert lines[-1] == "paystack ready: fail"
    assert any("rail_enabled" in line for line in lines)


def test_rejects_paystack_destination_material_on_argv() -> None:
    for flag in PAYSTACK_ARGV_BLOCKED_FLAGS:
        assert rejects_paystack_sensitive_argv_flag(flag) is True
        assert rejects_paystack_sensitive_argv_flag(f"{flag}=value") is True
        with pytest.raises(CliError) as exc_info:
            assert_no_paystack_sensitive_argv([f"{flag}=secret"])
        assert exc_info.value.code == "cli.paystack.argv_secret_forbidden"
        assert flag in exc_info.value.message
        assert "write-only" in exc_info.value.message
    assert rejects_paystack_sensitive_argv_flag("--format") is False
    assert_no_paystack_sensitive_argv([])


def test_doctor_console_pointer_lists_argv_blocked_flags() -> None:
    checks = build_paystack_doctor_checks(
        READY_FIXTURE,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    console = next(check for check in checks if check["name"] == "console_destination")
    assert console["details"]["argv_blocked_flags"] == list(PAYSTACK_ARGV_BLOCKED_FLAGS)
    assert "Console" in console["message"]
