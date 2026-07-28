"""Unit tests for paybond plaid ready/doctor/banks (H4 P2, H5)."""

from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import pytest
import respx

from paybond_kit.cli.core import CliError
from paybond_kit.cli.plaid import (
    PLAID_ARGV_BLOCKED_FLAGS,
    assert_no_plaid_sensitive_argv,
    build_plaid_doctor_checks,
    build_plaid_ready_checks,
    format_plaid_checklist,
    rejects_plaid_sensitive_argv_flag,
    resolve_plaid_webhook_address,
)
from paybond_kit.cli.router import run_cli

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
GATEWAY = "https://gateway.test"
BANK_ID = "8f14e45f-ceea-4c9b-a71a-0d0e12b3f4d1"


READY_LIST = {
    "environment": "sandbox",
    "bank_accounts": [
        {
            "id": "8f14e45f-ceea-4c9b-a71a-0d0e12b3f4d1",
            "environment": "sandbox",
            "bank_name": "Chase",
            "bank_mask": "0000",
            "bank_last4": "0000",
            "status": "active",
            "ready": True,
            "readiness_reason": "ready",
            "access_token": "access-sandbox-should-never-appear",
            "link_token": "link-sandbox-should-never-appear",
        }
    ],
}

PENDING_LIST = {
    "environment": "sandbox",
    "bank_accounts": [
        {
            "id": "8f14e45f-ceea-4c9b-a71a-0d0e12b3f4d1",
            "ready": False,
            "readiness_reason": "pending_automatic_verification",
            "status": "active",
            "verification_status": "pending_automatic_verification",
        }
    ],
}


class _Globals:
    color = "never"
    format = "table"


def test_resolve_plaid_webhook_address() -> None:
    assert (
        resolve_plaid_webhook_address("https://api.paybond.ai")
        == "https://api.paybond.ai/webhooks/plaid"
    )
    assert (
        resolve_plaid_webhook_address("https://api.paybond.ai/")
        == "https://api.paybond.ai/webhooks/plaid"
    )
    assert "/webhooks/production/plaid" not in resolve_plaid_webhook_address(
        "https://api.paybond.ai"
    )


def test_ready_passes_when_ready_bank_present() -> None:
    checks = build_plaid_ready_checks(READY_LIST, None)
    assert all(check["ok"] for check in checks)
    assert [check["name"] for check in checks] == [
        "feature_available",
        "ready_bank_available",
    ]


def test_ready_fails_when_no_ready_bank() -> None:
    checks = build_plaid_ready_checks(PENDING_LIST, None)
    by_name = {check["name"]: check for check in checks}
    assert by_name["feature_available"]["ok"] is True
    assert by_name["ready_bank_available"]["ok"] is False
    assert by_name["attention_needed"]["ok"] is True
    assert "pending_automatic_verification" in by_name["attention_needed"]["message"]


def test_ready_surfaces_feature_disabled_reason_code() -> None:
    err = CliError(
        "Plaid Auth is disabled on this deployment.",
        category="gateway",
        code="feature_disabled",
        details={"gateway_code": "feature_disabled", "gateway_status": 404},
    )
    checks = build_plaid_ready_checks(None, err)
    assert len(checks) == 1
    assert checks[0]["ok"] is False
    assert checks[0]["details"]["reason_code"] == "feature_disabled"


def test_ready_surfaces_production_not_allowlisted() -> None:
    err = CliError(
        "Plaid Auth is not enabled for this tenant.",
        category="gateway",
        code="production_not_allowlisted",
        details={"gateway_code": "production_not_allowlisted", "gateway_status": 404},
    )
    checks = build_plaid_ready_checks(None, err)
    assert checks[0]["details"]["reason_code"] == "production_not_allowlisted"


def test_doctor_expands_webhook_and_docs() -> None:
    checks = build_plaid_doctor_checks(
        READY_LIST,
        None,
        gateway_base="https://api.paybond.ai",
        tenant_environment="sandbox",
    )
    webhook = next(check for check in checks if check["name"] == "webhook_endpoint")
    assert webhook["details"]["webhook_address"] == "https://api.paybond.ai/webhooks/plaid"
    assert webhook["details"]["route"] == "/webhooks/plaid"
    docs = next(check for check in checks if check["name"] == "console_and_docs")
    assert docs["details"]["guide_path"] == "/guides/configure-plaid-bank-verification"
    assert all(check["ok"] for check in checks)


def test_safe_bank_summary_redacts_tokens() -> None:
    from paybond_kit.cli.plaid import _safe_bank_summary

    summary = _safe_bank_summary(READY_LIST["bank_accounts"][0])
    assert "access_token" not in summary
    assert "link_token" not in summary
    assert summary["readiness_reason"] == "ready"
    assert summary["id"] == "8f14e45f-ceea-4c9b-a71a-0d0e12b3f4d1"


def test_format_checklist_summary() -> None:
    checks = build_plaid_ready_checks(PENDING_LIST, None)
    lines = format_plaid_checklist(checks, _Globals(), "plaid ready")
    assert lines[-1] == "plaid ready: fail"
    assert any("ready_bank_available" in line for line in lines)


def test_rejects_plaid_token_material_on_argv() -> None:
    for flag in PLAID_ARGV_BLOCKED_FLAGS:
        assert rejects_plaid_sensitive_argv_flag(flag) is True
        assert rejects_plaid_sensitive_argv_flag(f"{flag}=value") is True
        with pytest.raises(CliError) as exc_info:
            assert_no_plaid_sensitive_argv([f"{flag}=secret"])
        assert exc_info.value.code == "cli.plaid.argv_secret_forbidden"
        assert flag in exc_info.value.message
    assert rejects_plaid_sensitive_argv_flag("--format") is False
    assert_no_plaid_sensitive_argv([])


@pytest.mark.asyncio
@respx.mock
async def test_banks_get_issues_per_id_get_not_list_and_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    list_route = respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts").mock(
        return_value=httpx.Response(200, json={"bank_accounts": []})
    )
    get_route = respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts/{BANK_ID}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": BANK_ID,
                "environment": "sandbox",
                "bank_name": "Chase",
                "bank_mask": "0000",
                "bank_last4": "0000",
                "status": "active",
                "ready": True,
                "readiness_reason": "ready",
                "access_token": "access-sandbox-should-never-appear",
                "link_token": "link-sandbox-should-never-appear",
            },
        )
    )

    stdout = io.StringIO()
    code = await run_cli(
        ["--gateway", GATEWAY, "--format", "json", "plaid", "banks", "get", BANK_ID],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["bank_account"]["id"] == BANK_ID
    assert payload["data"]["bank_account"]["bank_name"] == "Chase"
    # Per-id route only; never the list-all route (H5: no list+filter).
    assert get_route.called
    assert not list_route.called
    # Secret boundary: Link/access tokens must never reach CLI output.
    output = stdout.getvalue()
    assert "access-sandbox-should-never-appear" not in output
    assert "link-sandbox-should-never-appear" not in output
    assert "access_token" not in payload["data"]["bank_account"]
    assert "link_token" not in payload["data"]["bank_account"]


@pytest.mark.asyncio
@respx.mock
async def test_banks_get_unknown_id_maps_to_bank_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts/{BANK_ID}").mock(
        return_value=httpx.Response(
            404, json={"error": "plaid_bank_not_found", "message": "Linked bank not found."}
        )
    )

    stdout = io.StringIO()
    code = await run_cli(
        ["--gateway", GATEWAY, "--format", "json", "plaid", "banks", "get", BANK_ID],
        stdout=stdout,
    )
    assert code != 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert payload["error"]["code"] == "cli.plaid.bank_not_found"
    assert payload["error"]["details"]["reason_code"] == "plaid_bank_not_found"


@pytest.mark.asyncio
@respx.mock
async def test_banks_get_keeps_feature_disabled_distinct_from_bank_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts/{BANK_ID}").mock(
        return_value=httpx.Response(
            404,
            json={
                "error": "feature_disabled",
                "message": "Plaid Auth is disabled on this deployment.",
            },
        )
    )

    stdout = io.StringIO()
    code = await run_cli(
        ["--gateway", GATEWAY, "--format", "json", "plaid", "banks", "get", BANK_ID],
        stdout=stdout,
    )
    assert code != 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert payload["error"]["code"] == "feature_disabled"
    assert payload["error"]["code"] != "cli.plaid.bank_not_found"
    assert payload["error"]["details"]["gateway_code"] == "feature_disabled"


@pytest.mark.asyncio
@respx.mock
async def test_banks_get_keeps_production_not_allowlisted_distinct_from_bank_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    respx.get(f"{GATEWAY}/v1/admin/plaid/bank-accounts/{BANK_ID}").mock(
        return_value=httpx.Response(
            404,
            json={
                "error": "production_not_allowlisted",
                "message": "Plaid Auth is not enabled for this tenant.",
            },
        )
    )

    stdout = io.StringIO()
    code = await run_cli(
        ["--gateway", GATEWAY, "--format", "json", "plaid", "banks", "get", BANK_ID],
        stdout=stdout,
    )
    assert code != 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert payload["error"]["code"] == "production_not_allowlisted"
    assert payload["error"]["code"] != "cli.plaid.bank_not_found"
    assert payload["error"]["details"]["gateway_code"] == "production_not_allowlisted"
