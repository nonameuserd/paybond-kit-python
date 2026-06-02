from __future__ import annotations

import uuid

import httpx
import pytest
import respx

from paybond_kit.harbor import HarborClient, HarborHttpError, TenantBindingError


@pytest.mark.asyncio
@respx.mock
async def test_verify_success_checks_tenant_echo() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "tenant-a",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        out = await client.verify_capability(
            intent_id=intent_id,
            token="Cg==",
            operation="demo.tool",
            requested_spend_cents=0,
        )
        assert out.allow
        assert out.tenant == "tenant-a"
        assert out.intent_id == intent_id
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_verify_rejects_tenant_mismatch() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "other",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        with pytest.raises(TenantBindingError):
            await client.verify_capability(
                intent_id=intent_id,
                token="Cg==",
                operation="demo.tool",
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_verify_http_error_surfaces_status() -> None:
    intent_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(return_value=httpx.Response(500, text="boom"))
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        with pytest.raises(HarborHttpError):
            await client.verify_capability(
                intent_id=intent_id,
                token="Cg==",
                operation="demo.tool",
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_fund_intent_returns_x402_challenge() -> None:
    intent_id = uuid.uuid4()
    respx.post(f"https://harbor.test/intents/{intent_id}/fund").mock(
        return_value=httpx.Response(
            402,
            headers={"payment-required": "x402-requirements"},
            json={
                "intent_id": str(intent_id),
                "tenant": "tenant-a",
                "state": "open",
                "settlement_rail": "x402_usdc_base",
                "currency": "usd",
                "amount_cents": 2000,
                "funded": False,
                "funding": {
                    "settlement_rail": "x402_usdc_base",
                    "harbor_fund_endpoint": f"/intents/{intent_id}/fund",
                    "status": "authorization_pending",
                    "payment_session_id": "paymentSession_test",
                    "payment_url": "https://pay.coinbase.com/payment-sessions/paymentSession_test",
                    "asset": "usdc",
                    "network": "base",
                },
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        out = await client.fund_intent(intent_id)
        assert out.status_code == 402
        assert out.payment_required == "x402-requirements"
        assert out.settlement_rail == "x402_usdc_base"
        assert out.funding is not None
        assert out.funding.payment_session_id == "paymentSession_test"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_fund_intent_returns_stripe_ach_handoff() -> None:
    intent_id = uuid.uuid4()
    respx.post(f"https://harbor.test/intents/{intent_id}/fund").mock(
        return_value=httpx.Response(
            202,
            json={
                "intent_id": str(intent_id),
                "tenant": "tenant-a",
                "state": "open",
                "settlement_rail": "stripe_ach_debit",
                "currency": "usd",
                "amount_cents": 4200,
                "funded": False,
                "funding": {
                    "settlement_rail": "stripe_ach_debit",
                    "harbor_fund_endpoint": f"/intents/{intent_id}/fund",
                    "status": "requires_payment_method",
                    "stripe_payment_intent_id": "pi_ach_123",
                    "client_secret": "pi_ach_123_secret_abc",
                    "stripe_connect_destination": "acct_123",
                    "stripe_customer_id": "cus_123",
                    "payment_method_id": "pm_123",
                    "mandate_id": "mandate_123",
                    "financial_connections_account_id": "fca_123",
                    "bank_last4": "6789",
                    "bank_fingerprint": "bankfp_123",
                    "bank_name": "Test Bank",
                    "expected_debit_date": "2026-06-05",
                    "payment_reference": "PAYBOND-ACH-123",
                },
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        out = await client.fund_intent(intent_id)
        assert out.status_code == 202
        assert out.settlement_rail == "stripe_ach_debit"
        assert out.funding is not None
        assert out.funding.stripe_payment_intent_id == "pi_ach_123"
        assert out.funding.client_secret == "pi_ach_123_secret_abc"
        assert out.funding.stripe_connect_destination == "acct_123"
        assert out.funding.stripe_customer_id == "cus_123"
        assert out.funding.payment_method_id == "pm_123"
        assert out.funding.mandate_id == "mandate_123"
        assert out.funding.financial_connections_account_id == "fca_123"
        assert out.funding.bank_last4 == "6789"
        assert out.funding.bank_fingerprint == "bankfp_123"
        assert out.funding.bank_name == "Test Bank"
        assert out.funding.expected_debit_date == "2026-06-05"
        assert out.funding.payment_reference == "PAYBOND-ACH-123"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_fund_intent_rejects_unknown_settlement_rail() -> None:
    intent_id = uuid.uuid4()
    respx.post(f"https://harbor.test/intents/{intent_id}/fund").mock(
        return_value=httpx.Response(
            200,
            json={
                "intent_id": str(intent_id),
                "tenant": "tenant-a",
                "state": "open",
                "settlement_rail": "bogus",
                "currency": "usd",
                "amount_cents": 2000,
                "funded": False,
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        with pytest.raises(HarborHttpError, match="must be one of"):
            await client.fund_intent(intent_id)
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_ledger_tip_rejects_tenant_mismatch() -> None:
    respx.get("https://harbor.test/ledger/v1/tip").mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "other",
                "seq": 1,
                "entry_commitment_hex": "ab" * 32,
                "empty": False,
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        with pytest.raises(TenantBindingError):
            await client.get_ledger_tip()
    finally:
        await client.aclose()


def _ledger_events_ok() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "schema_version": 1,
            "tenant_id": "tenant-a",
            "entries": [],
            "next_after_seq": None,
        },
    )


@pytest.mark.asyncio
@respx.mock
async def test_ledger_events_query_and_limit_clamp() -> None:
    respx.get("https://harbor.test/ledger/v1/events?after_seq=5&limit=10").mock(
        return_value=_ledger_events_ok()
    )
    respx.get("https://harbor.test/ledger/v1/events?after_seq=0&limit=256").mock(
        return_value=_ledger_events_ok()
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        await client.get_ledger_events(after_seq=5, limit=10)
        await client.get_ledger_events(after_seq=0, limit=999)
    finally:
        await client.aclose()
