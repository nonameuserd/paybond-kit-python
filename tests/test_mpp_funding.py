"""Tests for MPP intent funding orchestration."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest

from paybond_kit.harbor import FundIntentResult, IntentFundingResult
from paybond_kit.mpp_funding import (
    MppFundPollOptions,
    PaybondMppFundingFailedError,
    PaybondMppFundingPendingError,
    build_mpp_fund_request_envelope,
    execute_fund_with_mpp_charge,
    execute_fund_with_mpp_session,
    parse_payment_auth_challenge,
    select_mpp_charge_challenge,
    select_mpp_session_challenge,
)

INTENT_ID = uuid.UUID("550e8400-e29b-41d4-a716-446655440011")

CHARGE_CHALLENGE = (
    'Payment id="abc", realm="api.example.com", method="stripe", '
    'intent="charge", request="eyJ0ZXN0IjoidHJ1ZSJ9"'
)
SESSION_CHALLENGE = (
    'Payment id="def", realm="api.example.com", method="tempo", '
    'intent="session", request="eyJ0ZXN0Ijoic2VzcyJ9"'
)


def _fund_result(**overrides: Any) -> FundIntentResult:
    defaults: dict[str, Any] = {
        "status_code": 200,
        "payment_required": None,
        "payment_response": None,
        "www_authenticate": None,
        "payment_receipt": None,
        "cache_control": None,
        "intent_id": INTENT_ID,
        "tenant": "tenant-a",
        "state": "open",
        "settlement_rail": "stripe_mpp",
        "currency": "usd",
        "amount_cents": 2000,
        "funded": False,
        "capability_token": None,
        "funding": None,
    }
    defaults.update(overrides)
    return FundIntentResult(**defaults)


def test_parse_payment_auth_challenge() -> None:
    parsed = parse_payment_auth_challenge(CHARGE_CHALLENGE)
    assert parsed.id == "abc"
    assert parsed.realm == "api.example.com"
    assert parsed.method == "stripe"
    assert parsed.intent == "charge"
    assert parsed.request == "eyJ0ZXN0IjoidHJ1ZSJ9"


def test_select_mpp_charge_challenge() -> None:
    assert select_mpp_charge_challenge([CHARGE_CHALLENGE, SESSION_CHALLENGE]) == CHARGE_CHALLENGE


def test_select_mpp_session_challenge() -> None:
    assert select_mpp_session_challenge([CHARGE_CHALLENGE, SESSION_CHALLENGE]) == SESSION_CHALLENGE


@pytest.mark.asyncio
async def test_fund_with_mpp_charge_returns_immediately_when_already_funded() -> None:
    funded = _fund_result(status_code=200, funded=True, capability_token="cap-token")
    fund = AsyncMock(return_value=funded)

    result = await execute_fund_with_mpp_charge(
        intent_id=INTENT_ID,
        recognition_proof={"nonce": "initial"},
        create_payment_credential=AsyncMock(),
        issue_recognition_proof=AsyncMock(),
        fund=fund,
    )

    assert result is funded
    fund.assert_awaited_once_with(recognition_proof={"nonce": "initial"})


@pytest.mark.asyncio
async def test_fund_with_mpp_charge_creates_credential_and_retries() -> None:
    challenge = _fund_result(status_code=402, www_authenticate=[CHARGE_CHALLENGE])
    funded = _fund_result(status_code=200, funded=True, capability_token="cap-token")
    fund = AsyncMock(side_effect=[challenge, funded])
    create_payment_credential = AsyncMock(return_value="mpp-credential")
    issue_recognition_proof = AsyncMock(return_value={"nonce": "retry"})

    result = await execute_fund_with_mpp_charge(
        intent_id=INTENT_ID,
        recognition_proof={"nonce": "initial"},
        create_payment_credential=create_payment_credential,
        issue_recognition_proof=issue_recognition_proof,
        fund=fund,
    )

    assert result is funded
    create_payment_credential.assert_awaited_once_with(CHARGE_CHALLENGE)
    issue_recognition_proof.assert_awaited_once_with(
        build_mpp_fund_request_envelope(INTENT_ID)
    )
    fund.assert_any_await(recognition_proof={"nonce": "initial"})
    fund.assert_any_await(
        recognition_proof={"nonce": "retry"},
        payment_authorization="mpp-credential",
    )


@pytest.mark.asyncio
async def test_fund_with_mpp_charge_polls_until_funded() -> None:
    challenge = _fund_result(status_code=402, www_authenticate=[CHARGE_CHALLENGE])
    pending = _fund_result(
        status_code=202,
        funding=IntentFundingResult(
            settlement_rail="stripe_mpp",
            harbor_fund_endpoint=None,
            status="authorization_pending",
            payment_session_id=None,
            payment_url=None,
            stripe_payment_intent_id=None,
            client_secret=None,
            stripe_connect_destination=None,
            stripe_customer_id=None,
            latest_charge_id=None,
            payment_method_id=None,
            mandate_id=None,
            financial_connections_account_id=None,
            bank_last4=None,
            bank_fingerprint=None,
            bank_name=None,
            asset=None,
            network=None,
            authorization_id=None,
            capture_id=None,
            void_id=None,
            transfer_id=None,
            refund_id=None,
            expected_debit_date=None,
            payment_reference=None,
            refund_reference=None,
            refund_reference_status=None,
            source_address=None,
            target_address=None,
            authorization_expires_at=None,
            capture_expires_at=None,
            refund_expires_at=None,
            onchain_transaction_hashes=None,
        ),
    )
    funded = _fund_result(status_code=200, funded=True, capability_token="cap-token")
    fund = AsyncMock(side_effect=[challenge, pending, funded])
    create_payment_credential = AsyncMock(return_value="mpp-credential")
    issue_recognition_proof = AsyncMock(
        side_effect=[{"nonce": "retry"}, {"nonce": "poll"}]
    )

    result = await execute_fund_with_mpp_charge(
        intent_id=INTENT_ID,
        recognition_proof={"nonce": "initial"},
        create_payment_credential=create_payment_credential,
        issue_recognition_proof=issue_recognition_proof,
        fund=fund,
        poll_options=MppFundPollOptions(max_attempts=3, interval_ms=0),
    )

    assert result is funded
    assert fund.await_count == 3


@pytest.mark.asyncio
async def test_fund_with_mpp_charge_pending_error_after_max_attempts() -> None:
    pending = _fund_result(
        status_code=202,
        funding=IntentFundingResult(
            settlement_rail="stripe_mpp",
            harbor_fund_endpoint=None,
            status="authorization_pending",
            payment_session_id=None,
            payment_url=None,
            stripe_payment_intent_id=None,
            client_secret=None,
            stripe_connect_destination=None,
            stripe_customer_id=None,
            latest_charge_id=None,
            payment_method_id=None,
            mandate_id=None,
            financial_connections_account_id=None,
            bank_last4=None,
            bank_fingerprint=None,
            bank_name=None,
            asset=None,
            network=None,
            authorization_id=None,
            capture_id=None,
            void_id=None,
            transfer_id=None,
            refund_id=None,
            expected_debit_date=None,
            payment_reference=None,
            refund_reference=None,
            refund_reference_status=None,
            source_address=None,
            target_address=None,
            authorization_expires_at=None,
            capture_expires_at=None,
            refund_expires_at=None,
            onchain_transaction_hashes=None,
        ),
    )
    fund = AsyncMock(return_value=pending)

    with pytest.raises(PaybondMppFundingPendingError):
        await execute_fund_with_mpp_charge(
            intent_id=INTENT_ID,
            recognition_proof={"nonce": "initial"},
            create_payment_credential=AsyncMock(),
            issue_recognition_proof=AsyncMock(return_value={"nonce": "poll"}),
            fund=fund,
            poll_options=MppFundPollOptions(max_attempts=2, interval_ms=0),
        )


@pytest.mark.asyncio
async def test_fund_with_mpp_charge_failed_error_on_terminal_status() -> None:
    failed = _fund_result(
        status_code=200,
        funding=IntentFundingResult(
            settlement_rail="stripe_mpp",
            harbor_fund_endpoint=None,
            status="authorization_failed",
            payment_session_id=None,
            payment_url=None,
            stripe_payment_intent_id=None,
            client_secret=None,
            stripe_connect_destination=None,
            stripe_customer_id=None,
            latest_charge_id=None,
            payment_method_id=None,
            mandate_id=None,
            financial_connections_account_id=None,
            bank_last4=None,
            bank_fingerprint=None,
            bank_name=None,
            asset=None,
            network=None,
            authorization_id=None,
            capture_id=None,
            void_id=None,
            transfer_id=None,
            refund_id=None,
            expected_debit_date=None,
            payment_reference=None,
            refund_reference=None,
            refund_reference_status=None,
            source_address=None,
            target_address=None,
            authorization_expires_at=None,
            capture_expires_at=None,
            refund_expires_at=None,
            onchain_transaction_hashes=None,
        ),
    )
    fund = AsyncMock(return_value=failed)

    with pytest.raises(PaybondMppFundingFailedError):
        await execute_fund_with_mpp_charge(
            intent_id=INTENT_ID,
            recognition_proof={"nonce": "initial"},
            create_payment_credential=AsyncMock(),
            issue_recognition_proof=AsyncMock(),
            fund=fund,
        )


@pytest.mark.asyncio
async def test_fund_with_mpp_session_selects_session_challenge() -> None:
    challenge = _fund_result(
        status_code=402,
        www_authenticate=[CHARGE_CHALLENGE, SESSION_CHALLENGE],
    )
    funded = _fund_result(status_code=200, funded=True, capability_token="cap-token")
    fund = AsyncMock(side_effect=[challenge, funded])
    create_payment_credential = AsyncMock(return_value="session-credential")
    issue_recognition_proof = AsyncMock(return_value={"nonce": "retry"})

    result = await execute_fund_with_mpp_session(
        intent_id=INTENT_ID,
        recognition_proof={"nonce": "initial"},
        create_payment_credential=create_payment_credential,
        issue_recognition_proof=issue_recognition_proof,
        fund=fund,
    )

    assert result is funded
    create_payment_credential.assert_awaited_once_with(SESSION_CHALLENGE)
