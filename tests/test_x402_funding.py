"""Unit tests for x402 fund orchestration."""

from __future__ import annotations

from uuid import UUID

import pytest

from paybond_kit.harbor import FundIntentResult
from paybond_kit.x402_funding import (
    FundRequestEnvelope,
    PaybondX402FundingFailedError,
    PaybondX402FundingPendingError,
    X402FundPollOptions,
    build_x402_fund_request_envelope,
    execute_fund_with_x402,
)

INTENT_ID = UUID("550e8400-e29b-41d4-a716-446655440010")


def _fund_result(**overrides: object) -> FundIntentResult:
    base = {
        "status_code": 200,
        "payment_required": None,
        "payment_response": None,
        "intent_id": INTENT_ID,
        "tenant": "tenant-a",
        "state": "open",
        "settlement_rail": "x402_usdc_base",
        "currency": "usd",
        "amount_cents": 2000,
        "funded": False,
        "capability_token": None,
        "funding": None,
    }
    base.update(overrides)
    return FundIntentResult(**base)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_fund_with_x402_returns_immediately_when_already_funded() -> None:
    funded = _fund_result(status_code=200, funded=True, capability_token="cap-token")
    calls = {"count": 0}

    async def fund(**kwargs: object) -> FundIntentResult:
        calls["count"] += 1
        return funded

    result = await execute_fund_with_x402(
        intent_id=INTENT_ID,
        recognition_proof={"nonce": "initial"},
        sign_payment=lambda _challenge: pytest.fail("sign_payment should not run"),
        issue_recognition_proof=lambda _env: pytest.fail("issue_recognition_proof should not run"),
        fund=fund,
    )
    assert result is funded
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_fund_with_x402_signs_402_and_retries() -> None:
    challenge = _fund_result(status_code=402, payment_required="x402-requirements")
    funded = _fund_result(status_code=200, funded=True, capability_token="cap-token")
    responses = [challenge, funded]
    signed: list[str] = []
    issued: list[FundRequestEnvelope] = []

    async def fund(**kwargs: object) -> FundIntentResult:
        return responses.pop(0)

    async def sign_payment(challenge: str) -> str:
        signed.append(challenge)
        return "signed-payment"

    async def issue_recognition_proof(envelope: FundRequestEnvelope) -> dict[str, str]:
        issued.append(envelope)
        return {"nonce": "retry"}

    result = await execute_fund_with_x402(
        intent_id=INTENT_ID,
        recognition_proof={"nonce": "initial"},
        sign_payment=sign_payment,
        issue_recognition_proof=issue_recognition_proof,
        fund=fund,
    )
    assert result.capability_token == "cap-token"
    assert signed == ["x402-requirements"]
    assert issued == [build_x402_fund_request_envelope(INTENT_ID)]


@pytest.mark.asyncio
async def test_fund_with_x402_polls_until_capability_token() -> None:
    pending = _fund_result(status_code=202)
    funded = _fund_result(status_code=200, funded=True, capability_token="cap-token")
    responses = [pending, pending, funded]
    poll_count = {"value": 0}

    async def fund(**kwargs: object) -> FundIntentResult:
        return responses.pop(0)

    async def issue_recognition_proof(_envelope: FundRequestEnvelope) -> dict[str, str]:
        poll_count["value"] += 1
        return {"nonce": f"poll-{poll_count['value']}"}

    result = await execute_fund_with_x402(
        intent_id=INTENT_ID,
        recognition_proof={"nonce": "initial"},
        sign_payment=lambda _challenge: pytest.fail("sign_payment should not run"),
        issue_recognition_proof=issue_recognition_proof,
        poll_options=X402FundPollOptions(max_attempts=5, interval_ms=0),
        fund=fund,
    )
    assert result.capability_token == "cap-token"
    assert poll_count["value"] == 2


@pytest.mark.asyncio
async def test_fund_with_x402_pending_error_after_max_attempts() -> None:
    pending = _fund_result(status_code=202)

    async def fund(**kwargs: object) -> FundIntentResult:
        return pending

    with pytest.raises(PaybondX402FundingPendingError):
        await execute_fund_with_x402(
            intent_id=INTENT_ID,
            recognition_proof={"nonce": "initial"},
            sign_payment=async_sign_payment_unused,
            issue_recognition_proof=async_issue_recognition_proof_poll,
            poll_options=X402FundPollOptions(max_attempts=2, interval_ms=0),
            fund=fund,
        )


async def async_issue_recognition_proof_poll(_env: FundRequestEnvelope) -> dict[str, str]:
    return {"nonce": "poll"}


@pytest.mark.asyncio
async def test_fund_with_x402_failed_error_without_payment_required() -> None:
    challenge = _fund_result(status_code=402)

    with pytest.raises(PaybondX402FundingFailedError):
        await execute_fund_with_x402(
            intent_id=INTENT_ID,
            recognition_proof={"nonce": "initial"},
            sign_payment=async_sign_payment_returns_unused,
            issue_recognition_proof=async_issue_recognition_proof_poll,
            fund=async_fund_return(challenge),
        )


async def async_sign_payment_returns_unused(_challenge: str) -> str:
    return "unused"


@pytest.mark.asyncio
async def test_fund_with_x402_failed_error_on_authorization_failed() -> None:
    from paybond_kit.harbor import IntentFundingResult

    failed = _fund_result(
        status_code=202,
        funding=IntentFundingResult(
            settlement_rail="x402_usdc_base",
            harbor_fund_endpoint=f"/intents/{INTENT_ID}/fund",
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

    with pytest.raises(PaybondX402FundingFailedError):
        await execute_fund_with_x402(
            intent_id=INTENT_ID,
            recognition_proof={"nonce": "initial"},
            sign_payment=async_sign_payment_unused,
            issue_recognition_proof=async_issue_recognition_proof_unused,
            fund=async_fund_return(failed),
        )


async def async_sign_payment_unused(_challenge: str) -> str:
    raise AssertionError("sign_payment should not run")


async def async_issue_recognition_proof_unused(_env: FundRequestEnvelope) -> dict[str, str]:
    raise AssertionError("issue_recognition_proof should not run")


def async_fund_return(result: FundIntentResult):
    async def fund(**kwargs: object) -> FundIntentResult:
        return result

    return fund
