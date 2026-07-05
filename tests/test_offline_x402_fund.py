"""Tests for offline x402 fund state machine and gateway mock."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from paybond_kit.dev.offline_gateway import OFFLINE_DEV_TENANT_ID, create_offline_dev_gateway_transport
from paybond_kit.dev.x402_fund_mock import (
    X402FundStateMachine,
    X402_DEV_CAPABILITY_TOKEN,
    X402_DEV_PAYMENT_REQUIRED,
    X402_DEV_WIREMOCK_INTENT_ID,
    X402_DEV_WIREMOCK_TENANT_ID,
)
from paybond_kit.x402_funding import X402FundPollOptions, execute_fund_with_x402


INTENT_ID = X402_DEV_WIREMOCK_INTENT_ID


def test_x402_fund_state_machine_sequence() -> None:
    machine = X402FundStateMachine()

    challenge = machine.next(INTENT_ID, X402_DEV_WIREMOCK_TENANT_ID, None)
    assert challenge is not None
    assert challenge.status == 402
    assert challenge.headers["payment-required"] == X402_DEV_PAYMENT_REQUIRED
    assert challenge.body["funded"] is False

    pending = machine.next(INTENT_ID, X402_DEV_WIREMOCK_TENANT_ID, "signed-payment")
    assert pending is not None
    assert pending.status == 202
    assert pending.headers["payment-response"]
    assert pending.body["funding"]["status"] == "authorization_pending"

    funded = machine.next(INTENT_ID, X402_DEV_WIREMOCK_TENANT_ID, "signed-payment")
    assert funded is not None
    assert funded.status == 200
    assert funded.body["capability_token"] == X402_DEV_CAPABILITY_TOKEN
    assert funded.body["funded"] is True


def test_wiremock_x402_mappings_define_scenario_chain() -> None:
    mappings_dir = (
        Path(__file__).resolve().parents[1]
        / "src/paybond_kit/data/dev/wiremock/mappings"
    )
    files = {
        "challenge": mappings_dir / "11-x402-fund-challenge.json",
        "pending": mappings_dir / "12-x402-fund-pending.json",
        "success": mappings_dir / "13-x402-fund-success.json",
    }
    for path in files.values():
        assert path.is_file(), f"missing WireMock mapping: {path}"

    challenge = json.loads(files["challenge"].read_text(encoding="utf-8"))
    pending = json.loads(files["pending"].read_text(encoding="utf-8"))
    success = json.loads(files["success"].read_text(encoding="utf-8"))

    assert challenge["scenarioName"] == "x402-fund-sequence"
    assert challenge["requiredScenarioState"] == "Started"
    assert challenge["newScenarioState"] == "challenged"
    assert challenge["response"]["status"] == 402

    assert pending["requiredScenarioState"] == "challenged"
    assert pending["newScenarioState"] == "pending"
    assert pending["response"]["status"] == 202

    assert success["requiredScenarioState"] == "pending"
    assert success["newScenarioState"] == "funded"
    assert success["response"]["status"] == 200
    assert success["response"]["jsonBody"]["capability_token"] == X402_DEV_CAPABILITY_TOKEN


@pytest.mark.asyncio
async def test_offline_gateway_supports_fund_with_x402() -> None:
    import httpx

    transport = create_offline_dev_gateway_transport()
    call_count = 0

    async def fund(**kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        payment_signature = kwargs.get("payment_signature")
        headers = {
            "x-tenant-id": OFFLINE_DEV_TENANT_ID,
            "x-paybond-agent-recognition-proof": json.dumps(kwargs["recognition_proof"]),
        }
        if payment_signature:
            headers["payment-signature"] = str(payment_signature)
        async with httpx.AsyncClient(transport=transport, base_url="https://offline.dev") as client:
            response = await client.post(
                f"/harbor/intents/{INTENT_ID}/fund",
                json={},
                headers=headers,
            )
        body = response.json()
        from paybond_kit.harbor import _parse_fund_intent_response

        return _parse_fund_intent_response(
            body,
            status_code=response.status_code,
            payment_required=response.headers.get("payment-required"),
            payment_response=response.headers.get("payment-response"),
            tenant_id=OFFLINE_DEV_TENANT_ID,
            intent_id=uuid.UUID(INTENT_ID),
            source="gateway",
            url=str(response.request.url),
            body_text=response.text,
        )

    signed: list[str] = []

    async def sign_payment(challenge: str) -> str:
        assert challenge == X402_DEV_PAYMENT_REQUIRED
        signed.append(challenge)
        return "signed-payment"

    async def issue_recognition_proof(_envelope: object) -> dict[str, str]:
        return {"proof": "fresh"}

    result = await execute_fund_with_x402(
        intent_id=uuid.UUID(INTENT_ID),
        recognition_proof={"proof": "initial"},
        sign_payment=sign_payment,
        issue_recognition_proof=issue_recognition_proof,
        poll_options=X402FundPollOptions(max_attempts=3, interval_ms=0),
        fund=fund,
    )

    assert result.status_code == 200
    assert result.capability_token == X402_DEV_CAPABILITY_TOKEN
    assert call_count == 3
    assert signed == [X402_DEV_PAYMENT_REQUIRED]
