"""Deterministic x402 ``/fund`` sequence for WireMock and offline dev gateway mocks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

X402_DEV_WIREMOCK_INTENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
X402_DEV_WIREMOCK_TENANT_ID = "dry-run-tenant"

X402_DEV_PAYMENT_REQUIRED = (
    '{"asset":"usdc","network":"base","amount":"0.02",'
    '"payTo":"0xabc1230000000000000000000000000000000000"}'
)

X402_DEV_CAPABILITY_TOKEN = "cap-x402-dev-mock-1"

X402FundMockPhase = Literal["challenge", "pending", "funded"]


@dataclass(frozen=True)
class X402FundMockResponse:
    status: int
    headers: dict[str, str]
    body: dict[str, Any]
    phase: X402FundMockPhase


def _funding_base(intent_id: str) -> dict[str, Any]:
    return {
        "settlement_rail": "x402_usdc_base",
        "harbor_fund_endpoint": f"/harbor/intents/{intent_id}/fund",
        "payment_session_id": f"paymentSession_{intent_id}",
        "payment_url": f"https://pay.coinbase.com/payment-sessions/paymentSession_{intent_id}",
        "asset": "usdc",
        "network": "base",
        "capture_expires_at": "2027-12-31T23:59:59Z",
        "refund_expires_at": "2028-01-31T23:59:59Z",
    }


def _intent_shell(intent_id: str, tenant_id: str, extra: dict[str, Any]) -> dict[str, Any]:
    return {
        "intent_id": intent_id,
        "tenant": tenant_id,
        "settlement_rail": "x402_usdc_base",
        "currency": "usd",
        "amount_cents": 2000,
        **extra,
    }


def build_x402_fund_challenge_body(intent_id: str, tenant_id: str) -> dict[str, Any]:
    return _intent_shell(
        intent_id,
        tenant_id,
        {
            "state": "open",
            "funded": False,
            "funding": {**_funding_base(intent_id), "status": "created"},
        },
    )


def build_x402_fund_pending_body(intent_id: str, tenant_id: str) -> dict[str, Any]:
    return _intent_shell(
        intent_id,
        tenant_id,
        {
            "state": "open",
            "funded": False,
            "funding": {
                **_funding_base(intent_id),
                "status": "authorization_pending",
                "authorization_id": f"auth_{intent_id}",
                "source_address": "0xsource0000000000000000000000000000000001",
            },
        },
    )


def build_x402_fund_success_body(
    intent_id: str,
    tenant_id: str,
    capability_token: str = X402_DEV_CAPABILITY_TOKEN,
) -> dict[str, Any]:
    return _intent_shell(
        intent_id,
        tenant_id,
        {
            "state": "funded",
            "funded": True,
            "capability_token": capability_token,
            "funding": {
                **_funding_base(intent_id),
                "status": "authorization_succeeded",
                "authorization_id": f"auth_{intent_id}",
                "source_address": "0xsource0000000000000000000000000000000001",
            },
        },
    )


class X402FundStateMachine:
    """In-memory x402 fund sequence keyed by intent id."""

    def __init__(self) -> None:
        self._phases: dict[str, X402FundMockPhase] = {}

    def reset(self, intent_id: str | None = None) -> None:
        if intent_id is None:
            self._phases.clear()
            return
        self._phases.pop(intent_id, None)

    def next(
        self,
        intent_id: str,
        tenant_id: str,
        payment_signature: str | None,
    ) -> X402FundMockResponse | None:
        trimmed_intent = intent_id.strip()
        if not trimmed_intent:
            return None

        phase = self._phases.get(trimmed_intent, "challenge")
        has_signature = bool((payment_signature or "").strip())

        if phase == "challenge" and not has_signature:
            self._phases[trimmed_intent] = "pending"
            return X402FundMockResponse(
                status=402,
                headers={
                    "content-type": "application/json",
                    "payment-required": X402_DEV_PAYMENT_REQUIRED,
                },
                body=build_x402_fund_challenge_body(trimmed_intent, tenant_id),
                phase="challenge",
            )

        if phase == "pending" and has_signature:
            self._phases[trimmed_intent] = "funded"
            return X402FundMockResponse(
                status=202,
                headers={
                    "content-type": "application/json",
                    "payment-response": "simulated-x402-payment-response",
                },
                body=build_x402_fund_pending_body(trimmed_intent, tenant_id),
                phase="pending",
            )

        if phase == "funded" and has_signature:
            return X402FundMockResponse(
                status=200,
                headers={
                    "content-type": "application/json",
                    "payment-response": "simulated-x402-payment-response",
                },
                body=build_x402_fund_success_body(trimmed_intent, tenant_id),
                phase="funded",
            )

        return None
