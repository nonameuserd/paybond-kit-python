from __future__ import annotations

import uuid

import httpx
import pytest
import respx

from paybond_kit.paybond import Paybond, PaybondIntents


class _UnusedHarbor:
    async def create_intent(self, body: dict[str, object], *, idempotency_key: str | None = None) -> dict[str, object]:
        raise AssertionError("create_intent should not be called for invalid settlement_rail")


@pytest.mark.asyncio
async def test_paybond_intents_create_rejects_unknown_settlement_rail() -> None:
    intents = PaybondIntents(_UnusedHarbor(), "tenant-a")

    with pytest.raises(ValueError, match="settlement_rail must be one of"):
        await intents.create(
            principal_did="did:web:example.com#principal",
            principal_signing_seed=b"\x01" * 32,
            payee_did="did:web:example.com#payee",
            budget={"currency": "usd", "max_spend_usd": 10},
            predicate={"version": 1, "root": {"op": "true"}},
            currency="usd",
            amount_cents=1000,
            evidence_schema={"type": "object"},
            deadline_rfc3339="2030-01-01T00:00:00Z",
            allowed_tools=["payments.capture"],
            settlement_rail="bogus",
            recognition_proof={},
        )


@pytest.mark.asyncio
@respx.mock
async def test_paybond_open_defaults_to_hosted_gateway_with_api_key_only() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    api_key = "paybond_sk_" + "a" * 32 + "_" + "b" * 64

    principal_route = respx.get("https://api.paybond.ai/v1/auth/principal").mock(
        return_value=httpx.Response(
            200,
            json={"tenant_id": "realm-z", "environment": "sandbox"},
        )
    )
    verify_route = respx.post("https://api.paybond.ai/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "realm-z",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
            },
        )
    )

    paybond = await Paybond.open(api_key=api_key, expected_environment="sandbox")
    try:
        assert paybond.harbor.tenant_id == "realm-z"
        result = await paybond.harbor.verify_capability(
            intent_id=intent_id,
            token="Cg==",
            operation="demo.tool",
        )
        assert result.allow is True
        assert principal_route.calls[0].request.headers["authorization"] == f"Bearer {api_key}"
        assert verify_route.calls[0].request.headers["authorization"] == f"Bearer {api_key}"
        assert verify_route.calls[0].request.headers["x-tenant-id"] == "realm-z"
    finally:
        await paybond.aclose()
