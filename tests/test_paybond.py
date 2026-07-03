from __future__ import annotations

import json
import uuid
from typing import cast

import httpx
import pytest
import respx

from paybond_kit.harbor import HarborClient, SettlementRail, TenantBindingError
from paybond_kit.paybond import Paybond, PaybondIntents


class _UnusedHarbor:
    async def create_intent(self, body: dict[str, object], *, idempotency_key: str | None = None) -> dict[str, object]:
        raise AssertionError("create_intent should not be called for invalid settlement_rail")


@pytest.mark.asyncio
async def test_paybond_intents_create_rejects_unknown_settlement_rail() -> None:
    intents = PaybondIntents(cast(HarborClient, _UnusedHarbor()), "tenant-a")

    with pytest.raises(ValueError, match="settlement_rail must be one of"):
        await intents.create(
            principal_did="did:web:example.com#principal",
            principal_signing_seed=b"\x01" * 32,
            payee_did="did:web:example.com#payee",
            payee_signing_seed=b"\x02" * 32,
            budget={"currency": "usd", "max_spend_usd": 10},
            predicate={"version": 1, "root": {"op": "true"}},
            currency="usd",
            amount_cents=1000,
            evidence_schema={"type": "object"},
            deadline_rfc3339="2030-01-01T00:00:00Z",
            allowed_tools=["payments.capture"],
            settlement_rail=cast(SettlementRail, "bogus"),
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


@pytest.mark.asyncio
@respx.mock
async def test_paybond_guardrails_bootstrap_and_evidence_derive_tenant_from_bearer() -> None:
    intent_id = uuid.uuid4()
    api_key = "paybond_sk_" + "a" * 32 + "_" + "b" * 64
    captured: list[httpx.Request] = []

    respx.get("https://api.paybond.ai/v1/auth/principal").mock(
        return_value=httpx.Response(
            200,
            json={"tenant_id": "realm-z", "environment": "sandbox"},
        )
    )

    def handle_bootstrap(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        assert request.headers.get("authorization") == f"Bearer {api_key}"
        assert request.headers.get("x-tenant-id") is None
        assert json.loads(request.content) == {
            "operation": "vendor.lookup",
            "requested_spend_cents": 250,
        }
        return httpx.Response(
            201,
            json={
                "tenant_id": "realm-z",
                "intent_id": str(intent_id),
                "capability_token": "sandbox-cap-token",
                "operation": "vendor.lookup",
                "requested_spend_cents": 250,
                "currency": "usd",
                "settlement_rail": "stripe_connect",
                "settlement_mode": "simulated",
                "sandbox_lifecycle_status": "funded",
            },
        )

    def handle_evidence(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        assert request.headers.get("authorization") == f"Bearer {api_key}"
        assert request.headers.get("x-tenant-id") is None
        assert json.loads(request.content) == {
            "payload": {"status": "completed"},
            "operation": "vendor.lookup",
            "requested_spend_cents": 250,
        }
        return httpx.Response(
            202,
            json={
                "tenant_id": "realm-z",
                "intent_id": str(intent_id),
                "operation": "vendor.lookup",
                "requested_spend_cents": 250,
                "settlement_rail": "stripe_connect",
                "settlement_mode": "simulated",
                "sandbox_lifecycle_status": "released",
                "predicate_passed": True,
            },
        )

    respx.post("https://api.paybond.ai/v1/sandbox/guardrails/bootstrap").mock(
        side_effect=handle_bootstrap
    )
    respx.post(f"https://api.paybond.ai/v1/sandbox/guardrails/{intent_id}/evidence").mock(
        side_effect=handle_evidence
    )

    paybond = await Paybond.open(api_key=api_key, expected_environment="sandbox")
    try:
        boot = await paybond.guardrails.bootstrap_sandbox(
            operation="vendor.lookup",
            requested_spend_cents=250,
        )
        assert boot.tenant_id == "realm-z"
        assert boot.intent_id == intent_id
        assert boot.capability_token == "sandbox-cap-token"
        assert boot.operation == "vendor.lookup"
        assert boot.requested_spend_cents == 250
        assert boot.sandbox_lifecycle_status == "funded"

        evidence = await paybond.guardrails.submit_sandbox_evidence(
            intent_id,
            {"status": "completed"},
            operation="vendor.lookup",
            requested_spend_cents=250,
        )
        assert evidence.tenant_id == "realm-z"
        assert evidence.intent_id == intent_id
        assert evidence.operation == "vendor.lookup"
        assert evidence.requested_spend_cents == 250
        assert evidence.sandbox_lifecycle_status == "released"
        assert len(captured) == 2
    finally:
        await paybond.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_paybond_guardrails_omits_template_id_when_completion_preset_set() -> None:
    api_key = "paybond_sk_" + "a" * 32 + "_" + "b" * 64
    intent_id = uuid.uuid4()
    captured: list[dict[str, object]] = []

    respx.get("https://api.paybond.ai/v1/auth/principal").mock(
        return_value=httpx.Response(
            200,
            json={"tenant_id": "realm-z", "environment": "sandbox"},
        )
    )

    def handle_bootstrap(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        captured.append(body)
        return httpx.Response(
            201,
            json={
                "tenant_id": "realm-z",
                "intent_id": str(intent_id),
                "capability_token": "sandbox-cap-token",
                "operation": "saas.provision_seat",
                "requested_spend_cents": 2900,
                "sandbox_lifecycle_status": "funded",
            },
        )

    respx.post("https://api.paybond.ai/v1/sandbox/guardrails/bootstrap").mock(
        side_effect=handle_bootstrap
    )

    paybond = await Paybond.open(api_key=api_key, expected_environment="sandbox")
    try:
        await paybond.guardrails.bootstrap_sandbox(
            operation="saas.provision_seat",
            requested_spend_cents=2900,
            completion_preset="cost_and_completion",
            template_id="completion_budget_v1",
            parameters={"max_spend_cents": 2900},
        )
        assert len(captured) == 1
        payload = captured[0]
        assert payload.get("completion_preset") == "cost_and_completion"
        assert "template_id" not in payload
        assert "parameters" not in payload
        assert "evidence_schema" not in payload
    finally:
        await paybond.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_paybond_guardrails_rejects_tenant_drift() -> None:
    api_key = "paybond_sk_" + "a" * 32 + "_" + "b" * 64
    respx.get("https://api.paybond.ai/v1/auth/principal").mock(
        return_value=httpx.Response(
            200,
            json={"tenant_id": "realm-z", "environment": "sandbox"},
        )
    )
    respx.post("https://api.paybond.ai/v1/sandbox/guardrails/bootstrap").mock(
        return_value=httpx.Response(
            201,
            json={
                "tenant_id": "other",
                "intent_id": str(uuid.uuid4()),
                "capability_token": "sandbox-cap-token",
                "operation": "vendor.lookup",
                "requested_spend_cents": 250,
                "sandbox_lifecycle_status": "funded",
            },
        )
    )

    paybond = await Paybond.open(api_key=api_key, expected_environment="sandbox")
    try:
        with pytest.raises(TenantBindingError, match="sandbox guardrail tenant mismatch"):
            await paybond.guardrails.bootstrap_sandbox(
                operation="vendor.lookup",
                requested_spend_cents=250,
            )
    finally:
        await paybond.aclose()
