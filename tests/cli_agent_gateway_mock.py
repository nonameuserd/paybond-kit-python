from __future__ import annotations

import json
from typing import Any, Literal

import pytest

SMOKE_INTENT_ID = "00000000-0000-4000-8000-000000000001"
ATTACH_INTENT_ID = "550e8400-e29b-41d4-a716-446655440000"
SMOKE_AUDIT_ID = "00000000-0000-4000-8000-000000000002"
SMOKE_DECISION_ID = "00000000-0000-4000-8000-000000000003"

PRODUCTION_ATTACH_SEEDS = {
    "payee_did": "did:web:vendor.example",
    "payee_signing_seed_hex": "01" * 32,
    "agent_recognition_key_id": "kid-1",
    "agent_recognition_signing_seed_hex": "02" * 32,
}

SANDBOX_RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

LIVE_RAW_KEY = "paybond_sk_live_fixture_not_a_real_secret_for_tests_only"


class FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self) -> dict[str, Any]:
        return self._payload


def install_agent_gateway_mock(
    monkeypatch: pytest.MonkeyPatch,
    *,
    allow_verify: bool = True,
    deny_message: str = "spend denied",
    environment: Literal["sandbox", "live"] = "sandbox",
) -> None:
    import httpx

    tenant_id = "tenant-live" if environment == "live" else "tenant-sandbox"

    async def fake_request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:  # type: ignore[no-untyped-def]
        _ = self, method
        if url.endswith("/v1/auth/principal"):
            return FakeResponse(
                {
                    "tenant_id": tenant_id,
                    "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "environment": environment,
                    "service_account_role": "operator",
                }
            )
        if f"/harbor/operator/v1/intents/{ATTACH_INTENT_ID}" in url:
            return FakeResponse(
                {
                    "tenant_id": tenant_id,
                    "intent_id": ATTACH_INTENT_ID,
                    "allowed_tools": ["paid-tool"],
                }
            )
        if url.endswith("/v1/sandbox/guardrails/bootstrap"):
            body = kwargs.get("json") or {}
            return FakeResponse(
                {
                    "tenant_id": "tenant-sandbox",
                    "intent_id": SMOKE_INTENT_ID,
                    "capability_token": "cap-smoke-1",
                    "operation": body.get("operation"),
                    "requested_spend_cents": body.get("requested_spend_cents"),
                    "sandbox_lifecycle_status": "funded",
                }
            )
        if url.endswith("/verify"):
            if not allow_verify:
                return FakeResponse(
                    {
                        "allow": False,
                        "tenant": tenant_id,
                        "intent_id": SMOKE_INTENT_ID,
                        "audit_id": SMOKE_AUDIT_ID,
                        "decision_id": SMOKE_DECISION_ID,
                        "message": deny_message,
                    }
                )
            return FakeResponse(
                {
                    "allow": True,
                    "tenant": tenant_id,
                    "intent_id": SMOKE_INTENT_ID,
                    "audit_id": SMOKE_AUDIT_ID,
                    "decision_id": SMOKE_DECISION_ID,
                }
            )
        if url.endswith(f"/v1/sandbox/guardrails/{SMOKE_INTENT_ID}/evidence"):
            body = kwargs.get("json") or {}
            return FakeResponse(
                {
                    "tenant_id": "tenant-sandbox",
                    "intent_id": SMOKE_INTENT_ID,
                    "operation": body.get("operation", "paid-tool"),
                    "requested_spend_cents": body.get("requested_spend_cents", 100),
                    "sandbox_lifecycle_status": "released",
                    "predicate_passed": True,
                }
            )
        if "/v1/spend/decisions/" in url and url.endswith("/complete"):
            return FakeResponse({})
        return FakeResponse({}, status_code=404)

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)
