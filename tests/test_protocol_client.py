from __future__ import annotations

import httpx
import pytest
import respx

from paybond_kit.protocol import GatewayProtocolClient, ProtocolHttpError


def test_protocol_http_error_parses_explicit_gateway_codes() -> None:
    for code in (
        "unregistered_key",
        "revoked_key",
        "mandate_agent_key_mismatch",
        "protocol_binding_mismatch",
    ):
        err = ProtocolHttpError(
            "protocol failure",
            status_code=409,
            url="https://gateway.test/protocol/v2/mandates",
            body_text=f'{{"error":"{code}","message":"{code} detail"}}',
        )
        assert err.error_code == code
        assert err.error_message == f"{code} detail"


@pytest.mark.asyncio
@respx.mock
async def test_import_agent_mandate_v1_checks_tenant_binding() -> None:
    def handle_import(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-tenant-id"] == "tenant-a"
        assert request.headers["authorization"] == "Bearer gateway-token"
        return httpx.Response(
            200,
            json={
                "valid": True,
                "intent_id": "550e8400-e29b-41d4-a716-446655440000",
                "mandate_digest_sha256_hex": "ab" * 32,
                "mandate": {
                    "schema_version": 1,
                    "kind": "paybond.agent_mandate_v1",
                    "authorization": {
                        "kind": "principal",
                        "tenant_id": "tenant-a",
                        "principal_subject": "user-123",
                        "principal_type": "user",
                    },
                    "agent": {"subject": "did:agent:test"},
                    "allowed_actions": ["intent.create"],
                    "allowed_tools": ["travel.book"],
                    "spend_ceiling": {"amount_minor": 1000, "currency": "usd"},
                    "settlement": {
                        "default_rail": "stripe_connect",
                        "allowed_rails": ["stripe_connect"],
                    },
                    "constraint": {"kind": "policy", "id": "travel_hold"},
                    "expires_at": "2030-01-01T00:00:00Z",
                    "nonce": "nonce-123",
                    "human_presence_mode": "human_present",
                },
                "authorization_receipt": {
                    "schema_version": 1,
                    "kind": "paybond.protocol_authorization_receipt_v1",
                    "receipt_version": "1",
                    "receipt_id": "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
                    "issued_at": "2030-01-01T00:00:00Z",
                    "status": "authorized",
                    "intent_id": "550e8400-e29b-41d4-a716-446655440000",
                    "tenant_id": "tenant-a",
                    "verifier_id": "paybond-gateway",
                    "transport_binding": {"source_protocol": "ap2"},
                    "mandate_digest_sha256_hex": "ab" * 32,
                    "imported_mandate_signing_public_key_ed25519_hex": "cd" * 32,
                    "authorization": {
                        "kind": "principal",
                        "tenant_id": "tenant-a",
                        "principal_subject": "user-123",
                        "principal_type": "user",
                    },
                    "agent": {"subject": "did:agent:test"},
                    "allowed_actions": ["intent.create"],
                    "allowed_tools": ["travel.book"],
                    "spend_ceiling": {"amount_minor": 1000, "currency": "usd"},
                    "settlement": {
                        "default_rail": "stripe_connect",
                        "allowed_rails": ["stripe_connect"],
                    },
                    "constraint": {"kind": "policy", "id": "travel_hold"},
                    "expires_at": "2030-01-01T00:00:00Z",
                    "nonce": "nonce-123",
                    "human_presence_mode": "human_present",
                    "signing_algorithm": "ed25519-sha256-json-v1",
                    "message_digest_sha256_hex": "ef" * 32,
                    "signing_public_key_ed25519_hex": "01" * 32,
                    "ed25519_signature_hex": "02" * 64,
                },
            },
        )

    respx.post("https://gateway.test/protocol/v2/mandates").mock(side_effect=handle_import)

    client = GatewayProtocolClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token="gateway-token",
    )
    try:
        result = await client.import_agent_mandate_v1(
            signed_mandate={
                "schema_version": 1,
                "kind": "paybond.agent_mandate_v1",
                "authorization": {
                    "kind": "principal",
                    "tenant_id": "tenant-a",
                    "principal_subject": "user-123",
                    "principal_type": "user",
                },
                "agent": {"subject": "did:agent:test"},
                "allowed_actions": ["intent.create"],
                "allowed_tools": ["travel.book"],
                "spend_ceiling": {"amount_minor": 1000, "currency": "usd"},
                "settlement": {
                    "default_rail": "stripe_connect",
                    "allowed_rails": ["stripe_connect"],
                },
                "constraint": {"kind": "policy", "id": "travel_hold"},
                "expires_at": "2030-01-01T00:00:00Z",
                "nonce": "nonce-123",
                "human_presence_mode": "human_present",
                "signing_algorithm": "ed25519-sha256-json-v1",
                "message_digest_sha256_hex": "ab" * 32,
                "signing_public_key_ed25519_hex": "cd" * 32,
                "ed25519_signature_hex": "ef" * 64,
            },
            intent_id="550e8400-e29b-41d4-a716-446655440000",
            recognition_proof={
                "key_id": "kid-1",
                "issued_at": "2030-01-01T00:00:00Z",
                "expires_at": "2030-01-01T00:05:00Z",
                "nonce": "nonce-proof",
                "purpose": "protocol.mandate.import",
                "verifier_context": {
                    "tenant_id": "tenant-a",
                    "verifier_id": "paybond-gateway",
                },
                "request_envelope": {
                    "method": "POST",
                    "path": "/protocol/v2/mandates",
                    "body_digest_sha256_hex": "01" * 32,
                },
            },
        )
        assert result["valid"] is True
        assert result["authorization_receipt"]["kind"] == "paybond.protocol_authorization_receipt_v1"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_get_settlement_receipt_v1_checks_tenant_binding() -> None:
    respx.get(
        "https://gateway.test/protocol/v2/receipts/550e8400-e29b-41d4-a716-446655440000"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "kind": "paybond.protocol_settlement_receipt_v1",
                "receipt_version": "1",
                "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
                "issued_at": "2030-01-01T00:00:00Z",
                "intent_id": "550e8400-e29b-41d4-a716-446655440000",
                "tenant_id": "tenant-a",
                "verifier_id": "paybond-gateway",
                "transport_binding": {"source_protocol": "ap2"},
                "authorization_receipt_id": "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
                "mandate_digest_sha256_hex": "ab" * 32,
                "harbor_state": "released",
                "predicate_passed": True,
                "settlement_rail": "stripe_connect",
                "settlement_mode": "managed",
                "principal_did": "did:principal:alice",
                "payee_did": "did:payee:hotel",
                "currency": "usd",
                "amount_cents": 250000,
                "terminal_observed_at": "2030-01-01T00:00:00Z",
                "signing_algorithm": "ed25519-sha256-json-v1",
                "message_digest_sha256_hex": "ef" * 32,
                "signing_public_key_ed25519_hex": "01" * 32,
                "ed25519_signature_hex": "02" * 64,
            },
        )
    )

    client = GatewayProtocolClient("https://gateway.test", "tenant-a")
    try:
        receipt = await client.get_settlement_receipt_v1(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        assert receipt["kind"] == "paybond.protocol_settlement_receipt_v1"
        assert receipt["harbor_state"] == "released"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_verify_protocol_receipt_v1_raises_protocol_http_error() -> None:
    respx.post("https://gateway.test/protocol/v2/receipts/verify").mock(
        return_value=httpx.Response(
            409,
            json={
                "error": "protocol_binding_mismatch",
                "message": "harbor mandate digest does not match the stored gateway import binding",
            },
        )
    )

    client = GatewayProtocolClient("https://gateway.test", "tenant-a")
    try:
        with pytest.raises(ProtocolHttpError, match="protocol_binding_mismatch") as exc_info:
            await client.verify_protocol_receipt_v1({"kind": "bad"})
        assert exc_info.value.error_code == "protocol_binding_mismatch"
        assert "harbor mandate digest" in (exc_info.value.error_message or "")
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_create_harbor_intent_sets_recognition_proof_header() -> None:
    captured: dict[str, str] = {}

    def handle_create(request: httpx.Request) -> httpx.Response:
        captured["recognition"] = request.headers["x-paybond-agent-recognition-proof"]
        captured["idempotency"] = request.headers["idempotency-key"]
        return httpx.Response(
            200,
            json={
                "intent_id": "intent-123",
                "state": "open",
            },
        )

    respx.post("https://gateway.test/harbor/intents").mock(side_effect=handle_create)

    client = GatewayProtocolClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token="gateway-token",
    )
    try:
        result = await client.create_harbor_intent(
            body={
                "intent_id": "intent-123",
                "principal_did": "did:web:example.com#principal",
            },
            recognition_proof={
                "key_id": "kid-1",
                "issued_at": "2030-01-01T00:00:00Z",
                "expires_at": "2030-01-01T00:05:00Z",
                "nonce": "nonce-proof",
                "purpose": "harbor.intent.create",
                "verifier_context": {
                    "tenant_id": "tenant-a",
                    "verifier_id": "paybond-gateway",
                },
                "request_envelope": {
                    "method": "POST",
                    "path": "/harbor/intents",
                    "body_digest_sha256_hex": "01" * 32,
                },
            },
            idempotency_key="intent:intent-123",
        )
        assert result["intent_id"] == "intent-123"
        assert captured["recognition"]
        assert captured["idempotency"] == "intent:intent-123"
    finally:
        await client.aclose()
