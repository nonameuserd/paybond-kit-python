from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest
import respx
from mcp.server.fastmcp.exceptions import ToolError

from paybond_kit.mcp_server import (
    DEFAULT_RECOGNITION_VERIFIER_ID,
    PaybondMCPSettings,
    build_mcp_server,
)


def _api_key() -> str:
    return "paybond_sk_" + "a" * 32 + "_" + "b" * 64


async def _close_server(server: object) -> None:
    runtime = getattr(server, "_paybond_runtime", None)
    if runtime is not None:
        await runtime.aclose()


@pytest.mark.asyncio
async def test_gateway_only_server_exposes_gateway_first_mutation_tools() -> None:
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        tools = await server.list_tools()
        names = {tool.name for tool in tools}
        assert "paybond_get_a2a_agent_card" in names
        assert "paybond_get_principal" in names
        assert "paybond_get_signed_portfolio_artifact" in names
        assert "paybond_verify_agent_mandate_v1" in names
        assert "paybond_import_agent_mandate_v1" in names
        assert "paybond_get_settlement_receipt_v1" in names
        assert "paybond_verify_protocol_receipt_v1" in names
        assert "paybond_create_intent" in names
        assert "paybond_submit_evidence" in names
        assert "paybond_create_intent_legacy" not in names
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_get_principal_tool_returns_gateway_principal() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(
            200,
            json={
                "tenant_id": "tenant-a",
                "roles": ["operator"],
                "subject": "service-account-1",
            },
        )
    )
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        _, structured = await server.call_tool("paybond_get_principal", {})
        assert structured["tenant_id"] == "tenant-a"
        assert structured["roles"] == ["operator"]
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_get_a2a_agent_card_tool_returns_published_document() -> None:
    respx.get("https://gateway.test/.well-known/agent-card.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "Paybond Protocol Trust Delegation",
                "description": "discovery",
                "supportedInterfaces": [],
                "version": "2.0.0-preview",
                "capabilities": {},
                "defaultInputModes": ["application/json"],
                "defaultOutputModes": ["application/json"],
                "skills": [],
            },
        )
    )
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        _, structured = await server.call_tool("paybond_get_a2a_agent_card", {})
        assert structured["name"] == "Paybond Protocol Trust Delegation"
        assert structured["version"] == "2.0.0-preview"
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_get_signed_portfolio_artifact_tool_returns_portable_document() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )
    respx.get("https://gateway.test/signal/v1/portfolio/signed-export").mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "artifact_version": "1",
                "kind": "paybond.signal.portfolio_snapshot",
                "tenant_id": "tenant-a",
                "score_model_version": "1.0",
                "scoring_model": "paybond.signal.v1",
                "checkpoint_last_ledger_seq": 55,
                "operators": [],
                "signing_algorithm": "ed25519-sha256-json-v1",
                "message_digest_hex": "ab" * 32,
                "signing_public_key_hex": "cd" * 32,
                "signature_hex": "ef" * 64,
            },
        )
    )
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        _, structured = await server.call_tool("paybond_get_signed_portfolio_artifact", {})
        assert structured["tenant_id"] == "tenant-a"
        assert structured["kind"] == "paybond.signal.portfolio_snapshot"
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_verify_capability_tool_rejects_tenant_mismatch() -> None:
    intent_id = uuid4()
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )
    respx.post("https://gateway.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(uuid4()),
                "tenant": "other-tenant",
                "intent_id": str(intent_id),
            },
        )
    )
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        with pytest.raises(ToolError, match="tenant mismatch"):
            await server.call_tool(
                "paybond_verify_capability",
                {
                    "intent_id": str(intent_id),
                    "token": "cap-token",
                    "operation": "travel.book_hotel",
                    "requested_spend_cents": 100,
                },
            )
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_recognition_verify_defaults_verifier_context() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )

    captured: dict[str, object] = {}

    def handle_verify(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "valid": True,
                "proof": {
                    "nonce": "nonce-123",
                },
            },
        )

    respx.post("https://gateway.test/protocol/v2/recognition/verify").mock(
        side_effect=handle_verify
    )
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        _, structured = await server.call_tool(
            "paybond_verify_agent_recognition_proof_v1",
            {
                "proof": {"nonce": "nonce-123"},
                "expected_purpose": "harbor.policy.rollback",
                "expected_request": {
                    "method": "POST",
                    "path": "/harbor/policy/v1/rollback",
                    "body_digest_sha256_hex": "ab" * 32,
                },
            },
        )
        assert structured["valid"] is True
        assert captured["body"] == {
            "proof": {"nonce": "nonce-123"},
            "expected_purpose": "harbor.policy.rollback",
            "expected_verifier": {
                "tenant_id": "tenant-a",
                "verifier_id": DEFAULT_RECOGNITION_VERIFIER_ID,
            },
            "expected_request": {
                "method": "POST",
                "path": "/harbor/policy/v1/rollback",
                "body_digest_sha256_hex": "ab" * 32,
            },
        }
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_create_intent_tool_uses_gateway_harbor_path() -> None:
    captured: dict[str, object] = {}

    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )

    def handle_create(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers.get("authorization")
        captured["tenant"] = request.headers.get("x-tenant-id")
        captured["recognition"] = request.headers.get("x-paybond-agent-recognition-proof")
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "intent_id": "intent-123",
                "state": "open",
            },
        )

    respx.post("https://gateway.test/harbor/intents").mock(side_effect=handle_create)
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        _, structured = await server.call_tool(
            "paybond_create_intent",
            {
                "body": {
                    "intent_id": "intent-123",
                    "principal_did": "did:web:example.com#principal",
                },
                "recognition_proof": {
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
                        "body_digest_sha256_hex": "ab" * 32,
                    },
                },
                "idempotency_key": "intent:intent-123",
            },
        )
        assert structured == {
            "intent_id": "intent-123",
            "state": "open",
        }
        assert captured["authorization"] == f"Bearer {_api_key()}"
        assert captured["tenant"] == "tenant-a"
        assert captured["recognition"]
        assert captured["body"] == {
            "intent_id": "intent-123",
            "principal_did": "did:web:example.com#principal",
        }
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_import_agent_mandate_tool_uses_protocol_route() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )
    respx.post("https://gateway.test/protocol/v2/mandates").mock(
        return_value=httpx.Response(
            200,
            json={
                "valid": True,
                "intent_id": "550e8400-e29b-41d4-a716-446655440000",
                "mandate": {"authorization": {"tenant_id": "tenant-a"}},
                "authorization_receipt": {
                    "kind": "paybond.protocol_authorization_receipt_v1"
                },
            },
        )
    )
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        _, structured = await server.call_tool(
            "paybond_import_agent_mandate_v1",
            {
                "signed_mandate": {"kind": "paybond.agent_mandate_v1"},
                "intent_id": "550e8400-e29b-41d4-a716-446655440000",
                "recognition_proof": {
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
                        "body_digest_sha256_hex": "ab" * 32,
                    },
                },
            },
        )
        assert structured["valid"] is True
        assert (
            structured["authorization_receipt"]["kind"]
            == "paybond.protocol_authorization_receipt_v1"
        )
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_import_agent_mandate_tool_surfaces_explicit_protocol_error_codes() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )
    respx.post("https://gateway.test/protocol/v2/mandates").mock(
        return_value=httpx.Response(
            409,
            json={
                "error": "mandate_agent_key_mismatch",
                "message": "mandate.agent.key_id must match recognition_proof.key_id",
            },
        )
    )
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        with pytest.raises(ToolError, match="mandate_agent_key_mismatch"):
            await server.call_tool(
                "paybond_import_agent_mandate_v1",
                {
                    "signed_mandate": {"kind": "paybond.agent_mandate_v1"},
                    "intent_id": "550e8400-e29b-41d4-a716-446655440000",
                    "recognition_proof": {
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
                            "body_digest_sha256_hex": "ab" * 32,
                        },
                    },
                },
            )
    finally:
        await _close_server(server)
