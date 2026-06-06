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
        tool_by_name = {tool.name: tool for tool in tools}
        names = {tool.name for tool in tools}
        assert "paybond_get_a2a_agent_card" in names
        assert "paybond_get_principal" in names
        assert "paybond_get_signed_portfolio_artifact" in names
        assert "paybond_get_fraud_assessment" in names
        assert "paybond_get_fraud_metrics" in names
        assert "paybond_verify_agent_mandate_v1" in names
        assert "paybond_import_agent_mandate_v1" in names
        assert "paybond_get_settlement_receipt_v1" in names
        assert "paybond_verify_protocol_receipt_v1" in names
        assert "paybond_authorize_agent_spend" in names
        assert "paybond_bootstrap_sandbox_guardrail" in names
        assert "paybond_submit_sandbox_guardrail_evidence" in names
        assert "paybond_create_intent" in names
        assert "paybond_create_spend_intent" in names
        assert "paybond_submit_evidence" in names
        assert "paybond_submit_spend_evidence" in names
        assert "paybond_create_intent_legacy" not in names
        assert (
            "Provider-agnostic spend gate"
            in tool_by_name["paybond_authorize_agent_spend"].description
        )
        assert (
            "intent_id and capability_token"
            in tool_by_name["paybond_create_spend_intent"].description
        )
        assert (
            "paybond_authorize_agent_spend"
            in tool_by_name["paybond_fund_intent"].description
        )
        assert "sandbox-only" in tool_by_name["paybond_bootstrap_sandbox_guardrail"].description
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
async def test_get_fraud_assessment_tool_returns_operator_assessment() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )
    respx.get(
        "https://gateway.test/signal/v1/operators/did%3Aexample%3Aalpha/review-status"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "tenant-a",
                "operator_did": "did:example:alpha",
                "score_model_version": "1.0",
                "review_state": "open",
                "review_reasons": ["FRAUD_REVIEW"],
                "fraud_signals": [],
                "fraud_assessment": {
                    "fraud_signal_version": "1.0.4",
                    "level": "high",
                    "highest_severity": "high",
                    "review_priority": "high",
                    "signal_count": 1,
                    "severe_signal_count": 1,
                    "summary": "level=high",
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
            "paybond_get_fraud_assessment",
            {"operator_did": "did:example:alpha"},
        )
        structured = structured.get("result", structured)
        assert structured["tenant_id"] == "tenant-a"
        assert structured["operator_did"] == "did:example:alpha"
        assert structured["fraud_assessment"]["level"] == "high"
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_get_fraud_metrics_tool_returns_tenant_metrics() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )
    respx.get("https://gateway.test/signal/v1/fraud/metrics?window=7d").mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "tenant-a",
                "score_model_version": "1.0",
                "fraud_signal_version": "1.0.4",
                "window": "7d",
                "window_started_at": "2026-05-16T00:00:00Z",
                "window_ended_at": "2026-05-23T00:00:00Z",
                "generated_at": "2026-05-23T00:00:00Z",
                "flagged_operator_count": 2,
                "critical_signal_count": 1,
                "high_signal_count": 1,
                "elevated_signal_count": 0,
                "review_open_count": 1,
                "review_load_count": 1,
                "reviewed_count": 2,
                "labeled_outcome_count": 1,
                "confirmed_risk_count": 1,
                "false_positive_count": 0,
                "needs_more_evidence_count": 1,
                "review_precision_bps": 10000,
                "false_positive_rate_bps": 0,
                "confirmed_risk_rate_bps": 5000,
                "labeled_coverage_bps": 5000,
                "median_time_to_review_seconds": 300,
                "refund_burst_count": 1,
                "dispute_cluster_count": 0,
                "replay_appeal_abuse_count": 0,
                "critical_signal_hold_candidate_count": 1,
                "provider_signal_count": 0,
                "stale_label_gap_seconds": 900,
                "stale_signal_family_label_gap_count": 0,
                "backtest_summary": "precision_bps=10000",
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
            "paybond_get_fraud_metrics",
            {"window": "7d"},
        )
        assert structured["tenant_id"] == "tenant-a"
        assert structured["flagged_operator_count"] == 2
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
async def test_sandbox_guardrail_tools_call_sandbox_routes_without_tenant_headers() -> None:
    intent_id = uuid4()
    captured: dict[str, object] = {}

    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )

    def handle_bootstrap(request: httpx.Request) -> httpx.Response:
        captured["bootstrap_authorization"] = request.headers.get("authorization")
        captured["bootstrap_tenant"] = request.headers.get("x-tenant-id")
        captured["bootstrap_recognition"] = request.headers.get(
            "x-paybond-agent-recognition-proof"
        )
        captured["bootstrap_idempotency"] = request.headers.get("idempotency-key")
        captured["bootstrap_body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "tenant_id": "tenant-a",
                "intent_id": str(intent_id),
                "capability_token": "cap-sandbox",
                "operation": "vendor.lookup",
                "requested_spend_cents": 125,
                "sandbox_lifecycle_status": "funded",
                "settlement_rail": "simulator",
                "settlement_mode": "sandbox",
            },
        )

    def handle_evidence(request: httpx.Request) -> httpx.Response:
        captured["evidence_authorization"] = request.headers.get("authorization")
        captured["evidence_tenant"] = request.headers.get("x-tenant-id")
        captured["evidence_recognition"] = request.headers.get(
            "x-paybond-agent-recognition-proof"
        )
        captured["evidence_idempotency"] = request.headers.get("idempotency-key")
        captured["evidence_body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "tenant_id": "tenant-a",
                "intent_id": str(intent_id),
                "capability_token": "cap-sandbox",
                "operation": "vendor.lookup",
                "requested_spend_cents": 125,
                "sandbox_lifecycle_status": "evidence_submitted",
                "settlement_rail": "simulator",
                "settlement_mode": "sandbox",
                "predicate_passed": True,
                "payload_digest": "ab" * 32,
            },
        )

    respx.post("https://gateway.test/v1/sandbox/guardrails/bootstrap").mock(
        side_effect=handle_bootstrap
    )
    respx.post(f"https://gateway.test/v1/sandbox/guardrails/{intent_id}/evidence").mock(
        side_effect=handle_evidence
    )

    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        _, bootstrap = await server.call_tool(
            "paybond_bootstrap_sandbox_guardrail",
            {
                "operation": "vendor.lookup",
                "requested_spend_cents": 125,
                "currency": "USD",
                "evidence_schema": {"type": "object"},
                "metadata": {"demo": True},
                "idempotency_key": "sandbox-bootstrap-1",
            },
        )
        _, evidence = await server.call_tool(
            "paybond_submit_sandbox_guardrail_evidence",
            {
                "intent_id": str(intent_id),
                "payload": {"ok": True},
                "artifacts": ["artifact-1"],
                "operation": "vendor.lookup",
                "requested_spend_cents": 125,
                "metadata": {"demo": True},
                "idempotency_key": "sandbox-evidence-1",
            },
        )

        assert bootstrap["tenant_id"] == "tenant-a"
        assert bootstrap["intent_id"] == str(intent_id)
        assert bootstrap["capability_token"] == "cap-sandbox"
        assert evidence["sandbox_lifecycle_status"] == "evidence_submitted"
        assert evidence["predicate_passed"] is True
        assert captured["bootstrap_authorization"] == f"Bearer {_api_key()}"
        assert captured["bootstrap_tenant"] is None
        assert captured["bootstrap_recognition"] is None
        assert captured["bootstrap_idempotency"] == "sandbox-bootstrap-1"
        assert captured["bootstrap_body"] == {
            "operation": "vendor.lookup",
            "requested_spend_cents": 125,
            "currency": "USD",
            "evidence_schema": {"type": "object"},
            "metadata": {"demo": True},
        }
        assert captured["evidence_authorization"] == f"Bearer {_api_key()}"
        assert captured["evidence_tenant"] is None
        assert captured["evidence_recognition"] is None
        assert captured["evidence_idempotency"] == "sandbox-evidence-1"
        assert captured["evidence_body"] == {
            "payload": {"ok": True},
            "artifacts": ["artifact-1"],
            "operation": "vendor.lookup",
            "requested_spend_cents": 125,
            "metadata": {"demo": True},
        }
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
