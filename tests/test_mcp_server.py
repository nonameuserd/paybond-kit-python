from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import respx
from mcp.server.fastmcp.exceptions import ToolError

from paybond_kit.mcp_capability_token_cache import McpCapabilityTokenCacheConfig
from paybond_kit.mcp_server import (
    DEFAULT_RECOGNITION_VERIFIER_ID,
    PaybondMCPRuntime,
    PaybondMCPSettings,
    build_mcp_server,
    run_mcp_stdio,
)


def _api_key() -> str:
    return "paybond_sk_" + "a" * 32 + "_" + "b" * 64


def test_mcp_settings_loads_local_env_file(tmp_path) -> None:
    env_file = tmp_path / ".env.local"
    env_file.write_text(
        f"PAYBOND_API_KEY={_api_key()}\nPAYBOND_GATEWAY_BASE_URL=https://gateway.from-file.test\n",
        encoding="utf-8",
    )

    settings = PaybondMCPSettings.from_env({"PAYBOND_ENV_FILE": str(env_file)})

    assert settings.api_key == _api_key()
    assert settings.gateway_base_url == "https://gateway.from-file.test"


def test_mcp_settings_accepts_registry_gateway_url_alias() -> None:
    settings = PaybondMCPSettings.from_env(
        {
            "PAYBOND_API_KEY": _api_key(),
            "PAYBOND_GATEWAY_URL": "https://gateway.registry.test",
            "PAYBOND_GATEWAY_BASE_URL": "https://gateway.legacy.test",
        }
    )

    assert settings.gateway_base_url == "https://gateway.registry.test"


def test_run_mcp_stdio_invalid_tool_policy_exits_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAYBOND_API_KEY", _api_key())
    monkeypatch.setenv("PAYBOND_MCP_TOOL_POLICY", "allowlist")
    with pytest.raises(SystemExit, match="tool-allowlist"):
        run_mcp_stdio([])


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
        assert "paybond_list_audit_exports" in names
        assert "paybond_get_audit_export" in names
        assert "paybond_verify_agent_mandate_v1" in names
        assert "paybond_import_agent_mandate_v1" in names
        assert "paybond_get_settlement_receipt_v1" in names
        assert "paybond_verify_protocol_receipt_v1" in names
        assert "paybond_get_agent_receipt_v1" in names
        assert "paybond_verify_agent_receipt_v1" in names
        assert "paybond_authorize_agent_spend" in names
        assert "paybond_get_budget_remaining" in names
        assert "paybond_explain_policy" in names
        assert "paybond_bootstrap_sandbox_guardrail" in names
        assert "paybond_submit_sandbox_guardrail_evidence" in names
        assert "paybond_validate_completion_evidence" in names
        assert "paybond_create_intent" in names
        assert "paybond_create_spend_intent" in names
        assert "paybond_submit_evidence" in names
        assert "paybond_submit_spend_evidence" in names
        assert "paybond_create_intent_legacy" not in names
        assert "paybond_fund_intent" not in names
        assert "paybond_confirm_settlement" not in names
        authorize = tool_by_name["paybond_authorize_agent_spend"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert authorize["title"] == "Authorize Agent Spend"
        assert "Use this when" in authorize["description"]
        assert "Do not use this for" in authorize["description"]
        assert authorize["annotations"] == {
            "title": "Authorize Agent Spend",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        }
        assert authorize["outputSchema"]["properties"]["allow"]["type"] == "boolean"
        assert authorize["outputSchema"]["properties"]["tenant"]["type"] == "string"
        assert authorize["outputSchema"]["properties"]["intent_id"]["type"] == "string"
        assert authorize["outputSchema"]["properties"]["remaining_cents"]["type"] == "integer"
        assert authorize["outputSchema"]["properties"]["reason_codes"]["type"] == "array"
        assert authorize["outputSchema"]["properties"]["message"]["type"] == "string"
        assert authorize["outputSchema"]["properties"]["decision_id"]["type"] == "string"
        assert authorize["outputSchema"]["properties"]["approval_request_id"]["type"] == "string"

        budget = tool_by_name["paybond_get_budget_remaining"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert budget["title"] == "Get Budget Remaining"
        assert budget["annotations"]["readOnlyHint"] is True
        assert budget["outputSchema"]["properties"]["remaining_cents"]["type"] == "integer"
        assert budget["outputSchema"]["properties"]["spend_scope"]["type"] == "object"
        assert budget["outputSchema"]["properties"]["policy_version"]["type"] == "integer"

        explain = tool_by_name["paybond_explain_policy"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert explain["title"] == "Explain Spend Policy"
        assert explain["annotations"]["readOnlyHint"] is True
        assert explain["outputSchema"]["properties"]["outcome"]["type"] == "string"
        assert explain["outputSchema"]["properties"]["reason_codes"]["type"] == "array"
        assert explain["outputSchema"]["properties"]["explanation"]["type"] == "string"

        create_spend = tool_by_name["paybond_create_spend_intent"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert create_spend["title"] == "Create Spend Intent"
        assert create_spend["annotations"]["readOnlyHint"] is False
        assert create_spend["annotations"]["destructiveHint"] is False
        assert create_spend["outputSchema"]["properties"]["intent_id"]["type"] == "string"
        assert create_spend["outputSchema"]["properties"]["capability_token"]["type"] == "string"

        principal = tool_by_name["paybond_get_principal"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert principal["title"] == "Get Paybond Principal"
        assert "Use this when" in principal["description"]
        assert "Call early as a prerequisite" in principal["description"]
        assert "Not required before every later call" in principal["description"]
        assert (
            "use paybond_get_intent instead when you have an intent_id"
            in principal["description"]
        )
        assert (
            "Do not use this for A2A discovery; use paybond_get_a2a_agent_card instead"
            in principal["description"]
        )
        assert "Do not use this when" in principal["description"]
        assert "no side effects" in principal["description"]
        assert "read-only" in principal["description"]
        assert principal["annotations"] == {
            "title": "Get Paybond Principal",
            "readOnlyHint": True,
            "openWorldHint": False,
        }
        assert "Tenant bound" in principal["outputSchema"]["properties"]["tenant_id"][
            "description"
        ]
        assert "service-account" in principal["outputSchema"]["properties"]["subject"][
            "description"
        ]
        assert principal["outputSchema"]["properties"]["subject"]["examples"] == [
            "service-account-1"
        ]
        assert "RBAC" in principal["outputSchema"]["properties"]["roles"]["description"]
        assert principal["outputSchema"]["properties"]["roles"]["examples"] == [["operator"]]
        assert "sandbox-only" in tool_by_name["paybond_bootstrap_sandbox_guardrail"].description

        signed_portfolio = tool_by_name["paybond_get_signed_portfolio_artifact"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert signed_portfolio["title"] == "Get Signed Portfolio Artifact"
        assert "Use this when" in signed_portfolio["description"]
        assert "paybond_get_portfolio_summary" in signed_portfolio["description"]
        assert "paybond_get_reputation_receipt" in signed_portfolio["description"]
        assert "paybond_get_fraud_assessment" in signed_portfolio["description"]
        assert "Do not use this" in signed_portfolio["description"]
        assert "no side effects" in signed_portfolio["description"]
        assert signed_portfolio["annotations"] == {
            "title": "Get Signed Portfolio Artifact",
            "readOnlyHint": True,
            "openWorldHint": False,
        }
        signed_score_version = signed_portfolio["inputSchema"]["properties"]["score_version"]
        assert "1.0" in signed_score_version["description"]
        assert "1.0" in signed_score_version["examples"]
        assert "paybond.signal.portfolio_snapshot" in signed_portfolio["outputSchema"][
            "properties"
        ]["kind"]["description"]
        assert "tenant-a" in signed_portfolio["outputSchema"]["properties"]["tenant_id"][
            "description"
        ]
        assert "Ed25519" in signed_portfolio["outputSchema"]["properties"]["signature_hex"][
            "description"
        ]

        fraud_assessment = tool_by_name["paybond_get_fraud_assessment"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert fraud_assessment["title"] == "Get Fraud Assessment"
        assert "Use this when" in fraud_assessment["description"]
        assert "did:web:vendor.example#booker-agent" in fraud_assessment["description"]
        assert "paybond_get_fraud_metrics" in fraud_assessment["description"]
        assert "paybond_get_intent" in fraud_assessment["description"]
        assert "Do not use this" in fraud_assessment["description"]
        assert fraud_assessment["annotations"] == {
            "title": "Get Fraud Assessment",
            "readOnlyHint": True,
            "openWorldHint": False,
        }
        operator_did_prop = fraud_assessment["inputSchema"]["properties"]["operator_did"]
        assert "did:web:vendor.example#booker-agent" in operator_did_prop["description"]
        assert "did:web:vendor.example#booker-agent" in operator_did_prop["examples"]
        score_version_prop = fraud_assessment["inputSchema"]["properties"]["score_version"]
        assert "1.0" in score_version_prop["description"]
        assert "1.0" in score_version_prop["examples"]
        assert "tenant-a" in fraud_assessment["outputSchema"]["properties"]["tenant_id"][
            "description"
        ]
        assert fraud_assessment["outputSchema"]["properties"]["tenant_id"]["examples"] == [
            "tenant-a"
        ]
        assert "Operator DID" in fraud_assessment["outputSchema"]["properties"]["operator_did"][
            "description"
        ]
        assert fraud_assessment["outputSchema"]["properties"]["operator_did"]["examples"] == [
            "did:web:vendor.example#booker-agent"
        ]
        fraud_assessment_prop = fraud_assessment["outputSchema"]["properties"]["fraud_assessment"]
        assert "level" in fraud_assessment_prop["description"]
        assert fraud_assessment_prop["examples"][0]["level"] == "high"

        portfolio_summary = tool_by_name["paybond_get_portfolio_summary"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert portfolio_summary["title"] == "Get Portfolio Summary"
        assert "Use this when" in portfolio_summary["description"]
        assert "paybond_get_signed_portfolio_artifact" in portfolio_summary["description"]
        assert "paybond_get_reputation_receipt" in portfolio_summary["description"]
        assert "Do not use this" in portfolio_summary["description"]
        assert "no side effects" in portfolio_summary["description"]
        assert portfolio_summary["annotations"] == {
            "title": "Get Portfolio Summary",
            "readOnlyHint": True,
            "openWorldHint": False,
        }
        portfolio_score_version = portfolio_summary["inputSchema"]["properties"]["score_version"]
        assert "1.0" in portfolio_score_version["description"]
        assert "1.0" in portfolio_score_version["examples"]
        assert "tenant-a" in portfolio_summary["outputSchema"]["properties"]["tenant_id"][
            "description"
        ]
        assert portfolio_summary["outputSchema"]["properties"]["operator_count"]["type"] == "integer"
        assert portfolio_summary["outputSchema"]["properties"]["average_score"]["type"] == "number"
        assert "operators" not in portfolio_summary["outputSchema"]["properties"]

        verify_protocol_receipt = tool_by_name["paybond_verify_protocol_receipt_v1"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert verify_protocol_receipt["title"] == "Verify Protocol Receipt"
        assert "Use this when" in verify_protocol_receipt["description"]
        assert "paybond_verify_agent_mandate_v1" in verify_protocol_receipt["description"]
        assert "paybond_verify_capability" in verify_protocol_receipt["description"]
        assert "paybond_get_settlement_receipt_v1" in verify_protocol_receipt["description"]
        assert "Do not use this" in verify_protocol_receipt["description"]
        assert "side-effect free" in verify_protocol_receipt["description"]
        assert verify_protocol_receipt["annotations"] == {
            "title": "Verify Protocol Receipt",
            "readOnlyHint": True,
            "openWorldHint": False,
        }
        receipt_prop = verify_protocol_receipt["inputSchema"]["properties"]["receipt"]
        assert "paybond.protocol_authorization_receipt_v1" in receipt_prop["description"]
        assert "paybond.protocol_settlement_receipt_v1" in receipt_prop["description"]
        assert verify_protocol_receipt["outputSchema"]["properties"]["valid"]["type"] == "boolean"
        assert "Ed25519" in verify_protocol_receipt["outputSchema"]["properties"]["valid"][
            "description"
        ]
        assert verify_protocol_receipt["outputSchema"]["properties"]["receipt"]["type"] == "object"

        fraud_metrics = tool_by_name["paybond_get_fraud_metrics"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert fraud_metrics["title"] == "Get Fraud Metrics"
        assert "Use this when" in fraud_metrics["description"]
        assert "paybond_get_fraud_assessment" in fraud_metrics["description"]
        assert "Do not use this" in fraud_metrics["description"]
        assert "24h" in fraud_metrics["description"]
        assert "no side effects" in fraud_metrics["description"]
        assert fraud_metrics["annotations"] == {
            "title": "Get Fraud Metrics",
            "readOnlyHint": True,
            "openWorldHint": False,
        }
        window_prop = fraud_metrics["inputSchema"]["properties"]["window"]
        assert "24h" in window_prop["description"]
        assert set(window_prop.get("examples", [])) >= {"24h", "7d", "30d"}
        metrics_score_version = fraud_metrics["inputSchema"]["properties"]["score_version"]
        assert "1.0" in metrics_score_version["description"]
        assert "1.0" in metrics_score_version["examples"]
        assert fraud_metrics["outputSchema"]["properties"]["flagged_operator_count"][
            "type"
        ] == "integer"
        assert "Operators" in fraud_metrics["outputSchema"]["properties"]["flagged_operator_count"][
            "description"
        ]
        assert fraud_metrics["outputSchema"]["properties"]["critical_signal_count"][
            "type"
        ] == "integer"
        assert "backtest" in fraud_metrics["outputSchema"]["properties"]["backtest_summary"][
            "description"
        ]

        reputation_receipt = tool_by_name["paybond_get_reputation_receipt"].model_dump(
            by_alias=True, exclude_none=True
        )
        assert reputation_receipt["title"] == "Get Reputation Receipt"
        assert "Use this when" in reputation_receipt["description"]
        assert "paybond_get_portfolio_summary" in reputation_receipt["description"]
        assert "paybond_get_signed_portfolio_artifact" in reputation_receipt["description"]
        assert "paybond_get_fraud_assessment" in reputation_receipt["description"]
        assert "Do not use this" in reputation_receipt["description"]
        assert "returns null" in reputation_receipt["description"]
        assert reputation_receipt["annotations"] == {
            "title": "Get Reputation Receipt",
            "readOnlyHint": True,
            "openWorldHint": False,
        }
        reputation_operator = reputation_receipt["inputSchema"]["properties"]["operator_did"]
        assert "did:web:vendor.example#booker-agent" in reputation_operator["description"]
        assert "did:web:vendor.example#booker-agent" in reputation_operator["examples"]
        reputation_score_version = reputation_receipt["inputSchema"]["properties"]["score_version"]
        assert "1.0" in reputation_score_version["description"]
        assert "1.0" in reputation_score_version["examples"]
        assert reputation_receipt["outputSchema"]["properties"]["schema_version"]["type"] == "integer"
        assert reputation_receipt["outputSchema"]["properties"]["updated_at"]["type"] == "string"
        assert "signature_hex" in reputation_receipt["outputSchema"]["properties"]["receipt"][
            "description"
        ]
    finally:
        await _close_server(server)


@pytest.mark.asyncio
async def test_allowlist_policy_exposes_live_money_tool_metadata() -> None:
    from paybond_kit.mcp_policy import parse_mcp_tool_allowlist, parse_mcp_tool_policy, merge_mcp_tool_policy

    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
            tool_policy=merge_mcp_tool_policy(
                parse_mcp_tool_policy("allowlist"),
                allowlist=parse_mcp_tool_allowlist("paybond_fund_intent"),
            ),
        )
    )
    try:
        tools = await server.list_tools()
        tool_by_name = {tool.name: tool for tool in tools}
        fund = tool_by_name["paybond_fund_intent"].model_dump(by_alias=True, exclude_none=True)
        assert fund["title"] == "Fund Intent"
        assert fund["annotations"]["destructiveHint"] is True
        assert "paybond_authorize_agent_spend" in fund["description"]
    finally:
        await _close_server(server)


@pytest.mark.asyncio
@respx.mock
async def test_preload_principal_caches_gateway_principal_at_startup() -> None:
    principal_route = respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"}),
    )
    runtime = PaybondMCPRuntime(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        await runtime.preload_principal()
        assert principal_route.call_count == 1
        assert await runtime.tenant_id() == "tenant-a"
        assert principal_route.call_count == 1
    finally:
        await runtime.aclose()


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
async def test_budget_remaining_and_explain_policy_call_spend_preflight() -> None:
    intent_id = uuid4()
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "tenant-a"})
    )
    preflight = respx.post("https://gateway.test/v1/spend/preflight").mock(
        return_value=httpx.Response(
            200,
            json={
                "classification": "hold",
                "outcome": "approval_required",
                "reason_codes": ["approval_threshold_exceeded"],
                "remaining_cents": 25000,
                "spend_scope": {"scope_type": "tenant", "scope_key": ""},
                "policy_version": 3,
                "explanation": (
                    "Requested spend is at or above the approval threshold and requires human approval."
                ),
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
        _, budget = await server.call_tool(
            "paybond_get_budget_remaining",
            {
                "intent_id": str(intent_id),
                "operation": "tool.purchase",
                "requested_spend_cents": 75000,
                "vendor_id": "vendor-1",
            },
        )
        assert budget == {
            "remaining_cents": 25000,
            "spend_scope": {"scope_type": "tenant", "scope_key": ""},
            "policy_version": 3,
        }

        _, explained = await server.call_tool(
            "paybond_explain_policy",
            {
                "intent_id": str(intent_id),
                "operation": "tool.purchase",
                "requested_spend_cents": 75000,
                "vendor_id": "vendor-1",
            },
        )
        assert explained == {
            "outcome": "approval_required",
            "reason_codes": ["approval_threshold_exceeded"],
            "explanation": (
                "Requested spend is at or above the approval threshold and requires human approval."
            ),
            "remaining_cents": 25000,
            "approval_threshold_exceeded": True,
        }
        assert preflight.call_count == 2
        request = preflight.calls[0].request
        assert request.headers.get("x-tenant-id") == "tenant-a"
        body = json.loads(request.content.decode("utf-8"))
        assert body["intent_id"] == str(intent_id)
        assert body["operation"] == "tool.purchase"
        assert body["requested_spend_cents"] == 75000
        assert body["vendor_id"] == "vendor-1"
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
        assert bootstrap["capability_token"] == "[redacted]"
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
async def test_recognition_verify_ignores_caller_supplied_expected_verifier() -> None:
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
                "expected_verifier": {
                    "tenant_id": "tenant-evil",
                    "verifier_id": "attacker-controlled",
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


@pytest.mark.asyncio
async def test_default_spend_write_policy_blocks_live_money_tools() -> None:
    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
        )
    )
    try:
        tools = await server.list_tools()
        names = {tool.name for tool in tools}
        assert "paybond_create_spend_intent" in names
        assert "paybond_fund_intent" not in names
        assert "paybond_confirm_settlement" not in names
    finally:
        await _close_server(server)


@pytest.mark.asyncio
async def test_readonly_tool_policy_limits_exposed_tools() -> None:
    from paybond_kit.mcp_policy import parse_mcp_tool_policy

    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
            tool_policy=parse_mcp_tool_policy("readonly"),
        )
    )
    try:
        tools = await server.list_tools()
        names = {tool.name for tool in tools}
        assert "paybond_get_principal" in names
        assert "paybond_list_audit_exports" in names
        assert "paybond_get_audit_export" in names
        assert "paybond_get_budget_remaining" in names
        assert "paybond_explain_policy" in names
        assert "paybond_create_spend_intent" not in names
    finally:
        await _close_server(server)


@pytest.mark.asyncio
async def test_capability_token_cache_expires_between_tool_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    now = 1_000.0
    monkeypatch.setattr(time, "monotonic", lambda: now)

    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url="https://gateway.test",
            api_key=_api_key(),
            capability_token_cache=McpCapabilityTokenCacheConfig(
                ttl_sec=30.0,
                max_entries=4,
            ),
        )
    )
    runtime = server._paybond_runtime
    try:
        runtime._store_capability_token("intent-1", "cap-token")
        assert await runtime.resolve_capability_token("intent-1") == "cap-token"

        now += 31.0
        with pytest.raises(ValueError, match="unavailable or expired"):
            await runtime.resolve_capability_token("intent-1")
    finally:
        await _close_server(server)


def test_mcp_stdio_stdout_contract_is_mcp_pure(tmp_path) -> None:
    import subprocess
    import sys

    from paybond_kit.cli.doctor_agent import _stdout_is_mcp_pure, encode_mcp_message

    env_file = tmp_path / ".env.local"
    env_file.write_text(f"PAYBOND_API_KEY={_api_key()}\n", encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, "-m", "paybond_kit.mcp_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(tmp_path),
        env={
            **dict(__import__("os").environ),
            "PAYBOND_ENV_FILE": str(env_file),
            "PAYBOND_API_KEY": "",
        },
    )
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "paybond-test", "version": "0"},
            },
        }
        process.stdin.write(encode_mcp_message(initialize))
        process.stdin.flush()
        stdout = process.stdout.readline()
        assert _stdout_is_mcp_pure(stdout)
    finally:
        process.terminate()
        process.wait(timeout=2)


@pytest.mark.asyncio
async def test_mcp_agent_receipt_resource_reads_gateway_receipt() -> None:
    conformance_path = (
        Path(__file__).resolve().parents[2]
        / "agent-receipt"
        / "conformance"
        / "signed-action-receipt-v1.json"
    )
    receipt = json.loads(conformance_path.read_text(encoding="utf-8"))
    receipt_id = receipt["receipt_id"]
    with respx.mock(assert_all_called=True) as router:
        router.get("https://gateway.test/v1/auth/principal").respond(
            200,
            json={"tenant_id": receipt["tenant_id"], "roles": ["operator"], "subject": "svc"},
        )
        router.get(f"https://gateway.test/protocol/v2/agent-receipts/{receipt_id}").respond(
            200,
            json=receipt,
        )
        server = build_mcp_server(
            PaybondMCPSettings(
                gateway_base_url="https://gateway.test",
                api_key=_api_key(),
            )
        )
        try:
            templates = await server.list_resource_templates()
            assert any(
                template.uriTemplate == "paybond://receipt/{receipt_id}"
                for template in templates
            )
            contents = await server.read_resource(f"paybond://receipt/{receipt_id}")
            assert contents[0].mime_type == "application/json"
            body = json.loads(contents[0].content)
            assert body["receipt_id"] == receipt_id
            assert body["message_digest_sha256_hex"] == receipt["message_digest_sha256_hex"]
        finally:
            await _close_server(server)


@pytest.mark.asyncio
async def test_mcp_agent_receipt_resource_rejects_tampered_receipt() -> None:
    conformance_path = (
        Path(__file__).resolve().parents[2]
        / "agent-receipt"
        / "conformance"
        / "signed-action-receipt-v1.json"
    )
    receipt = json.loads(conformance_path.read_text(encoding="utf-8"))
    receipt_id = receipt["receipt_id"]
    tampered = dict(receipt)
    tampered["outcome"] = {**receipt["outcome"], "harbor_state": "released"}
    with respx.mock(assert_all_called=True) as router:
        router.get("https://gateway.test/v1/auth/principal").respond(
            200,
            json={"tenant_id": receipt["tenant_id"], "roles": ["operator"], "subject": "svc"},
        )
        router.get(f"https://gateway.test/protocol/v2/agent-receipts/{receipt_id}").respond(
            200,
            json=tampered,
        )
        server = build_mcp_server(
            PaybondMCPSettings(
                gateway_base_url="https://gateway.test",
                api_key=_api_key(),
            )
        )
        try:
            with pytest.raises(Exception, match="agent receipt verification failed"):
                await server.read_resource(f"paybond://receipt/{receipt_id}")
        finally:
            await _close_server(server)


@pytest.mark.asyncio
async def test_mcp_get_and_verify_agent_receipt_tools() -> None:
    conformance_path = (
        Path(__file__).resolve().parents[2]
        / "agent-receipt"
        / "conformance"
        / "signed-action-receipt-v1.json"
    )
    receipt = json.loads(conformance_path.read_text(encoding="utf-8"))
    receipt_id = receipt["receipt_id"]
    with respx.mock(assert_all_called=True) as router:
        router.get("https://gateway.test/v1/auth/principal").respond(
            200,
            json={"tenant_id": receipt["tenant_id"], "roles": ["operator"], "subject": "svc"},
        )
        router.get(f"https://gateway.test/protocol/v2/agent-receipts/{receipt_id}").respond(
            200,
            json=receipt,
        )
        server = build_mcp_server(
            PaybondMCPSettings(
                gateway_base_url="https://gateway.test",
                api_key=_api_key(),
            )
        )
        try:
            _, fetched = await server.call_tool(
                "paybond_get_agent_receipt_v1",
                {"receipt_id": receipt_id},
            )
            assert fetched["receipt_id"] == receipt_id
            _, verified = await server.call_tool(
                "paybond_verify_agent_receipt_v1",
                {"receipt": receipt},
            )
            assert verified["valid"] is True
            assert verified["validity_tier"] == "operational"
            assert verified["receipt_id"] == receipt_id
        finally:
            await _close_server(server)

