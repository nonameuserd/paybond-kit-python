"""No-LLM MCP sandbox demo: agent-run bind + in-process MCP call_tool for authorize and evidence."""

from __future__ import annotations

from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.mcp_server import PaybondMCPSettings, build_mcp_server


async def _close_mcp_server(server: Any) -> None:
    runtime = getattr(server, "_paybond_runtime", None)
    if runtime is not None:
        await runtime.aclose()


async def run_mcp_sandbox_demo(
    paybond: Paybond,
    *,
    api_key: str,
    gateway_base_url: str,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
) -> dict[str, Any]:
    """
    No-LLM MCP sandbox demo using in-process ``build_mcp_server().call_tool`` (no stdio subprocess).
    """
    operation = operation.strip()
    evidence_preset = evidence_preset.strip()

    registry = create_paybond_tool_registry(
        {
            "default_deny": True,
            "side_effecting": {
                operation: {
                    "operation": operation,
                    "evidence_preset": evidence_preset,
                    "spend_cents": requested_spend_cents,
                }
            },
        }
    )

    run = await paybond.agent_run.bind(
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": operation,
                "requested_spend_cents": requested_spend_cents,
                "completion_preset": evidence_preset,
            },
            "registry": registry,
        }
    )

    server = build_mcp_server(
        PaybondMCPSettings(
            gateway_base_url=gateway_base_url,
            api_key=api_key,
        )
    )
    try:
        _, authorization_body = await server.call_tool(
            "paybond_authorize_agent_spend",
            {
                "intent_id": str(run.intent_id),
                "token": run.capability_token,
                "operation": operation,
                "requested_spend_cents": requested_spend_cents,
            },
        )

        tool_result = {
            "status": "completed",
            "cost_cents": requested_spend_cents,
        }

        _, validation_body = await server.call_tool(
            "paybond_validate_completion_evidence",
            {
                "preset_id": evidence_preset,
                "vendor_payload": tool_result,
                "canonical_payload": tool_result,
            },
        )
        if not isinstance(validation_body, dict) or validation_body.get("ok") is not True:
            raise RuntimeError("paybond_validate_completion_evidence did not pass")

        _, evidence_body = await server.call_tool(
            "paybond_submit_sandbox_guardrail_evidence",
            {
                "intent_id": str(run.intent_id),
                "payload": tool_result,
                "operation": operation,
                "requested_spend_cents": requested_spend_cents,
                "completion_preset_id": evidence_preset,
            },
        )
    finally:
        await _close_mcp_server(server)

    sandbox = run.binding.sandbox
    sandbox_status = (
        evidence_body.get("sandbox_lifecycle_status")
        if isinstance(evidence_body, dict)
        else None
    ) or (sandbox.sandbox_lifecycle_status if sandbox else None)

    authorization = authorization_body if isinstance(authorization_body, dict) else {}
    evidence = evidence_body if isinstance(evidence_body, dict) else {}

    return {
        "bind": {
            "run_id": run.run_id,
            "tenant_id": run.tenant_id,
            "intent_id": str(run.intent_id),
            "capability_token": run.capability_token,
            "operation": operation,
            "sandbox_lifecycle_status": sandbox_status,
        },
        "authorization": {
            "allow": authorization.get("allow") is True,
            "audit_id": authorization.get("audit_id"),
            "decision_id": authorization.get("decision_id"),
        },
        "tool_result": tool_result,
        "evidence": {
            "submitted": True,
            "sandbox_lifecycle_status": sandbox_status,
            "predicate_passed": evidence.get("predicate_passed")
            if isinstance(evidence.get("predicate_passed"), bool)
            else True,
        },
    }
