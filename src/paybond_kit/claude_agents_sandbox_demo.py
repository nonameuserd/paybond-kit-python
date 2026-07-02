"""No-LLM Claude Agent SDK sandbox demo: wrapped MCP tool handlers + auto-evidence."""

from __future__ import annotations

from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.claude_agents.config import create_paybond_claude_agents_config


async def run_claude_agents_sandbox_demo(
    paybond: Paybond,
    *,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
    tool_call_id: str = "claude-demo-1",
) -> dict[str, Any]:
    sdk = __import__("claude_agent_sdk", fromlist=["tool"])
    tool = sdk.tool

    operation = operation.strip()
    evidence_preset = evidence_preset.strip()
    tool_call_id = tool_call_id.strip()

    registry = create_paybond_tool_registry(
        {
            "default_deny": True,
            "side_effecting": {
                operation: {
                    "operation": operation,
                    "evidence_preset": evidence_preset,
                    "spend_cents": requested_spend_cents,
                    "evidence_mapper": lambda result, _ctx: {
                        "status": result.get("status"),
                        "cost_cents": result.get("cost_cents"),
                    },
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

    async def paid_handler(args: dict[str, Any], _extra: Any) -> dict[str, Any]:
        cents = int(args.get("estimated_price_cents", requested_spend_cents))
        payload = {"status": "completed", "cost_cents": cents}
        return {
            "content": [{"type": "text", "text": __import__("json").dumps(payload)}],
            "structuredContent": payload,
        }

    sdk_tools = [
        tool(
            operation,
            f"Paid operation {operation}",
            {"estimated_price_cents": int},
            paid_handler,
        )
    ]

    config = create_paybond_claude_agents_config(run, sdk_tools)
    paid_tool = config.agent_tools[0]
    result = await paid_tool.handler(
        {"estimated_price_cents": requested_spend_cents},
        {"toolUseID": tool_call_id},
    )

    sandbox = run.binding.sandbox
    sandbox_status = sandbox.sandbox_lifecycle_status if sandbox else None
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    is_error = bool(result.get("isError")) if isinstance(result, dict) else False

    return {
        "bind": {
            "run_id": run.run_id,
            "tenant_id": run.tenant_id,
            "intent_id": str(run.intent_id),
            "capability_token": run.capability_token,
            "operation": operation,
            "sandbox_lifecycle_status": sandbox_status,
        },
        "allowed_tools": config.allowed_tools,
        "tool_result": structured,
        "evidence": {
            "submitted": not is_error,
            "sandbox_lifecycle_status": sandbox_status,
            "predicate_passed": True if not is_error else None,
        },
    }
