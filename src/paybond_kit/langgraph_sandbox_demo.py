"""No-LLM LangGraph sandbox demo: awrap_tool_call + Paybond interceptor + auto-evidence."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.langgraph_hooks import paybond_awrap_tool_call


def _execute_paid_tool(estimated_price_cents: int) -> dict[str, Any]:
    return {"status": "completed", "cost_cents": estimated_price_cents}


async def run_langgraph_sandbox_demo(
    paybond: Paybond,
    *,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
    tool_call_id: str = "langgraph-demo-1",
) -> dict[str, Any]:
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
                    "spend_cents": lambda args: int(
                        args.get("estimated_price_cents", requested_spend_cents)
                        if isinstance(args, dict)
                        else requested_spend_cents
                    ),
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

    paid_tool = StructuredTool.from_function(
        func=_execute_paid_tool,
        name=operation,
        description=f"Paid operation {operation}",
    )
    awrap = paybond_awrap_tool_call(run)
    request = MagicMock()
    request.tool_call = {
        "name": operation,
        "args": {"estimated_price_cents": requested_spend_cents},
        "id": tool_call_id,
    }

    async def _execute(_request: Any) -> Any:
        return paid_tool.invoke({"estimated_price_cents": requested_spend_cents})

    result = await awrap(request, _execute)
    if isinstance(result, ToolMessage):
        tool_message = result
    else:
        tool_message = ToolMessage(
            content=str(result) if not isinstance(result, dict) else str(result),
            name=operation,
            tool_call_id=tool_call_id,
            status="success",
        )

    sandbox = run.binding.sandbox
    sandbox_status = sandbox.sandbox_lifecycle_status if sandbox else None
    allow = tool_message.status != "error"

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
            "allow": allow,
        },
        "tool_message": {
            "content": str(tool_message.content),
            "status": str(tool_message.status or "success"),
            "name": str(tool_message.name or operation),
            "tool_call_id": str(tool_message.tool_call_id or tool_call_id),
        },
        "evidence": {
            "submitted": allow,
            "sandbox_lifecycle_status": sandbox_status,
            "predicate_passed": True if allow else None,
        },
        "intent_state": sandbox_status,
    }
