"""No-LLM agent-agnostic sandbox demo: generic runner + wrapped execute + auto-evidence."""

from __future__ import annotations

from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.generic_runner import create_paybond_generic_agent_config
from paybond_kit.agent.registry import create_paybond_tool_registry


async def _execute_paid_tool(args: dict[str, Any] | int) -> dict[str, Any]:
    if isinstance(args, dict):
        cents = int(args.get("estimated_price_cents", 100))
    else:
        cents = int(args)
    return {"status": "completed", "cost_cents": cents}


async def run_generic_sandbox_demo(
    paybond: Paybond,
    *,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
    tool_call_id: str = "generic-demo-1",
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

    config = create_paybond_generic_agent_config(
        run,
        [{"name": operation, "execute": _execute_paid_tool}],
    )
    wrapped = next((tool for tool in config.tools if tool.get("name") == operation), None)
    if wrapped is None:
        raise RuntimeError(f"generic sandbox demo missing wrapped tool {operation}")

    wrapped_result = await wrapped["execute"](
        {
            "tool_name": operation,
            "tool_call_id": tool_call_id,
            "arguments": {"estimated_price_cents": requested_spend_cents},
        }
    )

    sandbox = run.binding.sandbox
    sandbox_status = sandbox.sandbox_lifecycle_status if sandbox else None
    authorization = wrapped_result.get("authorization") or {}
    evidence = wrapped_result.get("evidence")

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
            "allow": True,
            "audit_id": authorization.get("audit_id"),
            "decision_id": authorization.get("decision_id"),
        },
        "execute": {
            "tool_result": wrapped_result.get("tool_result"),
            "evidence": {
                "submitted": bool(getattr(evidence, "submitted", False)) if evidence is not None else False,
                "sandbox_lifecycle_status": sandbox_status,
                "predicate_passed": getattr(evidence, "predicate_passed", None) if evidence is not None else None,
            },
        },
    }
