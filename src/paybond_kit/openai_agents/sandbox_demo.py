"""No-LLM OpenAI Agents SDK sandbox demo: input guardrail pre-check + guarded invoke + auto-evidence."""

from __future__ import annotations

import json
from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.openai_agents._peer import openai_agents_runtime_available
from paybond_kit.openai_agents.config import create_paybond_openai_agents_config


def _require_openai_agents_demo_deps() -> Any:
    if not openai_agents_runtime_available():
        raise ImportError(
            "openai-agents is required for paybond_kit.openai_agents.sandbox_demo. "
            'Install with `pip install "paybond-kit[openai-agents]"`.'
        )
    from agents import FunctionTool

    return FunctionTool


async def run_openai_agents_sandbox_demo(
    paybond: Paybond,
    *,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
    tool_call_id: str = "openai-demo-1",
) -> dict[str, Any]:
    function_tool_cls = _require_openai_agents_demo_deps()
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
                    "spend_cents": lambda args: (
                        int(args.get("estimatedPriceCents", requested_spend_cents))
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

    async def invoke_paid_tool(_ctx: Any, input_json: str) -> str:
        args = json.loads(input_json)
        estimated = int(args.get("estimatedPriceCents", requested_spend_cents))
        return json.dumps({"status": "completed", "cost_cents": estimated})

    paid_tool = function_tool_cls(
        name=operation,
        description=f"Paid operation {operation}",
        params_json_schema={
            "type": "object",
            "properties": {
                "estimatedPriceCents": {"type": "integer", "minimum": 0},
            },
            "required": ["estimatedPriceCents"],
            "additionalProperties": False,
        },
        on_invoke_tool=invoke_paid_tool,
        strict_json_schema=False,
        needs_approval=False,
    )

    config = create_paybond_openai_agents_config(run, [paid_tool])
    guarded = config.tools[0]
    if guarded is None:
        raise RuntimeError("openai-agents sandbox demo missing guarded tool")

    input_json = json.dumps({"estimatedPriceCents": requested_spend_cents})
    agents = __import__("agents")
    tool_context = agents.ToolContext(
        context={},
        tool_name=operation,
        tool_call_id=tool_call_id,
        tool_arguments=input_json,
    )

    guardrail_result = None
    guardrails = getattr(guarded, "tool_input_guardrails", None) or []
    if guardrails:
        guardrail_data = agents.ToolInputGuardrailData(context=tool_context, agent=None)
        guardrail_result = await guardrails[-1].run(guardrail_data)

    output = await guarded.on_invoke_tool(tool_context, input_json)

    tool_result: Any
    if isinstance(output, str):
        try:
            tool_result = json.loads(output)
        except json.JSONDecodeError:
            tool_result = output
    else:
        tool_result = output

    sandbox = run.binding.sandbox
    sandbox_status = sandbox.sandbox_lifecycle_status if sandbox else None
    behavior = None
    if guardrail_result is not None:
        behavior = getattr(guardrail_result, "behavior", None)
        if isinstance(behavior, dict):
            behavior_type = behavior.get("type")
        else:
            behavior_type = getattr(behavior, "type", None)
    else:
        behavior_type = "not-applicable"

    return {
        "bind": {
            "run_id": run.run_id,
            "tenant_id": run.tenant_id,
            "intent_id": str(run.intent_id),
            "capability_token": run.capability_token,
            "operation": operation,
            "sandbox_lifecycle_status": sandbox_status,
        },
        "guardrail": {
            "behavior": behavior_type,
        },
        "execute": {
            "tool_result": tool_result,
            "evidence": {
                "submitted": True,
                "sandbox_lifecycle_status": sandbox_status,
                "predicate_passed": True,
            },
        },
    }
