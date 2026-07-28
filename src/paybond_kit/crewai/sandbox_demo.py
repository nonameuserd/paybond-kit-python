"""No-LLM CrewAI sandbox demo: guarded @tool execution + auto-evidence."""

from __future__ import annotations

import importlib
import json
from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.crewai._peer import crewai_runtime_available
from paybond_kit.crewai.config import create_paybond_crewai_config


def _require_crewai_demo_deps() -> Any:
    if not crewai_runtime_available():
        raise ImportError(
            "crewai is required for paybond_kit.crewai.sandbox_demo. "
            'Install with `pip install "paybond-kit[crewai]"`.'
        )
    # Optional dependency resolved dynamically (see paybond_kit.crewai._peer).
    return importlib.import_module("crewai.tools").tool


async def run_crewai_sandbox_demo(
    paybond: Paybond,
    *,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
    tool_call_id: str = "crewai-demo-1",
) -> dict[str, Any]:
    tool_decorator = _require_crewai_demo_deps()
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

    @tool_decorator(operation)
    def paid_tool(estimated_price_cents: int) -> str:
        """Execute a paid sandbox operation."""
        payload = {"status": "completed", "cost_cents": estimated_price_cents}
        return json.dumps(payload)

    config = create_paybond_crewai_config(run, [paid_tool])
    guarded_tool = config.tools[0]
    raw_result = guarded_tool.run(estimated_price_cents=requested_spend_cents)

    sandbox = run.binding.sandbox
    sandbox_status = sandbox.sandbox_lifecycle_status if sandbox else None

    parsed_result: Any = raw_result
    if isinstance(raw_result, str):
        if raw_result.startswith("Paybond capability") or raw_result.startswith("Paybond evidence"):
            parsed_result = {"error": raw_result}
            allow = False
        else:
            try:
                parsed_result = json.loads(raw_result)
                allow = True
            except json.JSONDecodeError:
                allow = True
    else:
        allow = True

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
        "tool_result": parsed_result if isinstance(parsed_result, dict) else {"value": parsed_result},
        "evidence": {
            "submitted": allow,
            "sandbox_lifecycle_status": sandbox_status,
            "predicate_passed": True if allow else None,
        },
        "tool_call_id": tool_call_id,
    }
