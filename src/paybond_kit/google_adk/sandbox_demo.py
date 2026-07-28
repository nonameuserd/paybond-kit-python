"""No-LLM Google ADK sandbox demo: guarded FunctionTool execution + auto-evidence."""

from __future__ import annotations

import importlib
from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.google_adk._peer import google_adk_runtime_available
from paybond_kit.google_adk.config import create_paybond_google_adk_config


def _require_google_adk_demo_deps() -> Any:
    if not google_adk_runtime_available():
        raise ImportError(
            "google-adk is required for paybond_kit.google_adk.sandbox_demo. "
            'Install with `pip install "paybond-kit[google-adk]"`.'
        )
    # Optional dependency resolved dynamically (see paybond_kit.google_adk._peer).
    return importlib.import_module("google.adk.tools").FunctionTool


async def run_google_adk_sandbox_demo(
    paybond: Paybond,
    *,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
    tool_call_id: str = "google-adk-demo-1",
) -> dict[str, Any]:
    function_tool_cls = _require_google_adk_demo_deps()
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

    def paid_tool(estimated_price_cents: int) -> dict[str, Any]:
        """Execute a paid sandbox operation."""
        return {"status": "completed", "cost_cents": estimated_price_cents}

    # Rename so FunctionTool.name matches the registered operation.
    paid_tool.__name__ = operation
    paid_tool_instance = function_tool_cls(paid_tool)
    config = create_paybond_google_adk_config(run, [paid_tool_instance])
    guarded_tool = config.tools[0]

    sandbox = run.binding.sandbox
    sandbox_status = sandbox.sandbox_lifecycle_status if sandbox else None

    allow = True
    parsed_result: Any
    try:
        raw_result = guarded_tool.func(estimated_price_cents=requested_spend_cents)
        parsed_result = raw_result if isinstance(raw_result, dict) else {"value": raw_result}
    except Exception as exc:  # noqa: BLE001 — surface deny paths in smoke payload
        message = str(exc)
        if message.startswith("Paybond capability"):
            allow = False
            parsed_result = {"error": message}
        else:
            raise

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
