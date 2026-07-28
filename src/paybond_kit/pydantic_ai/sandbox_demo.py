"""No-LLM Pydantic AI sandbox demo: guarded Tool execution + auto-evidence."""

from __future__ import annotations

import importlib
from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.pydantic_ai._peer import pydantic_ai_runtime_available
from paybond_kit.pydantic_ai.config import create_paybond_pydantic_ai_config


def _require_pydantic_ai_demo_deps() -> Any:
    if not pydantic_ai_runtime_available():
        raise ImportError(
            "pydantic-ai is required for paybond_kit.pydantic_ai.sandbox_demo. "
            'Install with `pip install "paybond-kit[pydantic-ai]"`.'
        )
    # Optional dependency resolved dynamically (see paybond_kit.pydantic_ai._peer).
    return importlib.import_module("pydantic_ai").Tool


def _model_retry_cls() -> Any:
    return importlib.import_module("pydantic_ai").ModelRetry


async def run_pydantic_ai_sandbox_demo(
    paybond: Paybond,
    *,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
    tool_call_id: str = "pydantic-ai-demo-1",
) -> dict[str, Any]:
    tool_cls = _require_pydantic_ai_demo_deps()
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

    paid_tool_instance = tool_cls(paid_tool, name=operation)
    config = create_paybond_pydantic_ai_config(run, [paid_tool_instance])
    guarded_tool = config.tools[0]

    sandbox = run.binding.sandbox
    sandbox_status = sandbox.sandbox_lifecycle_status if sandbox else None

    model_retry_cls = _model_retry_cls()
    allow = True
    parsed_result: Any
    try:
        raw_result = guarded_tool.function(estimated_price_cents=requested_spend_cents)
        parsed_result = raw_result if isinstance(raw_result, dict) else {"value": raw_result}
    except Exception as exc:  # noqa: BLE001 — surface ModelRetry / deny paths in smoke payload
        if isinstance(exc, model_retry_cls):
            allow = False
            parsed_result = {"error": str(exc)}
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
