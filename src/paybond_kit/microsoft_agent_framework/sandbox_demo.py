"""No-LLM Microsoft Agent Framework sandbox demo: function middleware + auto-evidence."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.microsoft_agent_framework._peer import (
    microsoft_agent_framework_runtime_available,
)
from paybond_kit.microsoft_agent_framework.config import (
    create_paybond_microsoft_agent_framework_middleware,
    process_paybond_function_invocation,
)


def _require_maf_demo_deps() -> None:
    if not microsoft_agent_framework_runtime_available():
        raise ImportError(
            "agent-framework-core is required for paybond_kit.microsoft_agent_framework.sandbox_demo. "
            'Install with `pip install "paybond-kit[microsoft-agent-framework]"`.'
        )


async def run_microsoft_agent_framework_sandbox_demo(
    paybond: Paybond,
    *,
    operation: str = "paid-tool",
    requested_spend_cents: int = 100,
    evidence_preset: str = "cost_and_completion",
    tool_call_id: str = "microsoft-agent-framework-demo-1",
) -> dict[str, Any]:
    """
    Bind a sandbox run, build function middleware, and invoke the middleware path
    against a fake ``FunctionInvocationContext`` (no LLM).
    """

    _require_maf_demo_deps()
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

    # Ensure middleware factory succeeds (peer import + FunctionMiddleware subclass).
    _middleware = create_paybond_microsoft_agent_framework_middleware(run)

    executed = False

    async def call_next() -> None:
        nonlocal executed
        executed = True
        context.result = {
            "status": "completed",
            "cost_cents": requested_spend_cents,
        }

    context = SimpleNamespace(
        function=SimpleNamespace(name=operation),
        arguments={"estimated_price_cents": requested_spend_cents},
        metadata={"call_id": tool_call_id},
        result=None,
    )

    await process_paybond_function_invocation(run, context, call_next)

    sandbox = run.binding.sandbox
    sandbox_status = sandbox.sandbox_lifecycle_status if sandbox else None

    parsed_result = context.result
    allow = True
    if isinstance(parsed_result, str) and parsed_result.startswith("Paybond capability"):
        allow = False
        parsed_result = {"error": parsed_result}
    elif not executed and not (
        isinstance(parsed_result, dict) and parsed_result.get("status") == "completed"
    ):
        # Deny/hold path never entered the tool body.
        if isinstance(parsed_result, str):
            allow = False
            parsed_result = {"error": parsed_result}

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
        "tool_executed": executed,
    }
