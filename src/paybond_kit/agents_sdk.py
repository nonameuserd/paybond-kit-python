"""
OpenAI Agents SDK integration — capability verification guardrails bound to Harbor.

Requires ``pip install "paybond-kit[agents]"``.
"""

from __future__ import annotations

from paybond_kit.capability_binding import PaybondCapabilityBinding
from paybond_kit.harbor import HarborClient

try:
    from agents.tool_guardrails import (
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
        ToolInputGuardrailData,
    )
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "openai-agents is required for paybond_kit.agents_sdk. Install with "
        '`pip install "paybond-kit[agents]"`.'
    ) from exc


PaybondAgentsBinding = PaybondCapabilityBinding


def paybond_capability_input_guardrail(
    *,
    requested_spend_cents: int = 0,
) -> ToolInputGuardrail[PaybondCapabilityBinding]:
    """
    Build a tool input guardrail that calls Harbor ``POST /verify`` before tool execution.

    The guardrail uses :attr:`agents.tool_context.ToolContext.qualified_tool_name` as the delegated
    ``operation`` string, so intent ``allowed_tools`` entries should use the same qualified names.

    Args:
        requested_spend_cents: Static spend hint forwarded to Harbor (per-run totals require a
            richer policy hook for production billing).
    """

    async def _guard(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        binding = data.context.context
        if not isinstance(binding, PaybondCapabilityBinding):
            return ToolGuardrailFunctionOutput.raise_exception(
                output_info={
                    "code": "paybond_bad_run_context",
                    "detail": (
                        "RunContext.context must be a PaybondCapabilityBinding; "
                        "pass context=PaybondCapabilityBinding(...) to Runner.run()."
                    ),
                },
            )
        operation = data.context.qualified_tool_name
        result = await binding.harbor.verify_capability(
            intent_id=binding.intent_id,
            token=binding.capability_token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )
        if not result.allow:
            msg = result.message or result.code or "capability denied"
            return ToolGuardrailFunctionOutput.reject_content(
                message=str(msg),
                output_info=result,
            )
        return ToolGuardrailFunctionOutput.allow(output_info=result)

    return ToolInputGuardrail(
        name="paybond_capability_verify",
        guardrail_function=_guard,
    )


__all__ = [
    "PaybondAgentsBinding",
    "PaybondCapabilityBinding",
    "paybond_capability_input_guardrail",
]
