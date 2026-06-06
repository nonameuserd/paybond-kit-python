import asyncio
import json
import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Any, TypeVar

from paybond_kit import (
    Paybond,
    SandboxGuardrailBootstrapResult,
    SandboxGuardrailEvidenceResult,
)

DEFAULT_OPERATION = "paid_tool.smoke_test"
DEFAULT_REQUESTED_SPEND_CENTS = 500

TInput = TypeVar("TInput")
TResult = TypeVar("TResult")
PaidToolHandler = Callable[[TInput], TResult | Awaitable[TResult]]


async def open_paybond_from_env() -> Paybond:
    api_key = os.environ.get("PAYBOND_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("PAYBOND_API_KEY is required")

    return await Paybond.open(
        api_key=api_key,
        gateway_base_url=os.environ.get("PAYBOND_GATEWAY_BASE_URL") or "https://api.paybond.ai",
        expected_environment="sandbox",
    )


async def bootstrap_sandbox_guardrail_intent(
    paybond: Paybond,
    *,
    operation: str = DEFAULT_OPERATION,
    requested_spend_cents: int = DEFAULT_REQUESTED_SPEND_CENTS,
    currency: str = "usd",
    evidence_schema: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> SandboxGuardrailBootstrapResult:
    return await paybond.guardrails.bootstrap_sandbox(
        operation=operation,
        requested_spend_cents=requested_spend_cents,
        currency=currency,
        evidence_schema=evidence_schema
        or {
            "type": "object",
            "required": ["confirmation_id", "charged_cents"],
            "properties": {
                "confirmation_id": {"type": "string"},
                "charged_cents": {"type": "integer"},
            },
        },
        metadata=metadata,
        idempotency_key=idempotency_key,
    )


def wrap_paid_tool(
    paybond: Paybond,
    guardrail: SandboxGuardrailBootstrapResult,
    handler: PaidToolHandler[TInput, TResult],
) -> Callable[[TInput], Awaitable[TResult]]:
    if not guardrail.capability_token.strip():
        raise RuntimeError("sandbox guardrail bootstrap did not return a capability token")

    guard = paybond.spend_guard(guardrail.intent_id, guardrail.capability_token)

    # Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.
    return guard.guard_tool(
        operation=guardrail.operation,
        requested_spend_cents=guardrail.requested_spend_cents,
        handler=handler,
    )


async def submit_sandbox_evidence(
    paybond: Paybond,
    guardrail: SandboxGuardrailBootstrapResult,
    payload: Mapping[str, Any],
    *,
    operation: str | None = None,
    requested_spend_cents: int | None = None,
    artifacts: list[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> SandboxGuardrailEvidenceResult:
    return await paybond.guardrails.submit_sandbox_evidence(
        guardrail.intent_id,
        payload,
        artifacts=artifacts,
        operation=operation if operation is not None else guardrail.operation,
        requested_spend_cents=(
            requested_spend_cents
            if requested_spend_cents is not None
            else guardrail.requested_spend_cents
        ),
        metadata=metadata,
        idempotency_key=idempotency_key,
    )


async def replaceable_smoke_test_paid_tool(input: Mapping[str, Any]) -> dict[str, Any]:
    # Replace this sandbox smoke-test function with the real paid side-effecting tool.
    item_id = str(input.get("item_id", "replace-with-your-tool-input"))
    max_price_cents = int(input.get("max_price_cents", DEFAULT_REQUESTED_SPEND_CENTS))
    return {
        "confirmation_id": "sandbox-confirmation-" + item_id,
        "item_id": item_id,
        "charged_cents": min(max_price_cents, DEFAULT_REQUESTED_SPEND_CENTS),
        "sandbox": True,
    }


async def run_sandbox_smoke_path() -> dict[str, Any]:
    paybond = await open_paybond_from_env()
    guardrail = await bootstrap_sandbox_guardrail_intent(paybond)
    guarded_tool = wrap_paid_tool(paybond, guardrail, replaceable_smoke_test_paid_tool)
    tool_result = await guarded_tool(
        {
            "item_id": "replace-with-your-tool-input",
            "max_price_cents": DEFAULT_REQUESTED_SPEND_CENTS,
        }
    )
    evidence = await submit_sandbox_evidence(
        paybond,
        guardrail,
        {
            "confirmation_id": tool_result["confirmation_id"],
            "charged_cents": tool_result["charged_cents"],
            "item_id": tool_result["item_id"],
            "sandbox": tool_result["sandbox"],
        },
    )
    return {"guardrail": guardrail, "tool_result": tool_result, "evidence": evidence}


def _json_default(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    return str(value)


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run_sandbox_smoke_path()), default=_json_default, indent=2))
