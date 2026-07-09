"""Runtime-neutral agent tool adapters for Paybond spend authorization."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import TypeVar

from paybond_kit.harbor import VerifyCapabilityResult
from paybond_kit.spend_guard import (
    PaybondSpendApprovalRequiredError,
    PaybondSpendDeniedError,
    PaybondSpendGuard,
    _SpendGuardSource,
)

TCall = TypeVar("TCall")
R = TypeVar("R")


OperationResolver = str | Callable[[TCall], str]
SpendResolver = int | Callable[[TCall], int]
ToolCallExecutor = Callable[[TCall], R | Awaitable[R]]
ToolCallDenyHandler = Callable[[VerifyCapabilityResult, TCall], R | Awaitable[R]]


def _resolve_operation(operation: OperationResolver[TCall], call: TCall) -> str:
    raw = operation(call) if callable(operation) else operation
    value = str(raw).strip()
    if not value:
        raise ValueError("Paybond operation must be a non-empty string")
    return value


def _resolve_spend_cents(
    requested_spend_cents: SpendResolver[TCall],
    call: TCall,
) -> int:
    raw = requested_spend_cents(call) if callable(requested_spend_cents) else requested_spend_cents
    return int(raw)


async def _maybe_await(value: R | Awaitable[R]) -> R:
    if inspect.isawaitable(value):
        return await value
    return value


def paybond_runtime_tool_call_adapter(
    source: _SpendGuardSource,
    *,
    operation: OperationResolver[TCall],
    execute: ToolCallExecutor[TCall, R],
    requested_spend_cents: SpendResolver[TCall] = 0,
    on_deny: ToolCallDenyHandler[TCall, R] | None = None,
) -> Callable[[TCall], Awaitable[R]]:
    """
    Wrap a generic agent-runtime tool call with Paybond capability verification.

    Use this for SDKs that expose a tool-call object plus an application-owned executor, including
    provider SDKs, local-model runtimes, queues, and custom orchestrators. Frameworks with a
    dedicated hook contract can still use their specific adapter, such as LangGraph
    ``awrap_tool_call``.

    Args:
        source: Object with ``harbor``, ``intent_id``, and ``capability_token`` attributes.
        operation: Static operation name, or a callable that extracts it from the runtime tool call.
        execute: Application-owned function that performs the side-effecting work after allow.
        requested_spend_cents: Static spend hint, or a callable that extracts it from the call.
        on_deny: Optional runtime-specific denial mapper. If omitted, hard denials raise
            :class:`PaybondSpendDeniedError` and approval holds raise
            :class:`PaybondSpendApprovalRequiredError`.
    """

    guard = PaybondSpendGuard(source)

    async def wrapped(call: TCall) -> R:
        resolved_operation = _resolve_operation(operation, call)
        resolved_spend = _resolve_spend_cents(requested_spend_cents, call)
        result = await guard.authorize_spend(
            operation=resolved_operation,
            requested_spend_cents=resolved_spend,
        )
        if not result.allow:
            if on_deny is not None:
                return await _maybe_await(on_deny(result, call))
            if result.approval_required:
                raise PaybondSpendApprovalRequiredError(result)
            raise PaybondSpendDeniedError(result)
        try:
            out = await _maybe_await(execute(call))
            if result.decision_id is not None:
                await guard.complete_spend_authorization(str(result.decision_id), "consumed")
            return out
        except Exception:
            if result.decision_id is not None:
                try:
                    await guard.complete_spend_authorization(str(result.decision_id), "released")
                except Exception:
                    pass
            raise

    return wrapped


__all__ = [
    "OperationResolver",
    "SpendResolver",
    "ToolCallDenyHandler",
    "ToolCallExecutor",
    "paybond_runtime_tool_call_adapter",
]
