"""Spend-oriented guard helpers over Paybond capability verification."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, ParamSpec, TypeVar

from paybond_kit.capability_binding import PaybondCapabilityBinding
from paybond_kit.harbor import VerifyCapabilityResult

P = ParamSpec("P")
R = TypeVar("R")


class PaybondSpendDeniedError(RuntimeError):
    """Raised when Paybond denies a guarded spend or tool invocation."""

    def __init__(self, result: VerifyCapabilityResult) -> None:
        reason = result.message or result.code or "denied"
        super().__init__(f"Paybond spend authorization denied: {reason}")
        self.result = result


@dataclass(frozen=True)
class PaybondSpendGuard:
    """Authorize delegated agent spend before side-effecting tool work runs."""

    binding: PaybondCapabilityBinding

    async def verify_spend_capability(
        self,
        *,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> VerifyCapabilityResult:
        return await self.binding.verify_spend_capability(
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    async def authorize_spend(
        self,
        *,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> VerifyCapabilityResult:
        return await self.binding.authorize_spend(
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    async def assert_spend_authorized(
        self,
        *,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> VerifyCapabilityResult:
        result = await self.authorize_spend(
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )
        if not result.allow:
            raise PaybondSpendDeniedError(result)
        return result

    def guard_tool(
        self,
        *,
        operation: str,
        requested_spend_cents: int = 0,
        handler: Callable[P, R | Awaitable[R]],
    ) -> Callable[P, Awaitable[R]]:
        async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            await self.assert_spend_authorized(
                operation=operation,
                requested_spend_cents=requested_spend_cents,
            )
            out = handler(*args, **kwargs)
            if inspect.isawaitable(out):
                return await out
            return out

        return wrapped


async def authorize_spend(
    binding: PaybondCapabilityBinding,
    *,
    operation: str,
    requested_spend_cents: int = 0,
) -> VerifyCapabilityResult:
    return await binding.authorize_spend(
        operation=operation,
        requested_spend_cents=requested_spend_cents,
    )


def guard_tool(
    binding: PaybondCapabilityBinding,
    *,
    operation: str,
    requested_spend_cents: int = 0,
    handler: Callable[P, R | Awaitable[R]],
) -> Callable[P, Awaitable[R]]:
    return PaybondSpendGuard(binding).guard_tool(
        operation=operation,
        requested_spend_cents=requested_spend_cents,
        handler=handler,
    )


paybond_openai_tool_spend_guard = guard_tool
paybond_anthropic_tool_spend_guard = guard_tool
paybond_claude_tool_spend_guard = guard_tool
paybond_gemini_tool_spend_guard = guard_tool
paybond_google_ai_tool_spend_guard = guard_tool
paybond_langgraph_tool_spend_guard = guard_tool
paybond_mcp_tool_spend_guard = guard_tool


__all__ = [
    "PaybondSpendDeniedError",
    "PaybondSpendGuard",
    "authorize_spend",
    "guard_tool",
    "paybond_anthropic_tool_spend_guard",
    "paybond_claude_tool_spend_guard",
    "paybond_gemini_tool_spend_guard",
    "paybond_google_ai_tool_spend_guard",
    "paybond_langgraph_tool_spend_guard",
    "paybond_mcp_tool_spend_guard",
    "paybond_openai_tool_spend_guard",
]
