"""
LangGraph integration — async tool-call wrapper that verifies Harbor capabilities before execution.

Requires ``pip install --pre "paybond-kit[langgraph]"``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from paybond_kit.capability_binding import PaybondCapabilityBinding


def paybond_awrap_tool_call_capability(
    binding: PaybondCapabilityBinding,
    *,
    requested_spend_cents: int = 0,
) -> Callable[
    [Any, Callable[[Any], Awaitable[Any]]],
    Awaitable[Any],
]:
    """
    Build an ``awrap_tool_call`` interceptor for :class:`langgraph.prebuilt.ToolNode`.

    The LangGraph tool ``name`` is forwarded to Harbor as the delegated ``operation`` string; keep
    intent ``allowed_tools`` entries aligned with those tool registration names (same contract as
    OpenAI Agents ``qualified_tool_name`` when tools are registered without an extra namespace).

    On deny, returns a :class:`langchain_core.messages.ToolMessage` with ``status=\"error\"`` so the
    model can recover without executing the tool.
    """
    try:
        from langchain_core.messages import ToolMessage
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "langchain-core is required for paybond_kit.langgraph_hooks. "
            'Install with `pip install --pre "paybond-kit[langgraph]"`.'
        ) from exc

    async def _awrap(
        request: ToolCallRequest,
        execute: Callable[[ToolCallRequest], Awaitable[ToolMessage | Any]],
    ) -> Any:
        call = request.tool_call
        name = str(call.get("name", "")).strip()
        if not name:
            return ToolMessage(
                content="Paybond: tool call missing name",
                name="unknown",
                tool_call_id=str(call.get("id", "")),
                status="error",
            )
        result = await binding.harbor.verify_capability(
            intent_id=binding.intent_id,
            token=binding.capability_token,
            operation=name,
            requested_spend_cents=requested_spend_cents,
        )
        if not result.allow:
            msg = result.message or result.code or "capability denied"
            return ToolMessage(
                content=f"Paybond capability denied: {msg}",
                name=name,
                tool_call_id=str(call.get("id", "")),
                status="error",
            )
        return await execute(request)

    return _awrap


__all__ = ["paybond_awrap_tool_call_capability"]
