"""
LangGraph integration — async tool-call wrapper that verifies Harbor capabilities before execution.

Requires ``pip install "paybond-kit[langgraph]"``.
"""

from __future__ import annotations

import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from paybond_kit.agent.interceptor import PaybondEvidenceSubmitError
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import PaybondUnregisteredSideEffectingToolError
from paybond_kit.capability_binding import PaybondCapabilityBinding
from paybond_kit.spend_guard import (
    PaybondSpendApprovalRequiredError,
    PaybondSpendDeniedError,
    PaybondSpendGuard,
)

SpendResolver = int | Callable[[Any], int]


def _require_tool_message() -> type[Any]:
    try:
        from langchain_core.messages import ToolMessage
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "langchain-core is required for paybond_kit.langgraph_hooks. "
            'Install with `pip install "paybond-kit[langgraph]"`.'
        ) from exc
    return ToolMessage


def _resolve_spend_cents(requested_spend_cents: SpendResolver, request: Any) -> int:
    raw = requested_spend_cents(request) if callable(requested_spend_cents) else requested_spend_cents
    return int(raw)


def _tool_call_fields(request: Any) -> tuple[str, str, Any]:
    call = request.tool_call
    name = str(call.get("name", "")).strip()
    tool_call_id = str(call.get("id", "")).strip()
    args = call.get("args") or {}
    return name, tool_call_id, args


def _deny_tool_message(
    ToolMessage: type[Any],
    *,
    name: str,
    tool_call_id: str,
    content: str,
) -> Any:
    return ToolMessage(
        content=content,
        name=name or "unknown",
        tool_call_id=tool_call_id,
        status="error",
    )


def paybond_awrap_tool_call(
    run: PaybondAgentRun,
) -> Callable[
    [Any, Callable[[Any], Awaitable[Any]]],
    Awaitable[Any],
]:
    """
    Build an ``awrap_tool_call`` interceptor backed by :class:`PaybondToolInterceptor`.

    Prefer this over :func:`paybond_awrap_tool_call_capability` when the agent run is bound
    with a tool registry (registry spend resolvers, auto-evidence, and ``defaultDeny``).
    """
    ToolMessage = _require_tool_message()

    async def _awrap(
        request: Any,
        execute: Callable[[Any], Awaitable[Any]],
    ) -> Any:
        name, tool_call_id, args = _tool_call_fields(request)
        if not name:
            return _deny_tool_message(
                ToolMessage,
                name="unknown",
                tool_call_id=tool_call_id,
                content="Paybond: tool call missing name",
            )
        if not tool_call_id:
            return _deny_tool_message(
                ToolMessage,
                name=name,
                tool_call_id="",
                content="Paybond: tool call missing id",
            )

        try:
            wrapped = await run.interceptor.wrap_execute(
                tool_name=name,
                tool_call_id=tool_call_id,
                arguments=args,
                execute=lambda: execute(request),
            )
            return wrapped.tool_result
        except PaybondUnregisteredSideEffectingToolError as exc:
            return _deny_tool_message(
                ToolMessage,
                name=name,
                tool_call_id=tool_call_id,
                content=f"Paybond capability denied: unregistered side-effecting tool ({exc})",
            )
        except PaybondSpendApprovalRequiredError as exc:
            decision_id = exc.result.decision_id
            suffix = f" (decision_id={decision_id})" if decision_id is not None else ""
            msg = exc.result.message or exc.result.code or "approval required"
            return _deny_tool_message(
                ToolMessage,
                name=name,
                tool_call_id=tool_call_id,
                content=f"Paybond capability approval required: {msg}{suffix}",
            )
        except PaybondSpendDeniedError as exc:
            msg = exc.result.message or exc.result.code or "capability denied"
            return _deny_tool_message(
                ToolMessage,
                name=name,
                tool_call_id=tool_call_id,
                content=f"Paybond capability denied: {msg}",
            )
        except PaybondEvidenceSubmitError as exc:
            return _deny_tool_message(
                ToolMessage,
                name=name,
                tool_call_id=tool_call_id,
                content=f"Paybond evidence submit failed: {exc}",
            )

    return _awrap


def _require_tool_node() -> type[Any]:
    try:
        from langgraph.prebuilt import ToolNode
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "langgraph is required for paybond_kit.langgraph_hooks.paybond_tool_node. "
            'Install with `pip install "paybond-kit[langgraph]"`.'
        ) from exc
    return ToolNode


def paybond_tool_node(
    tools: list[Any],
    run: PaybondAgentRun,
    **options: Any,
) -> Any:
    """
    Convenience factory: LangGraph ``ToolNode`` with Paybond spend guard + auto-evidence.

    Equivalent to ``ToolNode(tools, awrap_tool_call=paybond_awrap_tool_call(run), **options)``.
    """
    ToolNode = _require_tool_node()
    return ToolNode(tools, awrap_tool_call=paybond_awrap_tool_call(run), **options)


@dataclass(frozen=True, slots=True)
class PaybondLangGraphHooks:
    """LangGraph runner hooks: async tool-call wrapper and guarded ``ToolNode`` factory."""

    awrap_tool_call: Callable[[Any, Callable[[Any], Awaitable[Any]]], Awaitable[Any]]
    create_tool_node: Callable[..., Any]


def create_paybond_langgraph_hooks(run: PaybondAgentRun) -> PaybondLangGraphHooks:
    """Framework runner helper for LangGraph ``ToolNode`` and ``awrap_tool_call`` integration."""

    def create_tool_node(tools: list[Any], **node_options: Any) -> Any:
        return paybond_tool_node(tools, run, **node_options)

    return PaybondLangGraphHooks(
        awrap_tool_call=paybond_awrap_tool_call(run),
        create_tool_node=create_tool_node,
    )


def paybond_awrap_tool_call_capability(
    binding: PaybondCapabilityBinding,
    *,
    requested_spend_cents: SpendResolver = 0,
) -> Callable[
    [Any, Callable[[Any], Awaitable[Any]]],
    Awaitable[Any],
]:
    """
    Build an ``awrap_tool_call`` interceptor for :class:`langgraph.prebuilt.ToolNode`.

    .. deprecated::
        Use :func:`paybond_awrap_tool_call` with a :class:`PaybondAgentRun` bound to a tool
        registry instead. This helper does not support registry spend resolvers, ``defaultDeny``,
        or automatic evidence submission.

    The LangGraph tool ``name`` is forwarded to Harbor as the delegated ``operation`` string; keep
    intent ``allowed_tools`` entries aligned with those tool registration names.

    ``requested_spend_cents`` may be a static integer or a callable that derives spend from the
    LangGraph tool-call request (for example from ``request.tool_call["args"]``).

    On deny, returns a :class:`langchain_core.messages.ToolMessage` with ``status=\"error\"`` so the
    model can recover without executing the tool.
    """
    warnings.warn(
        "paybond_awrap_tool_call_capability(binding) is deprecated; use "
        "paybond_awrap_tool_call(run) with PaybondAgentRun.bind(...) and a tool registry. "
        "See https://docs.paybond.ai/kit/agent-integrations#langgraph",
        DeprecationWarning,
        stacklevel=2,
    )
    ToolMessage = _require_tool_message()
    guard = PaybondSpendGuard(binding)

    async def _awrap(
        request: Any,
        execute: Callable[[Any], Awaitable[Any]],
    ) -> Any:
        name, tool_call_id, _args = _tool_call_fields(request)
        if not name:
            return _deny_tool_message(
                ToolMessage,
                name="unknown",
                tool_call_id=tool_call_id,
                content="Paybond: tool call missing name",
            )

        resolved_spend = _resolve_spend_cents(requested_spend_cents, request)
        result = await guard.authorize_spend(
            operation=name,
            requested_spend_cents=resolved_spend,
            tool_call_id=tool_call_id or None,
            tool_name=name,
        )
        if not result.allow:
            msg = result.message or result.code or "capability denied"
            if result.approval_required:
                decision_id = result.decision_id
                suffix = f" (decision_id={decision_id})" if decision_id is not None else ""
                return _deny_tool_message(
                    ToolMessage,
                    name=name,
                    tool_call_id=tool_call_id,
                    content=f"Paybond capability approval required: {msg}{suffix}",
                )
            return _deny_tool_message(
                ToolMessage,
                name=name,
                tool_call_id=tool_call_id,
                content=f"Paybond capability denied: {msg}",
            )

        try:
            out = await execute(request)
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

    return _awrap


__all__ = [
    "PaybondLangGraphHooks",
    "SpendResolver",
    "create_paybond_langgraph_hooks",
    "paybond_awrap_tool_call",
    "paybond_awrap_tool_call_capability",
    "paybond_tool_node",
]
