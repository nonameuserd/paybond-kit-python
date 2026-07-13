"""Microsoft Agent Framework integration — function middleware gates paid tools via ``wrap_execute``."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from paybond_kit.agent.interceptor import PaybondEvidenceSubmitError
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import PaybondUnregisteredSideEffectingToolError
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError


@dataclass(frozen=True, slots=True)
class PaybondMicrosoftAgentFrameworkConfig:
    """
    Runner config for Microsoft Agent Framework agents.

    Attach ``middleware`` on the agent (required). Tools pass through unchanged in v1 —
    Harbor governance runs in function middleware, not via tool-body mutation.
    """

    tools: list[Any]
    middleware: list[Any]
    wrap_tool: Callable[[Any], Any]


def _require_function_middleware() -> Any:
    from paybond_kit.microsoft_agent_framework._peer import (
        _require_function_middleware as _load,
    )

    return _load()


def _paybond_error_message(exc: BaseException) -> str:
    if isinstance(exc, PaybondUnregisteredSideEffectingToolError):
        return f"Paybond capability denied: unregistered side-effecting tool ({exc})"
    if isinstance(exc, PaybondSpendApprovalRequiredError):
        decision_id = exc.result.decision_id
        suffix = f" (decision_id={decision_id})" if decision_id is not None else ""
        msg = exc.result.message or exc.result.code or "approval required"
        return f"Paybond capability approval required: {msg}{suffix}"
    if isinstance(exc, PaybondSpendDeniedError):
        msg = exc.result.message or exc.result.code or "capability denied"
        return f"Paybond capability denied: {msg}"
    if isinstance(exc, PaybondEvidenceSubmitError):
        return f"Paybond evidence submit failed: {exc}"
    return str(exc)


def _normalize_arguments(arguments: Any) -> dict[str, Any]:
    """Normalize MAF ``BaseModel | Mapping`` tool args for spend resolvers."""

    if arguments is None:
        return {}
    if isinstance(arguments, Mapping):
        return dict(arguments)
    model_dump = getattr(arguments, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    as_dict = getattr(arguments, "dict", None)
    if callable(as_dict):
        dumped = as_dict()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    raise TypeError(
        "Microsoft Agent Framework tool arguments must be a Mapping or Pydantic BaseModel"
    )


def _resolve_tool_name(context: Any) -> str:
    function = getattr(context, "function", None)
    name = getattr(function, "name", None)
    if isinstance(name, str) and name.strip():
        return name.strip()
    raise TypeError("FunctionInvocationContext.function must expose a non-empty name")


def _resolve_tool_call_id(context: Any) -> str:
    metadata = getattr(context, "metadata", None)
    if isinstance(metadata, Mapping):
        call_id = metadata.get("call_id")
        if isinstance(call_id, str) and call_id.strip():
            return call_id.strip()
    return str(uuid.uuid4())


async def process_paybond_function_invocation(
    run: PaybondAgentRun,
    context: Any,
    call_next: Callable[[], Awaitable[None]],
) -> None:
    """
    Harbor-gated MAF function middleware body.

    On deny / approval hold: set ``context.result`` to a clear string and do **not**
    call ``call_next()`` so the model sees a tool result without stopping the whole
    function-calling loop (avoid ``MiddlewareTermination`` / ``terminate`` for holds).
    """

    tool_name = _resolve_tool_name(context)
    if not run.registry.is_side_effecting(tool_name):
        await call_next()
        return

    tool_call_id = _resolve_tool_call_id(context)
    arguments = _normalize_arguments(getattr(context, "arguments", None))

    async def execute() -> Any:
        await call_next()
        return getattr(context, "result", None)

    try:
        wrapped = await run.interceptor.wrap_execute(
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            arguments=arguments,
            approval_token=run.get_approval_token(tool_call_id),
            execute=execute,
        )
        context.result = wrapped.tool_result
    except (
        PaybondUnregisteredSideEffectingToolError,
        PaybondSpendApprovalRequiredError,
        PaybondSpendDeniedError,
        PaybondEvidenceSubmitError,
    ) as exc:
        context.result = _paybond_error_message(exc)


def create_paybond_microsoft_agent_framework_middleware(run: PaybondAgentRun) -> Any:
    """
    Build a MAF ``FunctionMiddleware`` that gates side-effecting tools via Harbor.

    Attach on ``Agent(..., middleware=[middleware])``. With
    ``@tool(approval_mode="never_require")``, Paybond middleware is the sole spend
    authority — do not compose MAF ``always_require`` HITL with Paybond holds in the
    same sample.

    Tenant isolation: uses only authenticated :class:`PaybondAgentRun` context —
    never invent tenant IDs from MAF session state or agent names.
    """

    function_middleware_cls = _require_function_middleware()

    class PaybondMicrosoftAgentFrameworkMiddleware(function_middleware_cls):
        """Paybond Harbor spend gate for Microsoft Agent Framework function calls."""

        async def process(
            self,
            context: Any,
            call_next: Callable[[], Awaitable[None]],
        ) -> None:
            await process_paybond_function_invocation(run, context, call_next)

    return PaybondMicrosoftAgentFrameworkMiddleware()


def _normalize_tools(tools: Sequence[Any] | None) -> list[Any]:
    if tools is None:
        return []
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        raise TypeError(
            "microsoft-agent-framework tools must be a sequence of tool callables or AIFunction instances"
        )
    return list(tools)


def create_paybond_microsoft_agent_framework_config(
    run: PaybondAgentRun,
    tools: Sequence[Any] | None = None,
) -> PaybondMicrosoftAgentFrameworkConfig:
    """
    Build MAF wiring: passthrough tools plus required function middleware.

    Returns ``{ tools, middleware, wrap_tool }``. Callers **must** attach
    ``middleware`` on the agent — tools-only wrap is insufficient for this
    framework (same class of footgun as LangGraph without ``awrap_tool_call``).
    """

    _require_function_middleware()
    normalized = _normalize_tools(tools)
    middleware = create_paybond_microsoft_agent_framework_middleware(run)
    return PaybondMicrosoftAgentFrameworkConfig(
        tools=normalized,
        middleware=[middleware],
        wrap_tool=lambda tool: tool,
    )
