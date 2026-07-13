"""Google ADK integration — wrap ``FunctionTool`` / callable execution with Paybond middleware."""

from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import inspect
import json
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from paybond_kit.agent.interceptor import PaybondEvidenceSubmitError
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import PaybondUnregisteredSideEffectingToolError
from paybond_kit.google_adk._peer import (
    google_adk_runtime_available,
    is_google_adk_function_tool,
)
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError


@dataclass(frozen=True, slots=True)
class PaybondGoogleAdkConfig:
    """Runner config for Google ADK agents and tool lists."""

    tools: list[Any]
    wrap_tool: Callable[[Any], Any]


def _require_function_tool() -> Any:
    from paybond_kit.google_adk._peer import _require_function_tool as _load

    return _load()


def _resolve_tool_name(tool: Any) -> str:
    name = getattr(tool, "name", None)
    if isinstance(name, str) and name.strip():
        return name.strip()
    func = getattr(tool, "func", None)
    if callable(func):
        func_name = getattr(func, "__name__", None)
        if isinstance(func_name, str) and func_name.strip():
            return func_name.strip()
    raise TypeError("each Google ADK tool must expose a non-empty name")


def _arguments_from_callable(
    target: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    skip_context: bool = True,
) -> dict[str, Any]:
    if kwargs:
        filtered = dict(kwargs)
        if skip_context:
            filtered.pop("tool_context", None)
            for key, value in list(filtered.items()):
                if type(value).__name__ == "ToolContext":
                    filtered.pop(key, None)
        return filtered
    if not args:
        return {}
    if len(args) == 1 and isinstance(args[0], dict):
        return dict(args[0])
    try:
        signature = inspect.signature(target)
        parameters = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind
            not in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            )
        ]
        if len(parameters) == len(args):
            return {
                parameter.name: value
                for parameter, value in zip(parameters, args, strict=False)
                if not (skip_context and parameter.name == "tool_context")
            }
    except (TypeError, ValueError):
        pass
    return {"args": list(args)}


def _coerce_tool_result(raw: Any) -> Any:
    """Parse JSON tool outputs so evidence mappers receive structured dicts."""

    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return raw
    return raw


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


def _tool_call_id_from_invocation(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> str:
    """Prefer ADK ``ToolContext.function_call_id`` when the runner injects context."""

    candidates: list[Any] = []
    if "tool_context" in kwargs:
        candidates.append(kwargs["tool_context"])
    for value in kwargs.values():
        if type(value).__name__ == "ToolContext":
            candidates.append(value)
    for value in args:
        if type(value).__name__ == "ToolContext":
            candidates.append(value)
    for context in candidates:
        call_id = getattr(context, "function_call_id", None)
        if isinstance(call_id, str) and call_id.strip():
            return call_id.strip()
    return str(uuid.uuid4())


def _attach_tool_context_signature(
    wrapper: Callable[..., Any],
    target: Callable[..., Any],
) -> Callable[..., Any]:
    """
    Preserve the target schema for ADK while accepting injected ``tool_context``.

    ``inspect.signature`` follows ``__wrapped__``, so a bare ``*args/**kwargs``
    guard would otherwise hide ``tool_context`` from ADK's ``run_async`` injection
    and lose ``function_call_id`` correlation.
    """

    functools.update_wrapper(wrapper, target)
    try:
        original = inspect.signature(target)
    except (TypeError, ValueError):
        return wrapper
    if any(parameter.name == "tool_context" for parameter in original.parameters.values()):
        return wrapper

    annotation: Any = Any
    try:
        from google.adk.tools.tool_context import ToolContext

        annotation = ToolContext | None
    except ImportError:
        pass

    parameters = [
        *original.parameters.values(),
        inspect.Parameter(
            "tool_context",
            kind=inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=annotation,
        ),
    ]
    wrapper.__signature__ = original.replace(parameters=parameters)  # type: ignore[attr-defined]
    return wrapper


def _call_original_tool(
    target: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> Any:
    """Invoke ``target`` without forwarding ADK ``tool_context`` unless declared."""

    try:
        signature = inspect.signature(target)
        accepts_context = "tool_context" in signature.parameters or any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        )
        accepts_var_positional = any(
            parameter.kind == inspect.Parameter.VAR_POSITIONAL
            for parameter in signature.parameters.values()
        )
    except (TypeError, ValueError):
        accepts_context = True
        accepts_var_positional = True

    call_kwargs = dict(kwargs)
    call_args = args
    if not accepts_context:
        call_kwargs = {
            key: value
            for key, value in call_kwargs.items()
            if key != "tool_context" and type(value).__name__ != "ToolContext"
        }
        if not accepts_var_positional:
            call_args = tuple(
                value for value in call_args if type(value).__name__ != "ToolContext"
            )
    return target(*call_args, **call_kwargs)


async def _guard_tool_execution(
    run: PaybondAgentRun,
    *,
    tool_name: str,
    tool_call_id: str,
    arguments: dict[str, Any],
    execute: Callable[[], Any],
) -> Any:
    try:
        wrapped = await run.interceptor.wrap_execute(
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            arguments=arguments,
            approval_token=run.get_approval_token(tool_call_id),
            execute=execute,
        )
        return wrapped.tool_result
    except PaybondUnregisteredSideEffectingToolError:
        raise
    except (
        PaybondSpendApprovalRequiredError,
        PaybondSpendDeniedError,
        PaybondEvidenceSubmitError,
    ) as exc:
        # Re-raise with a clear Paybond message so the ADK agent loop surfaces it.
        raise RuntimeError(_paybond_error_message(exc)) from exc


def _run_async_guard(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _wrap_callable_target(
    run: PaybondAgentRun,
    *,
    tool_name: str,
    target: Callable[..., Any],
) -> Callable[..., Any]:
    """Wrap ``target`` while preserving callable metadata for ADK schema inspection."""

    if inspect.iscoroutinefunction(target):

        async def guarded_async(*args: Any, **kwargs: Any) -> Any:
            tool_call_id = _tool_call_id_from_invocation(args, kwargs)
            arguments = _arguments_from_callable(target, args, kwargs)

            async def execute() -> Any:
                raw = _call_original_tool(target, args, kwargs)
                if inspect.isawaitable(raw):
                    raw = await raw
                return _coerce_tool_result(raw)

            return await _guard_tool_execution(
                run,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                execute=execute,
            )

        return _attach_tool_context_signature(guarded_async, target)

    def guarded_sync(*args: Any, **kwargs: Any) -> Any:
        tool_call_id = _tool_call_id_from_invocation(args, kwargs)
        arguments = _arguments_from_callable(target, args, kwargs)

        async def execute() -> Any:
            raw = _call_original_tool(target, args, kwargs)
            if inspect.isawaitable(raw):
                raw = await raw
            return _coerce_tool_result(raw)

        return _run_async_guard(
            _guard_tool_execution(
                run,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                execute=execute,
            )
        )

    return _attach_tool_context_signature(guarded_sync, target)


def _rebuild_function_tool(original: Any, guarded_function: Callable[..., Any]) -> Any:
    """Rebuild with the original tool class so LongRunningFunctionTool stays long-running."""

    tool_cls = type(original)
    require_confirmation = getattr(original, "_require_confirmation", False)
    try:
        return tool_cls(guarded_function, require_confirmation=require_confirmation)
    except TypeError:
        # LongRunningFunctionTool (and similar subclasses) only accept ``func``.
        return tool_cls(guarded_function)


def _wrap_google_adk_tool(run: PaybondAgentRun, tool: Any) -> Any:
    tool_name = _resolve_tool_name(tool)
    if not run.registry.is_side_effecting(tool_name):
        return tool

    function = getattr(tool, "func", None)
    if not callable(function):
        raise TypeError(
            "each Google ADK tool must be a FunctionTool instance or callable with an executable func"
        )

    guarded = _wrap_callable_target(run, tool_name=tool_name, target=function)
    return _rebuild_function_tool(tool, guarded)


def _normalize_google_adk_tools(tools: Sequence[Any]) -> list[Any]:
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        raise TypeError(
            "google-adk framework tools must be a sequence of FunctionTool instances or callables"
        )

    function_tool_cls = _require_function_tool()
    normalized: list[Any] = []
    for tool in tools:
        if is_google_adk_function_tool(tool):
            normalized.append(tool)
            continue
        if callable(tool):
            if not google_adk_runtime_available():
                raise ImportError(
                    "google-adk is required to wrap plain callables with FunctionTool. "
                    'Install with `pip install "paybond-kit[google-adk]"`.'
                )
            if not getattr(tool, "__doc__", None):
                tool.__doc__ = f"Tool {getattr(tool, '__name__', 'google_adk_tool')}"
            normalized.append(function_tool_cls(tool))
            continue
        raise TypeError(
            "each Google ADK tool must be a FunctionTool instance or a plain callable"
        )
    return normalized


def create_paybond_google_adk_config(
    run: PaybondAgentRun,
    tools: Sequence[Any],
) -> PaybondGoogleAdkConfig:
    """
    Wrap Google ADK ``FunctionTool`` / callable instances with Paybond middleware.

    Returns guarded tools plus a ``wrap_tool`` helper for incremental wiring.
    Prefer ``LlmAgent(tools=config.tools)`` with pre-wrapped tools.

    Tenant isolation: wrap uses only authenticated :class:`PaybondAgentRun`
    context — never invent tenant IDs from ADK session state or agent names.
    """
    _require_function_tool()
    normalized = _normalize_google_adk_tools(tools)
    guarded = [_wrap_google_adk_tool(run, tool) for tool in normalized]
    return PaybondGoogleAdkConfig(
        tools=guarded,
        wrap_tool=lambda tool: _wrap_google_adk_tool(
            run, _normalize_google_adk_tools([tool])[0]
        ),
    )


# Public aliases matching the bilingual Kit surface.
instrument = create_paybond_google_adk_config
instrument_google_adk = create_paybond_google_adk_config
wrap_tools = create_paybond_google_adk_config
