"""Pydantic AI integration — wrap ``Tool`` / callable execution with Paybond middleware."""

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
from paybond_kit.pydantic_ai._peer import is_pydantic_ai_tool, pydantic_ai_runtime_available
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError


@dataclass(frozen=True, slots=True)
class PaybondPydanticAIConfig:
    """Runner config for Pydantic AI agents and tool lists."""

    tools: list[Any]
    wrap_tool: Callable[[Any], Any]


def _require_pydantic_ai() -> Any:
    from paybond_kit.pydantic_ai._peer import _require_pydantic_ai as _load

    return _load()


def _model_retry_cls() -> Any:
    return getattr(_require_pydantic_ai(), "ModelRetry")


def _resolve_tool_name(tool: Any) -> str:
    name = getattr(tool, "name", None)
    if isinstance(name, str) and name.strip():
        return name.strip()
    raise TypeError("each Pydantic AI tool must expose a non-empty name")


def _arguments_from_callable(
    target: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    skip_first: bool = False,
) -> dict[str, Any]:
    if kwargs:
        return dict(kwargs)
    if not args:
        return {}
    effective_args = args[1:] if skip_first and args else args
    if not effective_args:
        return {}
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
        if skip_first and parameters:
            parameters = parameters[1:]
        if len(parameters) == len(effective_args):
            return {
                parameter.name: value
                for parameter, value in zip(parameters, effective_args, strict=False)
            }
    except (TypeError, ValueError):
        pass
    if len(effective_args) == 1 and isinstance(effective_args[0], dict):
        return dict(effective_args[0])
    return {"args": list(effective_args)}


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
        raise _model_retry_cls()(_paybond_error_message(exc)) from exc


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
    takes_ctx: bool = False,
) -> Callable[..., Any]:
    """
    Wrap ``target`` while preserving its callable metadata.

    Pydantic AI rebuilds tool JSON schema from the wrapped function (via
    ``function_schema``). Without ``update_wrapper``, a bare ``*args/**kwargs``
    guard collapses the schema and breaks model tool calling. Do **not** reuse
    the original ``Tool.function_schema`` — Agent execution calls
    ``function_schema.call``, which would bypass the guard.
    """
    if inspect.iscoroutinefunction(target):

        async def guarded_async(*args: Any, **kwargs: Any) -> Any:
            tool_call_id = str(uuid.uuid4())
            arguments = _arguments_from_callable(
                target, args, kwargs, skip_first=takes_ctx
            )

            async def execute() -> Any:
                raw = await target(*args, **kwargs)
                return _coerce_tool_result(raw)

            return await _guard_tool_execution(
                run,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                execute=execute,
            )

        return functools.update_wrapper(guarded_async, target)

    def guarded_sync(*args: Any, **kwargs: Any) -> Any:
        tool_call_id = str(uuid.uuid4())
        arguments = _arguments_from_callable(target, args, kwargs, skip_first=takes_ctx)

        async def execute() -> Any:
            raw = target(*args, **kwargs)
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

    return functools.update_wrapper(guarded_sync, target)


def _rebuild_tool(original: Any, guarded_function: Callable[..., Any]) -> Any:
    tool_cls = getattr(_require_pydantic_ai(), "Tool")
    # Rebuild from the guarded callable so function_schema.call hits Paybond.
    # Signature/doc metadata must already be preserved on guarded_function.
    kwargs: dict[str, Any] = {
        "takes_ctx": getattr(original, "takes_ctx", None),
        "max_retries": getattr(original, "max_retries", None),
        "name": getattr(original, "name", None),
        "description": getattr(original, "description", None),
        "prepare": getattr(original, "prepare", None),
        "args_validator": getattr(original, "args_validator", None),
        "docstring_format": getattr(original, "docstring_format", "auto"),
        "require_parameter_descriptions": getattr(
            original, "require_parameter_descriptions", False
        ),
        "strict": getattr(original, "strict", None),
        "sequential": getattr(original, "sequential", False),
        "requires_approval": getattr(original, "requires_approval", False),
        "metadata": getattr(original, "metadata", None),
        "timeout": getattr(original, "timeout", None),
        "defer_loading": getattr(original, "defer_loading", False),
        "include_return_schema": getattr(original, "include_return_schema", None),
    }
    return tool_cls(guarded_function, **kwargs)


def _wrap_pydantic_ai_tool(run: PaybondAgentRun, tool: Any) -> Any:
    tool_name = _resolve_tool_name(tool)
    if not run.registry.is_side_effecting(tool_name):
        return tool

    function = getattr(tool, "function", None)
    if not callable(function):
        raise TypeError(
            "each Pydantic AI tool must be a Tool instance or callable with an executable function"
        )

    takes_ctx = bool(getattr(tool, "takes_ctx", False))
    guarded = _wrap_callable_target(
        run,
        tool_name=tool_name,
        target=function,
        takes_ctx=takes_ctx,
    )
    return _rebuild_tool(tool, guarded)


def _normalize_pydantic_ai_tools(tools: Sequence[Any]) -> list[Any]:
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        raise TypeError(
            "pydantic-ai framework tools must be a sequence of Tool instances or callables"
        )

    tool_cls = getattr(_require_pydantic_ai(), "Tool")
    normalized: list[Any] = []
    for tool in tools:
        if is_pydantic_ai_tool(tool):
            normalized.append(tool)
            continue
        if callable(tool):
            if not pydantic_ai_runtime_available():
                raise ImportError(
                    "pydantic-ai is required to wrap plain callables with Tool. "
                    'Install with `pip install "paybond-kit[pydantic-ai]"`.'
                )
            if not getattr(tool, "__doc__", None):
                tool.__doc__ = f"Tool {getattr(tool, '__name__', 'pydantic_ai_tool')}"
            normalized.append(tool_cls(tool))
            continue
        raise TypeError(
            "each Pydantic AI tool must be a Tool instance or a plain callable"
        )
    return normalized


def create_paybond_pydantic_ai_config(
    run: PaybondAgentRun,
    tools: Sequence[Any],
) -> PaybondPydanticAIConfig:
    """
    Wrap Pydantic AI ``Tool`` / callable instances with Paybond middleware.

    Returns guarded tools plus a ``wrap_tool`` helper for incremental wiring.
    Prefer ``Agent(tools=config.tools)`` or ``FunctionToolset`` with pre-wrapped tools.
    """
    _require_pydantic_ai()
    normalized = _normalize_pydantic_ai_tools(tools)
    guarded = [_wrap_pydantic_ai_tool(run, tool) for tool in normalized]
    return PaybondPydanticAIConfig(
        tools=guarded,
        wrap_tool=lambda tool: _wrap_pydantic_ai_tool(
            run, _normalize_pydantic_ai_tools([tool])[0]
        ),
    )
