"""CrewAI integration — wrap ``@tool`` / ``BaseTool`` execution with Paybond middleware."""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import json
import types
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from paybond_kit.agent.interceptor import PaybondEvidenceSubmitError
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import PaybondUnregisteredSideEffectingToolError
from paybond_kit.crewai._peer import crewai_runtime_available, is_crewai_base_tool
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError


@dataclass(frozen=True, slots=True)
class PaybondCrewAIConfig:
    """Runner config for CrewAI crews and tool lists."""

    tools: list[Any]
    wrap_tool: Callable[[Any], Any]


def _require_crewai_tools() -> Any:
    from paybond_kit.crewai._peer import _require_crewai_tools as _load

    return _load()


def _resolve_tool_name(tool: Any) -> str:
    name = getattr(tool, "name", None)
    if isinstance(name, str) and name.strip():
        return name.strip()
    raise TypeError("each CrewAI tool must expose a non-empty name")


def _arguments_from_callable(
    target: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    if kwargs:
        return dict(kwargs)
    if not args:
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
        if len(parameters) == len(args):
            return {
                parameter.name: value
                for parameter, value in zip(parameters, args, strict=False)
            }
    except (TypeError, ValueError):
        pass
    if len(args) == 1 and isinstance(args[0], dict):
        return dict(args[0])
    return {"args": list(args)}


def _format_tool_error(message: str) -> str:
    return message


def _coerce_crewai_tool_result(raw: Any) -> Any:
    """Parse JSON tool outputs so evidence mappers receive structured dicts."""

    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return raw
    return raw


def _serialize_crewai_tool_result(result: Any) -> Any:
    if isinstance(result, (dict, list)):
        return json.dumps(result)
    return result


def _paybond_error_message(exc: BaseException) -> str:
    if isinstance(exc, PaybondUnregisteredSideEffectingToolError):
        return _format_tool_error(
            f"Paybond capability denied: unregistered side-effecting tool ({exc})"
        )
    if isinstance(exc, PaybondSpendApprovalRequiredError):
        decision_id = exc.result.decision_id
        suffix = f" (decision_id={decision_id})" if decision_id is not None else ""
        msg = exc.result.message or exc.result.code or "approval required"
        return _format_tool_error(f"Paybond capability approval required: {msg}{suffix}")
    if isinstance(exc, PaybondSpendDeniedError):
        msg = exc.result.message or exc.result.code or "capability denied"
        return _format_tool_error(f"Paybond capability denied: {msg}")
    if isinstance(exc, PaybondEvidenceSubmitError):
        return _format_tool_error(f"Paybond evidence submit failed: {exc}")
    return _format_tool_error(str(exc))


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
        result = wrapped.tool_result
        return _serialize_crewai_tool_result(result)
    except (
        PaybondUnregisteredSideEffectingToolError,
        PaybondSpendApprovalRequiredError,
        PaybondSpendDeniedError,
        PaybondEvidenceSubmitError,
    ) as exc:
        return _paybond_error_message(exc)


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
    if inspect.iscoroutinefunction(target):

        async def guarded_async(*args: Any, **kwargs: Any) -> Any:
            tool_call_id = str(uuid.uuid4())
            arguments = _arguments_from_callable(target, args, kwargs)

            async def execute() -> Any:
                raw = await target(*args, **kwargs)
                return _coerce_crewai_tool_result(raw)

            return await _guard_tool_execution(
                run,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                execute=execute,
            )

        return guarded_async

    def guarded_sync(*args: Any, **kwargs: Any) -> Any:
        tool_call_id = str(uuid.uuid4())
        arguments = _arguments_from_callable(target, args, kwargs)

        async def execute() -> Any:
            raw = target(*args, **kwargs)
            if inspect.isawaitable(raw):
                raw = await raw
            return _coerce_crewai_tool_result(raw)

        return _run_async_guard(
            _guard_tool_execution(
                run,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                execute=execute,
            )
        )

    return guarded_sync


def _wrap_base_tool_method(
    run: PaybondAgentRun,
    tool: Any,
    *,
    method_name: str,
    tool_name: str,
) -> None:
    original = getattr(tool, method_name, None)
    if not callable(original):
        return

    if inspect.iscoroutinefunction(original):

        async def guarded_method(self: Any, *args: Any, **kwargs: Any) -> Any:
            tool_call_id = str(uuid.uuid4())
            arguments = _arguments_from_callable(original, args, kwargs)

            async def execute() -> Any:
                raw = await original(self, *args, **kwargs)
                return _coerce_crewai_tool_result(raw)

            return await _guard_tool_execution(
                run,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                execute=execute,
            )

        setattr(tool, method_name, types.MethodType(guarded_method, tool))
        return

    def guarded_method(self: Any, *args: Any, **kwargs: Any) -> Any:
        tool_call_id = str(uuid.uuid4())
        arguments = _arguments_from_callable(original, args, kwargs)

        async def execute() -> Any:
            raw = original(self, *args, **kwargs)
            if inspect.isawaitable(raw):
                raw = await raw
            return _coerce_crewai_tool_result(raw)

        return _run_async_guard(
            _guard_tool_execution(
                run,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                execute=execute,
            )
        )

    setattr(tool, method_name, types.MethodType(guarded_method, tool))


def _wrap_crewai_tool(run: PaybondAgentRun, tool: Any) -> Any:
    tool_name = _resolve_tool_name(tool)
    if not run.registry.is_side_effecting(tool_name):
        return tool

    func = getattr(tool, "func", None)
    if callable(func):
        tool.func = _wrap_callable_target(run, tool_name=tool_name, target=func)
        return tool

    if is_crewai_base_tool(tool):
        _wrap_base_tool_method(run, tool, method_name="_run", tool_name=tool_name)
        _wrap_base_tool_method(run, tool, method_name="_arun", tool_name=tool_name)
        return tool

    raise TypeError(
        "each CrewAI tool must be a BaseTool instance or an @tool-decorated tool with func/_run"
    )


def _normalize_crewai_tools(tools: Sequence[Any]) -> list[Any]:
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        raise TypeError("crewai framework tools must be a sequence of CrewAI tool instances")

    normalized: list[Any] = []
    for tool in tools:
        if (
            callable(tool)
            and not is_crewai_base_tool(tool)
            and not (isinstance(getattr(tool, "name", None), str) and getattr(tool, "name", "").strip())
        ):
            if not crewai_runtime_available():
                raise ImportError(
                    "crewai is required to wrap plain callables with @tool. "
                    'Install with `pip install "paybond-kit[crewai]"`.'
                )
            decorator = getattr(_require_crewai_tools(), "tool", None)
            if not callable(decorator):
                raise TypeError("crewai.tools.tool decorator is unavailable")
            if not getattr(tool, "__doc__", None):
                tool.__doc__ = f"Tool {getattr(tool, '__name__', 'crewai_tool')}"
            normalized.append(decorator(tool))
            continue
        normalized.append(tool)
    return normalized


def create_paybond_crewai_config(
    run: PaybondAgentRun,
    tools: Sequence[Any],
) -> PaybondCrewAIConfig:
    """
    Wrap CrewAI ``@tool`` / ``BaseTool`` instances with Paybond middleware.

    Returns guarded tools plus a ``wrap_tool`` helper for incremental wiring.
    """
    _require_crewai_tools()
    normalized = _normalize_crewai_tools(tools)
    guarded = [_wrap_crewai_tool(run, tool) for tool in normalized]
    return PaybondCrewAIConfig(
        tools=guarded,
        wrap_tool=lambda tool: _wrap_crewai_tool(run, tool),
    )
