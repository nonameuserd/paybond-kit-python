"""Lazy context tools — bind per request at execute time via a context provider."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol, TypeVar

PAYBOND_LAZY_CONTEXT_MESSAGE = (
    "context provider must return {intent_id, capability_token} for the active request "
    "before executing side-effecting tools."
)


class PaybondLazyContextError(RuntimeError):
    """Raised when a lazy-context provider returns incomplete binding material."""

    def __init__(self, message: str = PAYBOND_LAZY_CONTEXT_MESSAGE) -> None:
        super().__init__(message)


class _LazyRuntime(Protocol):
    tools: Any


TRuntime = TypeVar("TRuntime", bound=_LazyRuntime)
LazyRuntimeResolver = Callable[[], Awaitable[TRuntime]]


def _is_generic_tool_definition(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    name = value.get("name")
    execute = value.get("execute")
    return isinstance(name, str) and bool(str(name).strip()) and callable(execute)


async def _invoke_callable(fn: Callable[..., Any], call: Any | None = None) -> Any:
    result = fn(call)
    if hasattr(result, "__await__"):
        return await result
    return result


async def _execute_guarded_tool(runtime_tools: Any, tool_name: str, call: Any | None = None) -> Any:
    if isinstance(runtime_tools, list):
        for entry in runtime_tools:
            if isinstance(entry, Mapping) and entry.get("name") == tool_name:
                execute = entry.get("execute")
                if callable(execute):
                    return await _invoke_callable(execute, call)
        raise RuntimeError(f"guarded tool not found after lazy bind: {tool_name}")

    if isinstance(runtime_tools, Mapping):
        tool = runtime_tools.get(tool_name)
        if callable(tool):
            return await _invoke_callable(tool, call)
        if isinstance(tool, Mapping) and _is_generic_tool_definition(tool):
            execute = tool.get("execute")
            if callable(execute):
                return await _invoke_callable(execute, call)

    raise RuntimeError(f"guarded tool not found after lazy bind: {tool_name}")


def wrap_lazy_context_tools(raw_tools: Any, resolver: LazyRuntimeResolver[Any]) -> Any:
    """
    Wrap tools so each execution resolves request context via ``resolver``.
  Safe to register once; binding happens per active request at execute time.
    """

    async def run_guarded(tool_name: str, call: Any | None = None) -> Any:
        runtime = await resolver()
        return await _execute_guarded_tool(runtime.tools, tool_name, call)

    if isinstance(raw_tools, list):
        wrapped: list[Any] = []
        for tool in raw_tools:
            if not _is_generic_tool_definition(tool):
                wrapped.append(tool)
                continue
            name = str(tool["name"]).strip()
            shell = dict(tool)
            shell["name"] = name

            async def _execute(call: Any | None = None, *, _tool_name: str = name) -> Any:
                return await run_guarded(_tool_name, call)

            shell["execute"] = _execute
            wrapped.append(shell)
        return wrapped

    if isinstance(raw_tools, Mapping):
        wrapped_map: dict[str, Any] = {}
        for name, tool in raw_tools.items():
            tool_name = str(name).strip()
            if callable(tool):

                async def _fn(call: Any | None = None, *, _tool_name: str = tool_name) -> Any:
                    return await run_guarded(_tool_name, call)

                wrapped_map[tool_name] = _fn
                continue
            if _is_generic_tool_definition(tool):
                shell = dict(tool)
                resolved_name = str(shell.get("name", tool_name)).strip() or tool_name
                shell["name"] = resolved_name

                async def _execute(call: Any | None = None, *, _tool_name: str = resolved_name) -> Any:
                    return await run_guarded(_tool_name, call)

                shell["execute"] = _execute
                wrapped_map[tool_name] = shell
                continue
            wrapped_map[tool_name] = tool
        return wrapped_map

    return raw_tools
