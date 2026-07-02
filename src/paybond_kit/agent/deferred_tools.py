"""Deferred tool shells — safe to register before intent binding."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

PAYBOND_BIND_CONTEXT_MESSAGE = (
    "Call instrumented.bind(intent_id=..., capability_token=...) "
    "to attach a funded intent before executing side-effecting tools."
)


class PaybondUnboundContextError(RuntimeError):
    """Raised when a deferred tool executes before :meth:`PaybondInstrumented.bind`."""

    def __init__(self, tool_name: str) -> None:
        super().__init__(
            f'Tool "{tool_name}" requires a bound Paybond context. {PAYBOND_BIND_CONTEXT_MESSAGE}'
        )
        self.tool_name = tool_name


def _deferred_execute(tool_name: str) -> None:
    raise PaybondUnboundContextError(tool_name)


def _is_generic_tool_definition(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    name = value.get("name")
    execute = value.get("execute")
    return isinstance(name, str) and bool(name.strip()) and callable(execute)


def wrap_deferred_tools(raw_tools: Any) -> Any:
    """
    Wrap tools for static instrumentation — safe to register with agent frameworks.
    Side-effecting execution raises :class:`PaybondUnboundContextError` until ``bind()`` supplies a runtime.
    """
    if isinstance(raw_tools, list):
        wrapped: list[Any] = []
        for tool in raw_tools:
            if not _is_generic_tool_definition(tool):
                wrapped.append(tool)
                continue
            name = str(tool["name"]).strip()
            shell = dict(tool)
            shell["name"] = name

            async def _execute(*_args: Any, _tool_name: str = name, **_kwargs: Any) -> None:
                _deferred_execute(_tool_name)

            shell["execute"] = _execute
            wrapped.append(shell)
        return wrapped

    if isinstance(raw_tools, Mapping):
        wrapped_map: dict[str, Any] = {}
        for name, tool in raw_tools.items():
            tool_name = str(name).strip()
            if callable(tool):

                async def _fn(*_args: Any, _tool_name: str = tool_name, **_kwargs: Any) -> None:
                    _deferred_execute(_tool_name)

                wrapped_map[tool_name] = _fn
                continue
            if _is_generic_tool_definition(tool):
                shell = dict(tool)
                resolved_name = str(shell.get("name", tool_name)).strip() or tool_name
                shell["name"] = resolved_name

                async def _execute(*_args: Any, _tool_name: str = resolved_name, **_kwargs: Any) -> None:
                    _deferred_execute(_tool_name)

                shell["execute"] = _execute
                wrapped_map[tool_name] = shell
                continue
            wrapped_map[tool_name] = tool
        return wrapped_map

    return raw_tools
