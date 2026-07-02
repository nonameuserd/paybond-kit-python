"""Framework adapter contract and generic tool executor."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol, TypedDict, TypeVar

from paybond_kit.agent.interceptor import PaybondInterceptWrapExecuteResult
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import PaybondAuthorizeToolCallInput, PaybondToolInputGuardDecision

TArgs = TypeVar("TArgs")
TResult = TypeVar("TResult")


class PaybondFrameworkAdapter(Protocol):
    """Translate framework tools into run-scoped interceptor calls."""

    @property
    def name(self) -> str: ...

    def wrap_tools(self, run: PaybondAgentRun, tools: Any) -> Any: ...


class _PaybondGenericToolCallRequired(TypedDict):
    tool_name: str
    tool_call_id: str
    arguments: Any


class PaybondGenericToolCall(_PaybondGenericToolCallRequired, total=False):
    operation: str
    requested_spend_cents: int
    vendor_id: str
    task_id: str
    workflow_id: str
    currency: str
    agent_subject: str
    approval_token: str
    idempotency_key: str


class PaybondGenericToolDefinition(TypedDict, total=False):
    name: str
    execute: Callable[[Any], Any | Awaitable[Any]]


class PaybondToolInputGuardAdapter(Protocol):
    """Agent-agnostic pre-execution spend guard for any framework runtime."""

    @property
    def name(self) -> str: ...

    async def evaluate(self, input: PaybondAuthorizeToolCallInput) -> PaybondToolInputGuardDecision: ...

    def wrap_executors(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]: ...


def _is_generic_tool_definition(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    name = value.get("name")
    execute = value.get("execute")
    return isinstance(name, str) and name.strip() != "" and callable(execute)


def _assert_generic_tools(tools: Any) -> list[dict[str, Any]]:
    if not isinstance(tools, list):
        raise TypeError(
            "generic tool adapter expects a list of {name, execute} tool definitions"
        )
    for tool in tools:
        if not _is_generic_tool_definition(tool):
            raise TypeError("each generic tool must have a non-empty name and an execute callable")
    return tools


def _intercept_result_to_dict(result: PaybondInterceptWrapExecuteResult) -> dict[str, Any]:
    payload: dict[str, Any] = {"tool_result": result.tool_result}
    if result.authorization is not None:
        payload["authorization"] = result.authorization
    if result.evidence is not None:
        payload["evidence"] = result.evidence
    return payload


def _wrap_generic_tool(run: PaybondAgentRun, tool: dict[str, Any]) -> dict[str, Any]:
    original_execute = tool["execute"]

    async def wrapped_execute(call: PaybondGenericToolCall) -> dict[str, Any]:
        result = await run.interceptor.wrap_execute(
            tool_name=str(call["tool_name"]),
            tool_call_id=str(call["tool_call_id"]),
            arguments=call["arguments"],
            execute=lambda: original_execute(call["arguments"]),
            operation=call.get("operation"),
            requested_spend_cents=call.get("requested_spend_cents"),
            vendor_id=call.get("vendor_id"),
            task_id=call.get("task_id"),
            workflow_id=call.get("workflow_id"),
            currency=call.get("currency"),
            agent_subject=call.get("agent_subject"),
            approval_token=call.get("approval_token"),
            idempotency_key=call.get("idempotency_key"),
        )
        return _intercept_result_to_dict(result)

    return {**tool, "name": tool["name"], "execute": wrapped_execute}


@dataclass(frozen=True, slots=True)
class _GenericToolExecutorAdapter:
    name: str = "generic"

    def wrap_tools(self, run: PaybondAgentRun, tools: Any) -> list[dict[str, Any]]:
        return [_wrap_generic_tool(run, tool) for tool in _assert_generic_tools(tools)]


_GENERIC_TOOL_EXECUTOR_ADAPTER = _GenericToolExecutorAdapter()


def create_generic_tool_executor() -> PaybondFrameworkAdapter:
    """Provider-agnostic adapter for ``{name, execute}`` tool definitions."""
    return _GENERIC_TOOL_EXECUTOR_ADAPTER


paybond_generic_tool_executor_adapter = _GENERIC_TOOL_EXECUTOR_ADAPTER


@dataclass(frozen=True, slots=True)
class _ToolInputGuardAdapter:
    _run: PaybondAgentRun

    @property
    def name(self) -> str:
        return "tool-input-guard"

    async def evaluate(self, input: PaybondAuthorizeToolCallInput) -> PaybondToolInputGuardDecision:
        return await self._run.interceptor.authorize_tool_call(
            tool_name=str(input["tool_name"]),
            tool_call_id=str(input["tool_call_id"]),
            arguments=input.get("arguments"),
            operation=input.get("operation"),
            requested_spend_cents=input.get("requested_spend_cents"),
            vendor_id=input.get("vendor_id"),
            task_id=input.get("task_id"),
            workflow_id=input.get("workflow_id"),
            currency=input.get("currency"),
            agent_subject=input.get("agent_subject"),
            approval_token=input.get("approval_token"),
            idempotency_key=input.get("idempotency_key"),
        )

    def wrap_executors(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [_wrap_generic_tool(self._run, tool) for tool in _assert_generic_tools(tools)]


def create_tool_input_guard_adapter(run: PaybondAgentRun) -> PaybondToolInputGuardAdapter:
    """Build a run-scoped tool input guard adapter (framework-neutral)."""
    return _ToolInputGuardAdapter(_run=run)


def paybond_tool_input_guard_adapter(run: PaybondAgentRun) -> PaybondToolInputGuardAdapter:
    """Convenience alias for :func:`create_tool_input_guard_adapter`."""
    return create_tool_input_guard_adapter(run)


__all__ = [
    "PaybondFrameworkAdapter",
    "PaybondGenericToolCall",
    "PaybondGenericToolDefinition",
    "PaybondToolInputGuardAdapter",
    "create_generic_tool_executor",
    "create_tool_input_guard_adapter",
    "paybond_generic_tool_executor_adapter",
    "paybond_tool_input_guard_adapter",
]
