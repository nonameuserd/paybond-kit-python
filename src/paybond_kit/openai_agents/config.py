"""OpenAI Agents SDK integration — input guardrails and wrapped invoke with Paybond middleware."""

from __future__ import annotations

import copy
import inspect
import json
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from paybond_kit.agent.adapter import create_tool_input_guard_adapter
from paybond_kit.agent.interceptor import PaybondEvidenceSubmitError
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import (
    PaybondToolInputGuardDecision,
    PaybondUnregisteredSideEffectingToolError,
)
from paybond_kit.openai_agents._peer import _require_openai_agents, is_openai_function_tool
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError


@dataclass(frozen=True, slots=True)
class PaybondOpenAIAgentsAdapterOptions:
    """Options for the OpenAI Agents adapter."""

    bridge_needs_approval: bool = False
    """
    When True, side-effecting tools also set ``needs_approval`` so the OpenAI Agents SDK
    pauses for human review after Paybond pre-check passes.
    """


@dataclass(frozen=True, slots=True)
class PaybondOpenAIAgentsConfig:
    """Runner config for OpenAI Agents SDK ``Runner.run``."""

    tools: list[Any]
    run_config: Any


def _parse_tool_arguments(raw: str) -> Any:
    if not raw.strip():
        return {}
    return json.loads(raw)


def map_paybond_decision_to_openai_tool_guardrail(
    decision: PaybondToolInputGuardDecision,
) -> Any:
    """Map a framework-neutral Paybond decision to OpenAI tool guardrail output."""

    agents = _require_openai_agents()
    output_factory = agents.ToolGuardrailFunctionOutput
    if decision.get("kind") == "allow":
        return output_factory.allow(
            output_info={
                "paybond": {
                    "operation": decision.get("operation"),
                    "auditId": decision.get("audit_id"),
                    "decisionId": decision.get("decision_id"),
                    "passthrough": decision.get("passthrough", False),
                }
            }
        )

    message = str(decision.get("message") or decision.get("code") or "Paybond capability denied")
    return output_factory.reject_content(
        message,
        output_info={
            "paybond": {
                "kind": decision.get("kind"),
                "operation": decision.get("operation"),
                "auditId": decision.get("audit_id"),
                "code": decision.get("code"),
            }
        },
    )


def paybond_openai_agents_run_config() -> Any:
    """RunConfig fragment enabling Paybond verify before OpenAI approval interruptions."""

    agents = _require_openai_agents()
    return agents.RunConfig(
        tool_execution=agents.ToolExecutionConfig(pre_approval_tool_input_guardrails=True)
    )


def _coerce_tool_result(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


def _serialize_tool_result(result: Any) -> Any:
    if isinstance(result, (dict, list)):
        return json.dumps(result)
    if result is None:
        return ""
    return result


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


async def _guard_tool_execution(
    run: PaybondAgentRun,
    *,
    tool_name: str,
    tool_call_id: str,
    arguments: dict[str, Any],
    execute: Callable[[], Awaitable[Any]],
) -> Any:
    try:
        wrapped = await run.interceptor.wrap_execute(
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            arguments=arguments,
            approval_token=run.get_approval_token(tool_call_id),
            execute=execute,
        )
        return _serialize_tool_result(wrapped.tool_result)
    except (
        PaybondUnregisteredSideEffectingToolError,
        PaybondSpendApprovalRequiredError,
        PaybondSpendDeniedError,
        PaybondEvidenceSubmitError,
    ) as exc:
        return _paybond_error_message(exc)


def _build_paybond_input_guardrail(run: PaybondAgentRun, tool_name: str) -> Any:
    agents = _require_openai_agents()
    guard = create_tool_input_guard_adapter(run)

    async def _run_guard(data: Any) -> Any:
        context = data.context
        args = _parse_tool_arguments(context.tool_arguments)
        decision = await guard.evaluate(
            {
                "tool_name": context.tool_name or tool_name,
                "tool_call_id": context.tool_call_id or str(uuid.uuid4()),
                "arguments": args,
            }
        )
        return map_paybond_decision_to_openai_tool_guardrail(decision)

    return agents.ToolInputGuardrail(guardrail_function=_run_guard, name=f"paybond_spend_{tool_name}")


def _resolve_needs_approval(
    original: bool | Callable[..., Awaitable[bool] | bool],
    *,
    bridge: bool,
) -> bool | Callable[..., Awaitable[bool]]:
    if not bridge:
        return original

    async def bridged(
        run_context: Any,
        tool_parameters: dict[str, Any],
        call_id: str,
    ) -> bool:
        base = False
        if callable(original):
            result = original(run_context, tool_parameters, call_id)
            if inspect.isawaitable(result):
                result = await result
            base = bool(result)
        else:
            base = bool(original)
        return base or bridge

    return bridged


def _guard_function_tool(
    run: PaybondAgentRun,
    fn_tool: Any,
    options: PaybondOpenAIAgentsAdapterOptions | None = None,
) -> Any:
    if not run.registry.is_side_effecting(fn_tool.name):
        return fn_tool

    opts = options or PaybondOpenAIAgentsAdapterOptions()
    paybond_guardrail = _build_paybond_input_guardrail(run, fn_tool.name)
    existing_guardrails = list(fn_tool.tool_input_guardrails or [])
    original_invoke = fn_tool.on_invoke_tool

    async def guarded_on_invoke_tool(ctx: Any, input_json: str) -> Any:
        args = _parse_tool_arguments(input_json)
        tool_call_id = getattr(ctx, "tool_call_id", None) or str(uuid.uuid4())

        async def execute() -> Any:
            raw = await original_invoke(ctx, input_json)
            return _coerce_tool_result(raw)

        return await _guard_tool_execution(
            run,
            tool_name=fn_tool.name,
            tool_call_id=str(tool_call_id),
            arguments=args if isinstance(args, dict) else {"value": args},
            execute=execute,
        )

    guarded = copy.copy(fn_tool)
    guarded.tool_input_guardrails = [*existing_guardrails, paybond_guardrail]
    guarded.on_invoke_tool = guarded_on_invoke_tool
    if opts.bridge_needs_approval:
        guarded.needs_approval = _resolve_needs_approval(
            fn_tool.needs_approval,
            bridge=True,
        )
    return guarded


def _assert_openai_function_tools(tools: Sequence[Any]) -> list[Any]:
    if not isinstance(tools, Sequence) or isinstance(tools, (str, bytes)):
        raise TypeError("openai-agents framework tools must be a sequence of FunctionTool instances")
    normalized: list[Any] = []
    for tool in tools:
        if not is_openai_function_tool(tool):
            raise TypeError("each openai-agents tool must be an OpenAI Agents SDK FunctionTool instance")
        normalized.append(tool)
    return normalized


def create_openai_agents_adapter(
    run: PaybondAgentRun,
    options: PaybondOpenAIAgentsAdapterOptions | None = None,
) -> Any:
    """Translate Paybond middleware into OpenAI Agents SDK tool input guardrails."""

    _require_openai_agents()
    guard = create_tool_input_guard_adapter(run)

    class _OpenAIAgentsAdapter:
        name = "openai-agents"

        evaluate = guard.evaluate
        wrap_executors = guard.wrap_executors
        run_config = paybond_openai_agents_run_config()

        def input_guardrail_for(self, tool_name: str) -> Any:
            return _build_paybond_input_guardrail(run, tool_name)

        def guard_function_tools(self, tools: Sequence[Any]) -> list[Any]:
            normalized = _assert_openai_function_tools(tools)
            return [_guard_function_tool(run, tool, options) for tool in normalized]

    return _OpenAIAgentsAdapter()


def paybond_openai_agents_adapter(
    run: PaybondAgentRun,
    options: PaybondOpenAIAgentsAdapterOptions | None = None,
) -> Any:
    """Convenience alias for :func:`create_openai_agents_adapter`."""

    return create_openai_agents_adapter(run, options)


def create_paybond_openai_agents_config(
    run: PaybondAgentRun,
    tools: Sequence[Any],
    options: PaybondOpenAIAgentsAdapterOptions | None = None,
) -> PaybondOpenAIAgentsConfig:
    """
    Framework runner helper for OpenAI Agents SDK ``Runner.run``.

    Returns guarded function tools and the ``run_config`` fragment that enables
    Paybond verify before approval interruptions.
    """

    adapter = create_openai_agents_adapter(run, options)
    return PaybondOpenAIAgentsConfig(
        tools=adapter.guard_function_tools(tools),
        run_config=adapter.run_config,
    )
