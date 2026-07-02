"""Unified Paybond facade helpers for instrument(), agent(), and wrap_tools()."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from paybond_kit.agent.framework_support import raise_typescript_only_framework_error
from paybond_kit.agent.generic_runner import (
    create_paybond_generic_agent_config,
    create_paybond_generic_input_guard,
)
from paybond_kit.agent.guarded_agent import (
    CreateGuardedAgentInput,
    CreateGuardedAgentResult,
    GuardedAgentFramework,
)
from paybond_kit.agent.instrument import (
    PaybondInstrumentBuilder,
    PaybondInstrumentContext,
    PaybondInstrumentRuntime,
    PaybondInstrumented,
    instrument_paybond_agent,
    normalize_instrument_context,
)
from paybond_kit.policy.presets import is_known_policy_preset_id, resolve_policy_preset_path

if TYPE_CHECKING:
    from paybond_kit.agent.run import PaybondAgentRun, PaybondAgentRunHost
    from paybond_kit.policy.load import PaybondPolicy, PaybondPolicyLoadSource

_POLICY_PATH_PATTERN = re.compile(r"[/\\]|\.ya?ml$|\.json$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class PaybondAgentHooks:
    """Framework-native wiring returned by ``paybond.agent()``."""

    input_guard: Any | None = None
    tool_approval: Any | None = None
    awrap_tool_call: Any | None = None
    create_tool_node: Any | None = None
    run_config: Mapping[str, Any] | None = None
    openai_agents_adapter: Any | None = None
    mcp_server: Any | None = None
    allowed_tools: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class PaybondAgentResult:
    """Opinionated quickstart result: guarded tools plus framework hooks."""

    run: PaybondAgentRun
    tools: Any
    hooks: PaybondAgentHooks
    policy: PaybondPolicy


def resolve_agent_policy_source(policy: PaybondPolicyLoadSource) -> PaybondPolicyLoadSource:
    """Resolve a policy preset id (for example ``travel``) or pass through file paths and documents."""
    if not isinstance(policy, str):
        return policy
    trimmed = policy.strip()
    if not trimmed:
        raise ValueError("policy must be a non-empty preset id or file path")
    if _POLICY_PATH_PATTERN.search(trimmed):
        return trimmed
    if is_known_policy_preset_id(trimmed):
        return resolve_policy_preset_path(trimmed)
    return trimmed


def to_paybond_agent_result(result: CreateGuardedAgentResult) -> PaybondAgentResult:
    """Normalize ``CreateGuardedAgentResult`` into the quickstart ``{ run, tools, hooks, policy }`` shape."""
    hooks = PaybondAgentHooks()

    if result.framework == "generic":
        hooks = PaybondAgentHooks(input_guard=create_paybond_generic_input_guard(result.run))
    elif result.framework == "vercel-ai":
        hooks = PaybondAgentHooks(tool_approval=result.tool_approval)
    elif result.framework == "langgraph":
        hooks = PaybondAgentHooks(
            awrap_tool_call=result.awrap_tool_call,
            create_tool_node=result.create_tool_node,
        )
    elif result.framework == "claude-agents":
        allowed_tools: tuple[str, ...] | None = None
        mcp_server = None
        if result.claude_agents_config is not None:
            mcp_server = result.claude_agents_config.mcp_server
            allowed_tools = tuple(result.claude_agents_config.allowed_tools)
        hooks = PaybondAgentHooks(mcp_server=mcp_server, allowed_tools=allowed_tools)
    elif result.framework == "openai-agents":
        hooks = PaybondAgentHooks(
            run_config=result.run_config,
            openai_agents_adapter=result.openai_agents_adapter,
        )
    else:
        raise ValueError(f"unsupported guarded agent framework: {result.framework}")

    return PaybondAgentResult(
        run=result.run,
        tools=result.agent_tools,
        hooks=hooks,
        policy=result.policy,
    )


async def create_paybond_agent(
    paybond: PaybondAgentRunHost,
    *,
    policy: PaybondPolicyLoadSource,
    tools: Any,
    framework: GuardedAgentFramework | None = None,
    sandbox: bool | None = None,
    context: PaybondInstrumentContext | Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> PaybondAgentResult:
    """Opinionated quickstart: resolve named presets, then delegate to instrument."""
    resolved_policy = resolve_agent_policy_source(policy)
    normalized_context = normalize_instrument_context(context) if context is not None else None
    attach = kwargs.get("attach")
    result = await instrument_paybond_agent(
        paybond,
        {
            "policy": resolved_policy,
            "framework": framework or "generic",
            "tools": tools,
            "bootstrap": kwargs.get("bootstrap"),
            "attach": attach,
            "run_id": kwargs.get("run_id"),
            "validate_policy": kwargs.get("validate_policy"),
            "sandbox": False
            if normalized_context is not None or attach is not None
            else (sandbox if sandbox is not None else True),
            "context": normalized_context,
        },
    )
    if not isinstance(result, PaybondInstrumentRuntime):
        raise RuntimeError("paybond.agent() requires sandbox bootstrap or an explicit context")
    return PaybondAgentResult(
        run=result.run,
        tools=result.tools,
        hooks=result.hooks,
        policy=result.policy,
    )


def wrap_paybond_tools(
    run: PaybondAgentRun,
    tools: Any,
    *,
    framework: GuardedAgentFramework = "generic",
) -> Any:
    """Wrap tools for an existing bound run without reloading policy."""
    if framework in ("vercel-ai", "openai-agents"):
        raise_typescript_only_framework_error(framework)
    if framework == "generic":
        return create_paybond_generic_agent_config(run, tools).tools
    if framework == "claude-agents":
        from paybond_kit.claude_agents import create_paybond_claude_agents_config

        return create_paybond_claude_agents_config(run, tools).agent_tools
    if framework == "langgraph":
        raise ValueError(
            'framework "langgraph" does not wrap tools in place; use instrument() or create_paybond_langgraph_hooks(run)'
        )
    raise ValueError(f"unsupported framework for wrap_tools: {framework}")
