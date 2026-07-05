"""Policy-driven guarded agent factory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Mapping

from paybond_kit.agent.framework_support import raise_typescript_only_framework_error
from paybond_kit.agent.generic_runner import create_paybond_generic_agent_config
from paybond_kit.agent.run import PaybondAgentRun, PaybondAgentRunHost
from paybond_kit.agent.types import PaybondAgentRunBindConfig, PaybondRunBindingAttachInput
from paybond_kit.policy.sandbox_bootstrap import PaybondPolicySandboxBootstrapOptions

if TYPE_CHECKING:
    from paybond_kit.policy.load import PaybondPolicy, PaybondPolicyLoadSource

GuardedAgentFramework = Literal[
    "generic",
    "langgraph",
    "claude-agents",
    "crewai",
    "vercel-ai",
    "openai-agents",
]


@dataclass(frozen=True, slots=True)
class CreateGuardedAgentInput:
    policy: PaybondPolicyLoadSource | PaybondPolicy
    framework: GuardedAgentFramework
    tools: Any
    bootstrap: PaybondPolicySandboxBootstrapOptions | None = None
    attach: PaybondRunBindingAttachInput | None = None
    run_id: str | None = None
    validate_policy: bool | Mapping[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class CreateGuardedAgentResult:
    run: PaybondAgentRun
    policy: PaybondPolicy
    registry: Any
    framework: GuardedAgentFramework
    agent_tools: Any
    tool_approval: Any | None = None
    awrap_tool_call: Any | None = None
    create_tool_node: Any | None = None
    openai_agents_adapter: Any | None = None
    run_config: Mapping[str, Any] | None = None
    claude_agents_config: Any | None = None
    crewai_config: Any | None = None


async def _resolve_policy(source: PaybondPolicyLoadSource | PaybondPolicy) -> PaybondPolicy:
    from paybond_kit.policy.load import PaybondPolicy

    if isinstance(source, PaybondPolicy):
        return source
    return PaybondPolicy.load(source)


async def _maybe_validate_policy(
    policy: PaybondPolicy,
    validate_policy: bool | Mapping[str, Any] | None,
) -> None:
    if not validate_policy:
        return
    options = None if validate_policy is True else validate_policy
    result = policy.validate(options)  # type: ignore[arg-type]
    if not result.valid:
        messages = "; ".join(error.message for error in result.errors)
        raise ValueError(f"policy validation failed: {messages}")



async def _bind_guarded_run(
    paybond: PaybondAgentRunHost,
    policy: PaybondPolicy,
    input_: CreateGuardedAgentInput,
) -> PaybondAgentRun:
    registry = policy.to_tool_registry()
    bind_input: PaybondAgentRunBindConfig = {
        "registry": registry,
    }
    if input_.run_id is not None:
        bind_input["run_id"] = input_.run_id
    if input_.attach is not None:
        bind_input["attach"] = input_.attach
    else:
        bind_input["bootstrap"] = policy.sandbox_bootstrap(input_.bootstrap)
    return await PaybondAgentRun.bind(paybond, bind_input)


async def create_guarded_agent(
    paybond: PaybondAgentRunHost,
    input_: CreateGuardedAgentInput,
) -> CreateGuardedAgentResult:
    """Load policy, bind a run, and wire framework tools through agent middleware."""
    framework = input_.framework or "generic"
    if framework == "vercel-ai":
        raise_typescript_only_framework_error(framework)

    policy = await _resolve_policy(input_.policy)
    await _maybe_validate_policy(policy, input_.validate_policy)

    registry = policy.to_tool_registry()
    run = await _bind_guarded_run(paybond, policy, input_)

    if framework == "generic":
        config = create_paybond_generic_agent_config(run, input_.tools)
        return CreateGuardedAgentResult(
            run=run,
            policy=policy,
            registry=registry,
            framework="generic",
            agent_tools=config.tools,
        )

    if framework == "langgraph":
        from paybond_kit.langgraph_hooks import create_paybond_langgraph_hooks

        hooks = create_paybond_langgraph_hooks(run)
        return CreateGuardedAgentResult(
            run=run,
            policy=policy,
            registry=registry,
            framework="langgraph",
            agent_tools=input_.tools,
            awrap_tool_call=hooks.awrap_tool_call,
            create_tool_node=hooks.create_tool_node,
        )

    if framework == "claude-agents":
        from paybond_kit.claude_agents import create_paybond_claude_agents_config

        claude_agents_config = create_paybond_claude_agents_config(run, input_.tools)
        return CreateGuardedAgentResult(
            run=run,
            policy=policy,
            registry=registry,
            framework="claude-agents",
            agent_tools=claude_agents_config.agent_tools,
            claude_agents_config=claude_agents_config,
        )

    if framework == "crewai":
        from paybond_kit.crewai import create_paybond_crewai_config

        crewai_config = create_paybond_crewai_config(run, input_.tools)
        return CreateGuardedAgentResult(
            run=run,
            policy=policy,
            registry=registry,
            framework="crewai",
            agent_tools=crewai_config.tools,
            crewai_config=crewai_config,
        )

    if framework == "openai-agents":
        from paybond_kit.openai_agents import create_openai_agents_adapter, create_paybond_openai_agents_config

        openai_config = create_paybond_openai_agents_config(run, input_.tools)
        openai_adapter = create_openai_agents_adapter(run)
        return CreateGuardedAgentResult(
            run=run,
            policy=policy,
            registry=registry,
            framework="openai-agents",
            agent_tools=openai_config.tools,
            openai_agents_adapter=openai_adapter,
            run_config=openai_config.run_config,
        )

    raise ValueError(f"unsupported guarded agent framework: {framework}")


create_guarded_agent_runner = create_guarded_agent


__all__ = [
    "CreateGuardedAgentInput",
    "CreateGuardedAgentResult",
    "GuardedAgentFramework",
    "create_guarded_agent",
    "create_guarded_agent_runner",
]
