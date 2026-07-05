"""Paybond instrument() result, inline policies, and fluent builder."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Mapping, NotRequired, Required, TypeGuard, TypedDict, cast

from paybond_kit.agent.deferred_tools import PaybondUnboundContextError, wrap_deferred_tools
from paybond_kit.agent.lazy_context_tools import PaybondLazyContextError, wrap_lazy_context_tools
from paybond_kit.agent.attach_bundle import resolve_attach_context_from_env
from paybond_kit.agent.discover import (
    attach_paybond_agent_instrumentation,
    discover_policy_from_agent,
    discover_tools_from_agent,
    is_instrumentable_agent_object,
    read_paybond_agent_instrumentation,
)
from paybond_kit.agent.framework_support import raise_typescript_only_framework_error
from paybond_kit.agent.generic_runner import create_paybond_generic_agent_config
from paybond_kit.agent.guarded_agent import (
    CreateGuardedAgentInput,
    CreateGuardedAgentResult,
    GuardedAgentFramework,
    create_guarded_agent,
)
from paybond_kit.agent.run import PaybondAgentRun, PaybondAgentRunHost
from paybond_kit.agent.types import (
    PaybondAgentRunBindConfig,
    PaybondRunBindingAttachInput,
    PaybondRunProductionEvidenceCredentials,
    PaybondRunSandboxBinding,
)

if TYPE_CHECKING:
    from paybond_kit.policy.load import PaybondPolicy, PaybondPolicyLoadSource
    from paybond_kit.policy.schema import PaybondPolicyDocumentV1

    from paybond_kit.agent.facade import PaybondAgentHooks


class PaybondInstrumentBindingDeferred(TypedDict):
    phase: Literal["deferred"]


class PaybondInstrumentBindingLazy(TypedDict):
    phase: Literal["lazy"]


class PaybondInstrumentBindingBound(TypedDict, total=False):
    phase: Required[Literal["bound"]]
    mode: Required[Literal["sandbox", "attach"]]
    intent_id: Required[str]
    capability_token: Required[str]
    tenant_id: Required[str]
    user_id: NotRequired[str]


PaybondInstrumentBinding = (
    PaybondInstrumentBindingDeferred | PaybondInstrumentBindingLazy | PaybondInstrumentBindingBound
)


def _hooks_from_result(result: CreateGuardedAgentResult) -> PaybondAgentHooks:
    from paybond_kit.agent.facade import to_paybond_agent_result

    return to_paybond_agent_result(result).hooks


def _wrap_tools_for_framework(
    run: PaybondAgentRun,
    tools: Any,
    framework: GuardedAgentFramework,
) -> Any:
    if framework == "vercel-ai":
        raise_typescript_only_framework_error(framework)
    if framework == "openai-agents":
        from paybond_kit.openai_agents import create_paybond_openai_agents_config

        return create_paybond_openai_agents_config(run, tools).tools
    if framework == "generic":
        return create_paybond_generic_agent_config(run, tools).tools
    if framework == "claude-agents":
        from paybond_kit.claude_agents import create_paybond_claude_agents_config

        return create_paybond_claude_agents_config(run, tools).agent_tools
    if framework == "langgraph":
        return tools
    if framework == "crewai":
        from paybond_kit.crewai import create_paybond_crewai_config

        return create_paybond_crewai_config(run, tools).tools
    raise ValueError(f"unsupported framework for wrap_tools: {framework}")


_GLOB_META = re.compile(r"([.+^${}()|[\]\\])")


@dataclass(frozen=True, slots=True)
class PaybondInlinePolicy:
    """Simplified inline policy for tutorials and quick examples."""

    budget: str | Mapping[str, Any] | None = None
    approve: tuple[str, ...] | None = None
    deny: tuple[str, ...] | None = None
    name: str | None = None


@dataclass(frozen=True, slots=True)
class PaybondInstrumentContext:
    """Per-request execution context applied after static instrumentation."""

    intent_id: str
    capability_token: str
    user_id: str | None = None
    allowed_tools: tuple[str, ...] | None = None
    production_evidence: Any | None = None
    sandbox: Mapping[str, Any] | None = None


PaybondInstrumentContextProvider = Callable[
    [],
    "PaybondInstrumentContext | Mapping[str, Any] | Awaitable[PaybondInstrumentContext | Mapping[str, Any]]",
]
PaybondInstrumentContextInput = (
    PaybondInstrumentContext | Mapping[str, Any] | PaybondInstrumentContextProvider
)


def _resolve_instrument_attach_context(
    attach: Any | None,
) -> PaybondInstrumentContext | None:
    if attach is None:
        return None
    if attach == "env":
        resolved = resolve_attach_context_from_env()
        return PaybondInstrumentContext(
            intent_id=str(resolved["intent_id"]),
            capability_token=str(resolved["capability_token"]),
            production_evidence=resolved.get("production_evidence"),
        )
    if isinstance(attach, Mapping):
        return normalize_instrument_context(
            {
                "intent_id": attach.get("intent_id"),
                "capability_token": attach.get("capability_token"),
                "allowed_tools": attach.get("allowed_tools"),
                "production_evidence": attach.get("production_evidence"),
                "sandbox": attach.get("sandbox"),
            }
        )
    raise TypeError('attach must be "env" or a mapping with intent_id and capability_token')


def normalize_instrument_context(
    context: PaybondInstrumentContextInput,
) -> PaybondInstrumentContext:
    if isinstance(context, PaybondInstrumentContext):
        return context
    if isinstance(context, Mapping):
        allowed = context.get("allowed_tools")
        return PaybondInstrumentContext(
            intent_id=str(context["intent_id"]),
            capability_token=str(context["capability_token"]),
            user_id=context.get("user_id"),
            allowed_tools=tuple(allowed) if allowed is not None else None,
            production_evidence=context.get("production_evidence"),
            sandbox=dict(context["sandbox"]) if context.get("sandbox") is not None else None,
        )
    raise TypeError("instrument context providers must be awaited before normalization")


def is_context_provider(
    value: PaybondInstrumentContextInput,
) -> TypeGuard[PaybondInstrumentContextProvider]:
    return callable(value) and not isinstance(value, (PaybondInstrumentContext, Mapping))


async def _call_context_provider(
    provider: PaybondInstrumentContextProvider,
) -> PaybondInstrumentContext:
    result = provider()
    if isinstance(result, Awaitable):
        result = await result
    return normalize_instrument_context(result)


def _runtime_cache_key(context: PaybondInstrumentContext) -> str:
    return f"{context.intent_id}\0{context.capability_token}\0{context.user_id or ''}"


def _assert_instrument_context(context: PaybondInstrumentContext) -> None:
    if not str(context.intent_id).strip() or not str(context.capability_token).strip():
        raise PaybondLazyContextError()


def is_inline_policy(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if "version" in value or "default_deny" in value:
        return False
    tools = value.get("tools")
    if isinstance(tools, Mapping) and any(
        isinstance(entry, Mapping) and "side_effecting" in entry for entry in tools.values()
    ):
        return False
    return "budget" in value or "approve" in value or "deny" in value


def _glob_to_pattern(glob: str) -> re.Pattern[str]:
    escaped = _GLOB_META.sub(r"\\\1", glob.strip())
    return re.compile(f"^{escaped.replace('*', '.*').replace('?', '.')}$")


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(_glob_to_pattern(pattern).fullmatch(value) for pattern in patterns)


def _parse_budget_string(budget: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"^\$?([\d,]+(?:\.\d+)?)(?:\s*/\s*(day|week|month|year))?$",
        budget.strip(),
        flags=re.IGNORECASE,
    )
    if not match:
        raise ValueError(f'inline policy budget must look like "$500/day" (got {budget!r})')
    amount = float(match.group(1).replace(",", ""))
    period = match.group(2)
    resolved: dict[str, Any] = {"currency": "usd", "max_spend_usd": amount}
    if period:
        resolved["period"] = period.lower()
    return resolved


def discover_tool_names(tools: Any) -> list[str]:
    if isinstance(tools, Mapping):
        return [key for key in tools if str(key).strip()]
    if isinstance(tools, list):
        names: list[str] = []
        for tool in tools:
            if not isinstance(tool, Mapping) or not str(tool.get("name", "")).strip():
                raise TypeError("discovered tool array entries must include a non-empty name")
            names.append(str(tool["name"]).strip())
        return names
    raise TypeError("could not discover tool names; pass an object map or {name, execute}[]")


def inline_policy_to_document(
    inline: PaybondInlinePolicy | Mapping[str, Any],
    tools: Any,
) -> "PaybondPolicyDocumentV1":
    from paybond_kit.policy.schema import parse_paybond_policy_document_v1

    if isinstance(inline, Mapping) and not isinstance(inline, PaybondInlinePolicy):
        inline = PaybondInlinePolicy(
            budget=inline.get("budget"),
            approve=tuple(inline["approve"]) if inline.get("approve") else None,
            deny=tuple(inline["deny"]) if inline.get("deny") else None,
            name=inline.get("name"),
        )
    approve = inline.approve or ("*",)
    deny = inline.deny or ()
    allowed: list[str] = []
    tools_section: dict[str, Any] = {}
    for tool_name in discover_tool_names(tools):
        if deny and _matches_any(tool_name, deny):
            continue
        if not _matches_any(tool_name, approve):
            continue
        allowed.append(tool_name)
        tools_section[tool_name] = {
            "side_effecting": True,
            "evidence_preset": "cost_and_completion",
        }
    if not allowed:
        raise ValueError("inline policy matched no tools; widen approve patterns or pass explicit tools")
    budget = None
    if inline.budget is not None:
        budget = (
            _parse_budget_string(inline.budget)
            if isinstance(inline.budget, str)
            else dict(inline.budget)
        )
    return parse_paybond_policy_document_v1(
        {
            "version": 1,
            "name": inline.name or "inline-policy",
            "default_deny": True,
            "tools": tools_section,
            "intent": {
                "allowed_tools": allowed,
                **({"budget": budget} if budget else {}),
            },
        }
    )


def _binding_from_run(
    run: PaybondAgentRun,
    mode: Literal["sandbox", "attach"],
    user_id: str | None = None,
) -> PaybondInstrumentBindingBound:
    binding: PaybondInstrumentBindingBound = {
        "phase": "bound",
        "mode": mode,
        "intent_id": str(run.binding.intent_id),
        "capability_token": run.binding.capability_token,
        "tenant_id": run.binding.tenant_id,
    }
    if user_id:
        binding["user_id"] = user_id
    return binding


@dataclass(frozen=True, slots=True)
class PaybondInstrumentRuntime:
    """Bound Paybond runtime for one agent session — immutable; create a new runtime per request."""

    tools: Any
    run: PaybondAgentRun
    policy: PaybondPolicy
    hooks: Any
    binding: PaybondInstrumentBindingBound

    @property
    def status(self) -> PaybondInstrumentBinding:
        return self.binding

    def close(self) -> None:
        """Release hooks for this runtime (no-op today; reserved for long-lived sessions)."""
        return None


@dataclass(slots=True)
class PaybondInstrumented:
    """
    Static instrumentation: policy + tool shells.
    Call :meth:`bind` per session, or pass a ``context`` provider for lazy per-execution binding.
    """

    tools: Any
    policy: PaybondPolicy
    _paybond: PaybondAgentRunHost
    _raw_tools: Any
    _framework: GuardedAgentFramework
    _context_provider: PaybondInstrumentContextProvider | None = None
    _runtime_cache: dict[str, PaybondInstrumentRuntime] = field(default_factory=dict)

    @property
    def binding(self) -> PaybondInstrumentBindingDeferred | PaybondInstrumentBindingLazy:
        if self._context_provider is not None:
            return {"phase": "lazy"}
        return {"phase": "deferred"}

    @property
    def status(self) -> PaybondInstrumentBinding:
        return self.binding

    async def _resolve_runtime(self, context: PaybondInstrumentContext) -> PaybondInstrumentRuntime:
        _assert_instrument_context(context)
        key = _runtime_cache_key(context)
        cached = self._runtime_cache.get(key)
        if cached is not None:
            return cached
        runtime = await _create_bound_runtime(
            self._paybond,
            self.policy,
            self._raw_tools,
            self._framework,
            context,
            "attach",
        )
        self._runtime_cache[key] = runtime
        return runtime

    async def _resolve_runtime_from_provider(self) -> PaybondInstrumentRuntime:
        if self._context_provider is None:
            raise RuntimeError("lazy context resolution requires a context provider on instrument()")
        context = await _call_context_provider(self._context_provider)
        return await self._resolve_runtime(context)

    async def bind(self, context: PaybondInstrumentContext | Mapping[str, Any]) -> PaybondInstrumentRuntime:
        return await _create_bound_runtime(
            self._paybond,
            self.policy,
            self._raw_tools,
            self._framework,
            normalize_instrument_context(context),
            "attach",
        )

    async def with_context(self, context: PaybondInstrumentContext | Mapping[str, Any]) -> PaybondInstrumentRuntime:
        """Deprecated alias for :meth:`bind`."""
        return await self.bind(context)


@dataclass(frozen=True, slots=True)
class PaybondInstrumentBuilder:
    paybond: PaybondAgentRunHost
    policy: PaybondPolicyLoadSource | PaybondInlinePolicy | Mapping[str, Any]
    framework: GuardedAgentFramework | None = None

    async def instrument(
        self,
        tools: Any,
        *,
        sandbox: bool | None = None,
        context: PaybondInstrumentContextInput | None = None,
    ) -> PaybondInstrumented | PaybondInstrumentRuntime:
        payload: dict[str, Any] = {
            "policy": self.policy,
            "tools": tools,
            "framework": self.framework,
        }
        if sandbox is not None:
            payload["sandbox"] = sandbox
        if context is not None:
            payload["context"] = context
        return await instrument_paybond_agent(self.paybond, payload)


def _resolve_framework(framework: GuardedAgentFramework | None) -> GuardedAgentFramework:
    return framework or "generic"


async def _resolve_policy(
    policy_source: PaybondPolicyLoadSource | PaybondInlinePolicy | Mapping[str, Any] | PaybondPolicy | None,
    tools: Any,
) -> PaybondPolicy:
    from paybond_kit.policy.load import PaybondPolicy, PaybondPolicyLoadSource

    if policy_source is None:
        raise ValueError("instrument() requires policy (file path, preset id, inline object, or PaybondPolicy)")
    if isinstance(policy_source, PaybondPolicy):
        return policy_source
    if isinstance(policy_source, PaybondInlinePolicy) or (
        isinstance(policy_source, Mapping) and is_inline_policy(policy_source)
    ):
        return PaybondPolicy.from_document(inline_policy_to_document(policy_source, tools))
    return PaybondPolicy.load(cast(PaybondPolicyLoadSource, policy_source))


def _create_deferred_instrumented(
    paybond: PaybondAgentRunHost,
    policy: PaybondPolicy,
    raw_tools: Any,
    framework: GuardedAgentFramework,
    context_provider: PaybondInstrumentContextProvider | None = None,
) -> PaybondInstrumented:
    instrumented = PaybondInstrumented(
        tools=wrap_deferred_tools(raw_tools),
        policy=policy,
        _paybond=paybond,
        _raw_tools=raw_tools,
        _framework=framework,
        _context_provider=context_provider,
    )
    if context_provider is not None:
        instrumented.tools = wrap_lazy_context_tools(raw_tools, instrumented._resolve_runtime_from_provider)
    return instrumented


def _to_paybond_instrument_runtime(
    result: CreateGuardedAgentResult,
    bind_mode: Literal["sandbox", "attach"],
    user_id: str | None = None,
) -> PaybondInstrumentRuntime:
    from paybond_kit.agent.facade import to_paybond_agent_result

    agent_result = to_paybond_agent_result(result)
    return PaybondInstrumentRuntime(
        tools=agent_result.tools,
        run=agent_result.run,
        policy=agent_result.policy,
        hooks=agent_result.hooks,
        binding=_binding_from_run(agent_result.run, bind_mode, user_id),
    )


async def _create_bound_runtime(
    paybond: PaybondAgentRunHost,
    policy: PaybondPolicy,
    raw_tools: Any,
    framework: GuardedAgentFramework,
    context: PaybondInstrumentContext,
    bind_mode: Literal["sandbox", "attach"],
) -> PaybondInstrumentRuntime:
    if bind_mode == "sandbox":
        result = await create_guarded_agent(
            paybond,
            CreateGuardedAgentInput(
                policy=policy,
                framework=framework,
                tools=raw_tools,
            ),
        )
        mode: Literal["sandbox", "attach"] = "sandbox" if result.run.binding.sandbox else "attach"
        return _to_paybond_instrument_runtime(result, mode, context.user_id)

    attach: PaybondRunBindingAttachInput = {
        "intent_id": context.intent_id,
        "capability_token": context.capability_token,
    }
    if context.allowed_tools is not None:
        attach["allowed_tools"] = list(context.allowed_tools)
    if context.production_evidence is not None:
        attach["production_evidence"] = cast(
            PaybondRunProductionEvidenceCredentials,
            context.production_evidence,
        )
    if context.sandbox is not None:
        attach["sandbox"] = PaybondRunSandboxBinding(
            operation=str(context.sandbox.get("operation", "")),
            requested_spend_cents=int(context.sandbox.get("requested_spend_cents", 0)),
            sandbox_lifecycle_status=str(context.sandbox.get("sandbox_lifecycle_status", "")),
        )
    bind_config: PaybondAgentRunBindConfig = {
        "registry": policy.to_tool_registry(),
        "attach": attach,
    }
    run = await PaybondAgentRun.bind(paybond, bind_config)
    tools = _wrap_tools_for_framework(run, raw_tools, framework)
    result = CreateGuardedAgentResult(
        run=run,
        policy=policy,
        registry=policy.to_tool_registry(),
        framework=framework,
        agent_tools=tools,
    )
    return PaybondInstrumentRuntime(
        tools=tools,
        run=run,
        policy=policy,
        hooks=_hooks_from_result(result),
        binding=_binding_from_run(run, "attach", context.user_id),
    )


def _instrumentation_from_runtime(runtime: PaybondInstrumentRuntime) -> dict[str, Any]:
    return {
        "run": runtime.run,
        "policy": runtime.policy,
        "hooks": runtime.hooks,
        "tools": runtime.tools,
        "binding": runtime.binding,
        "status": runtime.status,
    }


def _instrumentation_from_instrumented(agent: Any, instrumented: PaybondInstrumented) -> dict[str, Any]:
    async def bind(context: PaybondInstrumentContext | Mapping[str, Any]) -> Mapping[str, Any]:
        runtime = await instrumented.bind(context)
        bound = _instrumentation_from_runtime(runtime)
        bound["bind"] = bind
        bound["with_context"] = bind
        attach_paybond_agent_instrumentation(agent, bound, runtime.tools)
        attached = read_paybond_agent_instrumentation(agent)
        if attached is None:
            raise RuntimeError("failed to attach paybond instrumentation to agent")
        return attached

    surface: dict[str, Any] = {
        "policy": instrumented.policy,
        "tools": instrumented.tools,
        "binding": instrumented.binding,
        "status": instrumented.status,
        "bind": bind,
        "with_context": bind,
    }
    return surface


async def _instrument_agent_object(
    paybond: PaybondAgentRunHost,
    agent: Any,
    *,
    policy: Any | None = None,
    framework: GuardedAgentFramework | None = None,
    sandbox: bool | None = None,
    context: PaybondInstrumentContextInput | None = None,
) -> Any:
    raw_tools = discover_tools_from_agent(agent)
    policy_source = discover_policy_from_agent(agent, policy=policy)
    resolved_framework = _resolve_framework(framework)
    policy_doc = await _resolve_policy(policy_source, raw_tools)

    if sandbox:
        runtime = await _create_bound_runtime(
            paybond,
            policy_doc,
            raw_tools,
            resolved_framework,
            PaybondInstrumentContext(intent_id="", capability_token=""),
            "sandbox",
        )
        surface = _instrumentation_from_runtime(runtime)
        attach_paybond_agent_instrumentation(agent, surface, runtime.tools)
        return agent

    if context is not None:
        if is_context_provider(context):
            instrumented = _create_deferred_instrumented(
                paybond,
                policy_doc,
                raw_tools,
                resolved_framework,
                context,
            )
            surface = _instrumentation_from_instrumented(agent, instrumented)
            attach_paybond_agent_instrumentation(agent, surface, instrumented.tools)
            return agent
        runtime = await _create_bound_runtime(
            paybond,
            policy_doc,
            raw_tools,
            resolved_framework,
            normalize_instrument_context(context),
            "attach",
        )
        surface = _instrumentation_from_runtime(runtime)
        attach_paybond_agent_instrumentation(agent, surface, runtime.tools)
        return agent

    instrumented = _create_deferred_instrumented(paybond, policy_doc, raw_tools, resolved_framework)
    surface = _instrumentation_from_instrumented(agent, instrumented)
    attach_paybond_agent_instrumentation(agent, surface, instrumented.tools)
    return agent


def _normalize_instrument_config(
    input_: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "policy": input_.get("policy"),
        "tools": input_.get("tools"),
        "framework": input_.get("framework"),
        "bootstrap": input_.get("bootstrap"),
        "attach": input_.get("attach"),
        "run_id": input_.get("run_id"),
        "validate_policy": input_.get("validate_policy"),
        "sandbox": input_.get("sandbox"),
        "context": input_.get("context"),
    }


async def instrument_paybond_agent(
    paybond: PaybondAgentRunHost,
    input_: CreateGuardedAgentInput | Mapping[str, Any] | Any,
    *,
    framework: GuardedAgentFramework | None = None,
    policy: Any | None = None,
    sandbox: bool | None = None,
    context: PaybondInstrumentContextInput | None = None,
) -> PaybondInstrumented | PaybondInstrumentRuntime | Any:
    if is_instrumentable_agent_object(input_):
        return await _instrument_agent_object(
            paybond,
            input_,
            policy=policy,
            framework=framework,
            sandbox=sandbox,
            context=context,
        )

    if isinstance(input_, CreateGuardedAgentInput):
        resolved_policy = input_.policy
        resolved_tools = input_.tools
        resolved_framework = framework or input_.framework or "generic"
        resolved_sandbox = sandbox
        resolved_attach = getattr(input_, "attach", None)
        resolved_context = context
    else:
        if input_.get("tools") is None:
            raise ValueError("instrument() requires tools")
        normalized = _normalize_instrument_config(input_)
        resolved_policy = normalized["policy"]
        resolved_tools = normalized["tools"]
        resolved_framework = _resolve_framework(framework or normalized["framework"])
        resolved_sandbox = sandbox if sandbox is not None else normalized.get("sandbox")
        resolved_attach = normalized.get("attach")
        resolved_context = context if context is not None else normalized.get("context")

    policy_doc = await _resolve_policy(resolved_policy, resolved_tools)

    attach_context = _resolve_instrument_attach_context(resolved_attach)
    if attach_context is not None and resolved_context is not None:
        raise ValueError("instrument() accepts either attach or context, not both")
    if attach_context is not None and resolved_sandbox:
        raise ValueError('instrument() accepts either sandbox: true, attach, or context — not multiple bind modes')
    effective_context = attach_context if attach_context is not None else resolved_context

    use_sandbox = bool(resolved_sandbox)
    if effective_context is not None:
        if is_context_provider(effective_context):
            return _create_deferred_instrumented(
                paybond,
                policy_doc,
                resolved_tools,
                resolved_framework,
                effective_context,
            )
        return await _create_bound_runtime(
            paybond,
            policy_doc,
            resolved_tools,
            resolved_framework,
            normalize_instrument_context(effective_context),
            "attach",
        )

    if use_sandbox:
        return await _create_bound_runtime(
            paybond,
            policy_doc,
            resolved_tools,
            resolved_framework,
            PaybondInstrumentContext(intent_id="", capability_token=""),
            "sandbox",
        )

    return _create_deferred_instrumented(paybond, policy_doc, resolved_tools, resolved_framework)


async def instrument_paybond_langgraph(
    paybond: PaybondAgentRunHost,
    input_: Mapping[str, Any],
) -> PaybondInstrumented | PaybondInstrumentRuntime:
    return await instrument_paybond_agent(paybond, input_, framework="langgraph")


async def instrument_paybond_openai(
    paybond: PaybondAgentRunHost,
    input_: Mapping[str, Any],
) -> PaybondInstrumented | PaybondInstrumentRuntime:
    return await instrument_paybond_agent(paybond, input_, framework="openai-agents")


async def instrument_paybond_vercel(
    paybond: PaybondAgentRunHost,
    input_: Mapping[str, Any],
) -> PaybondInstrumented | PaybondInstrumentRuntime:
    return await instrument_paybond_agent(paybond, input_, framework="vercel-ai")


async def instrument_paybond_claude_agents(
    paybond: PaybondAgentRunHost,
    input_: Mapping[str, Any],
) -> PaybondInstrumented | PaybondInstrumentRuntime:
    return await instrument_paybond_agent(paybond, input_, framework="claude-agents")


async def instrument_paybond_crewai(
    paybond: PaybondAgentRunHost,
    input_: Mapping[str, Any],
) -> PaybondInstrumented | PaybondInstrumentRuntime:
    return await instrument_paybond_agent(paybond, input_, framework="crewai")


async def instrument_paybond_mcp(
    paybond: PaybondAgentRunHost,
    input_: Mapping[str, Any],
) -> PaybondInstrumented | PaybondInstrumentRuntime:
    return await instrument_paybond_agent(paybond, input_)


__all__ = [
    "PaybondInlinePolicy",
    "PaybondInstrumentBinding",
    "PaybondInstrumentBindingBound",
    "PaybondInstrumentBindingDeferred",
    "PaybondInstrumentBindingLazy",
    "PaybondInstrumentBuilder",
    "PaybondInstrumentContext",
    "PaybondInstrumentContextInput",
    "PaybondInstrumentContextProvider",
    "PaybondInstrumentRuntime",
    "PaybondInstrumented",
    "PaybondLazyContextError",
    "PaybondUnboundContextError",
    "discover_tool_names",
    "inline_policy_to_document",
    "instrument_paybond_agent",
    "instrument_paybond_claude_agents",
    "instrument_paybond_langgraph",
    "instrument_paybond_mcp",
    "instrument_paybond_openai",
    "instrument_paybond_vercel",
    "is_context_provider",
    "is_inline_policy",
    "normalize_instrument_context",
    "wrap_deferred_tools",
    "wrap_lazy_context_tools",
]
