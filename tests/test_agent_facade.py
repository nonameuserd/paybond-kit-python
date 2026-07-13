from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from paybond_kit.agent.facade import (
    create_paybond_agent,
    resolve_agent_policy_source,
    wrap_paybond_tools,
)
from paybond_kit.agent.instrument import (
    PaybondInstrumentContext,
    PaybondInstrumentRuntime,
    PaybondInstrumented,
    PaybondUnboundContextError,
    discover_tool_names,
    instrument_paybond_agent,
)
from paybond_kit.agent.guarded_agent import (
    CreateGuardedAgentInput,
    create_guarded_agent_runner,
)

TRAVEL_POLICY: dict[str, Any] = {
    "version": 1,
    "name": "travel-agent-v1",
    "default_deny": True,
    "tools": {
        "travel.book_hotel": {
            "side_effecting": True,
            "max_spend_cents": 20000,
            "evidence_preset": "cost_and_completion",
        },
    },
    "intent": {"allowed_tools": ["travel.book_hotel"]},
}

BIND_CONTEXT = PaybondInstrumentContext(
    intent_id="40000000-0000-4000-8000-000000000010",
    capability_token="cap-prod",
    user_id="user-42",
    allowed_tools=("travel.book_hotel",),
    sandbox={
        "operation": "travel.book_hotel",
        "requested_spend_cents": 20_000,
        "sandbox_lifecycle_status": "funded",
    },
)


def _make_host() -> MagicMock:
    host = MagicMock()
    host.harbor.tenant_id = "tenant-a"
    host.harbor.get_intent = AsyncMock(
        return_value={"tenant_id": "tenant-a", "allowed_tools": ["travel.book_hotel"]}
    )
    host.harbor.submit_evidence = AsyncMock(
        return_value={
            "intentId": "40000000-0000-4000-8000-000000000010",
            "tenant": "tenant-a",
            "state": "completed",
        }
    )
    host.guardrails.bootstrap_sandbox = AsyncMock(
        return_value=type(
            "BootstrapResult",
            (),
            {
                "tenant_id": "tenant-a",
                "intent_id": "intent-sandbox",
                "capability_token": "cap-sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
                "sandbox_lifecycle_status": "funded",
            },
        )()
    )
    host.guardrails.submit_sandbox_evidence = AsyncMock(
        return_value=type(
            "SandboxEvidenceResult",
            (),
            {
                "intent_id": "intent-sandbox",
                "predicate_passed": True,
                "sandbox_lifecycle_status": "completed",
            },
        )()
    )
    auth_result = type(
        "SpendAuthResult",
        (),
        {"allow": True, "audit_id": "audit-stub", "decision_id": None},
    )()
    host.spend_guard.return_value.assert_spend_authorized = AsyncMock(return_value=auth_result)
    host.spend_guard.return_value.complete_spend_authorization = AsyncMock()
    return host


def test_policy_preset_resolution() -> None:
    from paybond_kit.policy.presets import is_known_policy_preset_id, resolve_policy_preset_path

    assert is_known_policy_preset_id("travel")
    assert is_known_policy_preset_id("read-only")
    assert is_known_policy_preset_id("strict")
    assert resolve_policy_preset_path("travel").endswith("travel.yaml")
    travel_policy_source = resolve_agent_policy_source("travel")
    assert isinstance(travel_policy_source, str)
    assert travel_policy_source.endswith("travel.yaml")
    assert resolve_agent_policy_source("./paybond.policy.yaml") == "./paybond.policy.yaml"


@pytest.mark.asyncio
async def test_instrument_defaults_to_deferred_tool_shells() -> None:
    host = _make_host()
    book_hotel = AsyncMock(return_value={"status": "completed", "cost_cents": 20_000})

    result = await instrument_paybond_agent(
        host,
        {
            "policy": TRAVEL_POLICY,
            "tools": {"travel.book_hotel": book_hotel},
        },
    )

    assert isinstance(result, PaybondInstrumented)
    assert result.binding == {"phase": "deferred"}
    assert discover_tool_names(result.tools) == ["travel.book_hotel"]
    assert not hasattr(result, "run")


@pytest.mark.asyncio
async def test_deferred_tool_execute_raises_unbound_error() -> None:
    host = _make_host()
    instrumented = await instrument_paybond_agent(
        host,
        {
            "policy": TRAVEL_POLICY,
            "tools": {"travel.book_hotel": AsyncMock(return_value={"ok": True})},
        },
    )
    tools = instrumented.tools
    assert isinstance(tools, dict)
    with pytest.raises(PaybondUnboundContextError):
        await tools["travel.book_hotel"]()


@pytest.mark.asyncio
async def test_instrument_sandbox_returns_runtime() -> None:
    host = _make_host()
    runtime = await instrument_paybond_agent(
        host,
        {
            "policy": TRAVEL_POLICY,
            "tools": {"travel.book_hotel": AsyncMock(return_value={"ok": True})},
            "sandbox": True,
        },
    )
    assert isinstance(runtime, PaybondInstrumentRuntime)
    assert runtime.binding["phase"] == "bound"
    assert runtime.binding["mode"] == "sandbox"
    assert runtime.binding["intent_id"] == "intent-sandbox"
    assert len(runtime.tools) == 1
    assert runtime.run is not None


@pytest.mark.asyncio
async def test_bind_returns_immutable_runtime() -> None:
    host = _make_host()
    instrumented = await instrument_paybond_agent(
        host,
        {
            "policy": TRAVEL_POLICY,
            "tools": {"travel.book_hotel": AsyncMock(return_value={"ok": True})},
        },
    )
    assert isinstance(instrumented, PaybondInstrumented)
    runtime = await instrumented.bind(BIND_CONTEXT)
    assert isinstance(runtime, PaybondInstrumentRuntime)
    assert runtime.binding["phase"] == "bound"
    assert runtime.binding["mode"] == "attach"
    assert runtime.binding["intent_id"] == BIND_CONTEXT.intent_id
    assert runtime.binding.get("user_id") == "user-42"
    assert instrumented.binding == {"phase": "deferred"}


@pytest.mark.asyncio
async def test_lazy_context_provider_binds_on_execute() -> None:
    host = _make_host()
    book_hotel = AsyncMock(return_value={"status": "completed", "cost_cents": 20_000})

    instrumented = await instrument_paybond_agent(
        host,
        {
            "policy": TRAVEL_POLICY,
            "tools": {"travel.book_hotel": book_hotel},
            "context": lambda: BIND_CONTEXT,
        },
    )

    assert isinstance(instrumented, PaybondInstrumented)
    assert instrumented.binding == {"phase": "lazy"}
    tools = instrumented.tools
    assert isinstance(tools, dict)
    await tools["travel.book_hotel"](
        {
            "tool_name": "travel.book_hotel",
            "tool_call_id": "call-1",
            "arguments": {"hotel": "ritz"},
        }
    )
    book_hotel.assert_awaited()


@pytest.mark.asyncio
async def test_lazy_context_provider_raises_when_empty() -> None:
    from paybond_kit.agent.instrument import PaybondLazyContextError

    host = _make_host()
    instrumented = await instrument_paybond_agent(
        host,
        {
            "policy": TRAVEL_POLICY,
            "tools": {"travel.book_hotel": AsyncMock(return_value={"ok": True})},
            "context": lambda: {"intent_id": "", "capability_token": ""},
        },
    )
    with pytest.raises(PaybondLazyContextError):
        await instrumented.tools["travel.book_hotel"]()


@pytest.mark.asyncio
async def test_create_paybond_agent_resolves_travel_preset() -> None:
    host = _make_host()
    book_hotel = AsyncMock(return_value={"status": "completed", "cost_cents": 20_000})

    result = await create_paybond_agent(
        host,
        policy="travel",
        framework="generic",
        tools={"travel.book_hotel": book_hotel},
    )

    assert result.policy.name == "travel-agent-v1"
    assert len(result.tools) == 1
    assert result.hooks.input_guard is not None
    assert result.run is not None


@pytest.mark.asyncio
async def test_wrap_paybond_tools_wraps_generic_tools() -> None:
    host = _make_host()
    guarded = await create_paybond_agent(
        host,
        policy=TRAVEL_POLICY,
        framework="generic",
        tools={"travel.book_hotel": AsyncMock(return_value={"ok": True})},
    )
    search_web = AsyncMock(return_value={"hits": []})

    wrapped = wrap_paybond_tools(
        guarded.run,
        {"search.web": search_web},
        framework="generic",
    )

    assert len(wrapped) == 1
    await wrapped[0]["execute"](
        {
            "tool_name": "search.web",
            "tool_call_id": "call-search",
            "arguments": {"q": "paris"},
        }
    )
    search_web.assert_awaited()


def test_wrap_paybond_tools_rejects_langgraph() -> None:
    run = MagicMock()
    with pytest.raises(ValueError, match="langgraph"):
        wrap_paybond_tools(run, [], framework="langgraph")


def test_wrap_paybond_tools_rejects_microsoft_agent_framework() -> None:
    run = MagicMock()
    with pytest.raises(ValueError, match="microsoft-agent-framework"):
        wrap_paybond_tools(run, [], framework="microsoft-agent-framework")


def test_to_paybond_agent_result_exposes_microsoft_agent_framework_middleware() -> None:
    from paybond_kit.agent.facade import to_paybond_agent_result
    from paybond_kit.agent.guarded_agent import CreateGuardedAgentResult
    from paybond_kit.microsoft_agent_framework.config import PaybondMicrosoftAgentFrameworkConfig

    middleware = object()
    config = PaybondMicrosoftAgentFrameworkConfig(
        tools=["tool-a"],
        middleware=[middleware],
        wrap_tool=lambda tool: tool,
    )
    result = CreateGuardedAgentResult(
        run=MagicMock(),
        policy=MagicMock(),
        registry=MagicMock(),
        framework="microsoft-agent-framework",
        agent_tools=config.tools,
        microsoft_agent_framework_config=config,
    )
    agent_result = to_paybond_agent_result(result)
    assert agent_result.hooks.middleware == [middleware]
    assert agent_result.hooks.microsoft_agent_framework_config is config
    assert agent_result.tools == ["tool-a"]


@pytest.mark.parametrize(
    ("framework", "docs_path"),
    [
        ("vercel-ai", "https://docs.paybond.ai/kit/vercel-ai"),
    ],
)
def test_wrap_paybond_tools_rejects_typescript_only_frameworks(
    framework: str,
    docs_path: str,
) -> None:
    run = MagicMock()
    with pytest.raises(ValueError, match=docs_path):
        wrap_paybond_tools(run, [], framework=framework)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_instrument_discovers_agent_tools() -> None:
    from paybond_kit.agent.discover import discover_tools_from_agent

    class Agent:
        def __init__(self, tools: dict[str, Any]) -> None:
            self.tools = tools
            self.policy = TRAVEL_POLICY
            self.paybond: dict[str, Any] = {}

    host = _make_host()
    book_hotel = AsyncMock(return_value={"status": "completed", "cost_cents": 20_000})
    agent = Agent({"travel.book_hotel": book_hotel})
    assert discover_tools_from_agent(agent) is agent.tools

    result = await instrument_paybond_agent(host, agent)
    assert result is agent
    assert agent.paybond is not None
    assert agent.paybond["binding"] == {"phase": "deferred"}
    assert agent.paybond["bind"] is not None


@pytest.mark.asyncio
async def test_agent_paybond_bind_patches_guarded_tools() -> None:
    class Agent:
        def __init__(self, tools: dict[str, Any]) -> None:
            self.tools = tools
            self.policy = TRAVEL_POLICY
            self.paybond: dict[str, Any] = {}

    host = _make_host()
    agent = Agent({"travel.book_hotel": AsyncMock(return_value={"ok": True})})
    await instrument_paybond_agent(host, agent)

    bound = await agent.paybond["bind"](BIND_CONTEXT)
    assert bound["binding"]["intent_id"] == BIND_CONTEXT.intent_id
    assert agent.paybond["run"] is not None
    assert isinstance(agent.tools, list)
    assert len(agent.tools) == 1


@pytest.mark.asyncio
async def test_paybond_instrument_agent_positional() -> None:
    from paybond_kit.paybond import Paybond

    class Agent:
        def __init__(self, tools: dict[str, Any]) -> None:
            self.tools = tools
            self.policy = TRAVEL_POLICY
            self.paybond: dict[str, Any] = {}

    host = _make_host()
    paybond = Paybond(
        harbor=host.harbor,
        guardrails=host.guardrails,
        signal=MagicMock(),
        fraud=MagicMock(),
        a2a=MagicMock(),
        protocol=MagicMock(),
        intents=MagicMock(),
        audit=MagicMock(),
    )
    agent = Agent({"travel.book_hotel": AsyncMock(return_value={"ok": True})})
    result = await paybond.instrument(agent)
    assert result is agent
    assert agent.paybond is not None
    assert agent.paybond["binding"]["phase"] == "deferred"


@pytest.mark.asyncio
async def test_paybond_facade_methods() -> None:
    from paybond_kit.paybond import Paybond

    host = _make_host()
    paybond = Paybond(
        harbor=host.harbor,
        guardrails=host.guardrails,
        signal=MagicMock(),
        fraud=MagicMock(),
        a2a=MagicMock(),
        protocol=MagicMock(),
        intents=MagicMock(),
        audit=MagicMock(),
    )

    assert create_guarded_agent_runner is not None

    instrumented = await paybond.instrument(
        policy=TRAVEL_POLICY,
        tools={"travel.book_hotel": AsyncMock(return_value={"ok": True})},
    )
    assert instrumented.binding == {"phase": "deferred"}
    assert "travel.book_hotel" in instrumented.tools

    sandbox_runtime = await paybond.instrument(
        policy=TRAVEL_POLICY,
        tools={"travel.book_hotel": AsyncMock(return_value={"ok": True})},
        sandbox=True,
    )
    assert isinstance(sandbox_runtime, PaybondInstrumentRuntime)

    agent = await paybond.agent(
        policy="travel",
        framework="generic",
        tools={"travel.book_hotel": AsyncMock(return_value={"ok": True})},
    )
    assert agent.policy.name == "travel-agent-v1"
    assert len(agent.tools) == 1
    assert agent.hooks.input_guard is not None

    runner = await paybond.create_guarded_agent_runner(
        CreateGuardedAgentInput(
            policy=TRAVEL_POLICY,
            framework="generic",
            tools={"travel.book_hotel": AsyncMock(return_value={"ok": True})},
        )
    )
    assert runner.framework == "generic"

    wrapped = paybond.wrap_tools(
        sandbox_runtime.run,
        {"search.web": AsyncMock(return_value={"hits": []})},
        framework="generic",
    )
    assert len(wrapped) == 1
