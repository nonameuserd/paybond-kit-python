from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from paybond_kit.agent.guarded_agent import (
    CreateGuardedAgentInput,
    create_guarded_agent,
    create_guarded_agent_runner,
)
from paybond_kit.policy import (
    PaybondPolicy,
    PaybondPolicySandboxBootstrapError,
    policy_sandbox_bootstrap,
)

TRAVEL_POLICY = {
    "version": 1,
    "name": "travel-agent-v1",
    "default_deny": True,
    "tools": {
        "travel.book_hotel": {
            "side_effecting": True,
            "max_spend_cents": 20000,
            "evidence_preset": "cost_and_completion",
        },
        "search.web": {
            "side_effecting": False,
        },
    },
    "intent": {
        "allowed_tools": ["travel.book_hotel"],
        "budget": {"currency": "usd", "max_spend_usd": 200},
    },
}


def test_policy_sandbox_bootstrap_defaults_to_first_side_effecting_tool() -> None:
    policy = PaybondPolicy.load(TRAVEL_POLICY)
    bootstrap = policy.sandbox_bootstrap()

    assert bootstrap["kind"] == "sandbox"
    assert bootstrap["operation"] == "travel.book_hotel"
    assert bootstrap["requested_spend_cents"] == 20000
    assert bootstrap.get("currency") == "usd"
    assert bootstrap.get("completion_preset") == "cost_and_completion"
    assert "evidence_schema" not in bootstrap
    assert "template_id" not in bootstrap
    assert "parameters" not in bootstrap


def test_policy_sandbox_bootstrap_rejects_read_only_policy() -> None:
    with pytest.raises(PaybondPolicySandboxBootstrapError):
        policy_sandbox_bootstrap(
            PaybondPolicy.load(
                {
                    "version": 1,
                    "name": "read-only",
                    "default_deny": True,
                    "tools": {"search.web": {"side_effecting": False}},
                }
            ).document
        )


@pytest.mark.asyncio
async def test_create_guarded_agent_generic_from_policy_record() -> None:
    bootstrap = AsyncMock(
        return_value=type(
            "BootstrapResult",
            (),
            {
                "tenant_id": "tenant-a",
                "intent_id": "intent-sandbox",
                "capability_token": "cap-sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20000,
                "sandbox_lifecycle_status": "funded",
            },
        )()
    )
    host = type(
        "Host",
        (),
        {
            "harbor": type("Harbor", (), {"tenant_id": "tenant-a"})(),
            "guardrails": type("Guardrails", (), {"bootstrap_sandbox": bootstrap})(),
            "spend_guard": lambda _self, _intent_id, _token: type(
                "Guard",
                (),
                {
                    "assert_spend_authorized": AsyncMock(
                        return_value={"allow": True, "audit_id": "audit-stub"}
                    ),
                    "complete_spend_authorization": AsyncMock(),
                },
            )(),
        },
    )()

    async def book_hotel(_args: dict[str, object]) -> dict[str, object]:
        return {"status": "completed", "cost_cents": 20000}

    result = await create_guarded_agent(
        host,  # type: ignore[arg-type]
        CreateGuardedAgentInput(
            policy=TRAVEL_POLICY,
            framework="generic",
            tools={"travel.book_hotel": book_hotel},
        ),
    )

    assert result.framework == "generic"
    assert result.policy.name == "travel-agent-v1"
    assert str(result.run.intent_id) == "intent-sandbox"
    assert len(result.agent_tools) == 1
    bootstrap.assert_awaited_once()


def _make_host(*, bootstrap: AsyncMock | None = None) -> SimpleNamespace:
    guard = SimpleNamespace(
        assert_spend_authorized=AsyncMock(
            return_value=SimpleNamespace(allow=True, audit_id="audit-stub", decision_id=None),
        ),
        complete_spend_authorization=AsyncMock(),
    )
    return SimpleNamespace(
        harbor=SimpleNamespace(tenant_id="tenant-a"),
        guardrails=SimpleNamespace(bootstrap_sandbox=bootstrap or AsyncMock()),
        spend_guard=lambda *_args, **_kwargs: guard,
    )


@pytest.mark.asyncio
async def test_create_guarded_agent_langgraph_returns_awrap_hook() -> None:
    bootstrap = AsyncMock(
        return_value=SimpleNamespace(
            tenant_id="tenant-a",
            intent_id="intent-sandbox",
            capability_token="cap-sandbox",
            operation="travel.book_hotel",
            requested_spend_cents=20000,
            sandbox_lifecycle_status="funded",
        )
    )
    host = _make_host(bootstrap=bootstrap)
    raw_tools = [{"name": "search.web"}]

    result = await create_guarded_agent(
        host,  # type: ignore[arg-type]
        CreateGuardedAgentInput(
            policy=TRAVEL_POLICY,
            framework="langgraph",
            tools=raw_tools,
        ),
    )

    assert result.framework == "langgraph"
    assert result.agent_tools is raw_tools
    assert callable(result.awrap_tool_call)
    assert callable(result.create_tool_node)


@pytest.mark.asyncio
async def test_create_guarded_agent_claude_agents_wraps_sdk_tools() -> None:
    bootstrap = AsyncMock(
        return_value=SimpleNamespace(
            tenant_id="tenant-a",
            intent_id="intent-sandbox",
            capability_token="cap-sandbox",
            operation="travel.book_hotel",
            requested_spend_cents=20000,
            sandbox_lifecycle_status="funded",
        )
    )
    host = _make_host(bootstrap=bootstrap)
    book_hotel_handler = AsyncMock(
        return_value={
            "content": [{"type": "text", "text": '{"status": "completed", "cost_cents": 20000}'}],
            "structuredContent": {"status": "completed", "cost_cents": 20000},
        }
    )

    @dataclass
    class MockSdkTool:
        name: str
        description: str
        handler: AsyncMock

    tools = [
        MockSdkTool(
            name="travel.book_hotel",
            description="Book a hotel",
            handler=book_hotel_handler,
        )
    ]
    fake_mcp_server = {"name": "paybond", "tools": tools}

    with patch(
        "paybond_kit.claude_agents.config._require_claude_agent_sdk",
        return_value=SimpleNamespace(
            create_sdk_mcp_server=lambda **kwargs: {**fake_mcp_server, **kwargs}
        ),
    ):
        result = await create_guarded_agent(
            host,  # type: ignore[arg-type]
            CreateGuardedAgentInput(
                policy=TRAVEL_POLICY,
                framework="claude-agents",
                tools=tools,
            ),
        )

    assert result.framework == "claude-agents"
    assert result.claude_agents_config is not None
    assert result.claude_agents_config.allowed_tools == ["mcp__paybond__travel.book_hotel"]
    assert result.agent_tools is tools

    await tools[0].handler({"estimatedPriceCents": 20000}, {"toolUseID": "call-claude-1"})
    book_hotel_handler.assert_awaited_once_with(
        {"estimatedPriceCents": 20000},
        {"toolUseID": "call-claude-1"},
    )
    bootstrap.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_guarded_agent_crewai_wraps_tools() -> None:
    bootstrap = AsyncMock(
        return_value=SimpleNamespace(
            tenant_id="tenant-a",
            intent_id="intent-sandbox",
            capability_token="cap-sandbox",
            operation="procurement.submit_po",
            requested_spend_cents=12000,
            sandbox_lifecycle_status="funded",
        )
    )
    host = _make_host(bootstrap=bootstrap)

    @dataclass
    class MockCrewTool:
        name: str
        description: str
        func: Any

    def submit_po(vendor_id: str, amount_cents: int) -> str:
        return f'{{"status": "completed", "cost_cents": {amount_cents}}}'

    tools = [
        MockCrewTool(
            name="procurement.submit_po",
            description="Submit PO",
            func=submit_po,
        )
    ]

    with patch("paybond_kit.crewai.config._require_crewai_tools", return_value=MagicMock()):
        with patch("paybond_kit.crewai.config.is_crewai_base_tool", return_value=False):
            result = await create_guarded_agent(
                host,  # type: ignore[arg-type]
                CreateGuardedAgentInput(
                    policy={
                        "version": 1,
                        "name": "procurement-agent-v1",
                        "default_deny": True,
                        "tools": {
                            "procurement.submit_po": {
                                "side_effecting": True,
                                "evidence_preset": "cost_and_completion",
                            }
                        },
                    },
                    framework="crewai",
                    tools=tools,
                ),
            )

    assert result.framework == "crewai"
    assert result.crewai_config is not None
    assert result.agent_tools is result.crewai_config.tools
    bootstrap.assert_awaited_once()


def test_create_guarded_agent_runner_is_alias() -> None:
    assert create_guarded_agent_runner is create_guarded_agent


@pytest.mark.asyncio
async def test_create_guarded_agent_openai_agents_framework() -> None:
    bootstrap = AsyncMock(
        return_value=SimpleNamespace(
            tenant_id="tenant-a",
            intent_id="intent-sandbox",
            capability_token="cap-sandbox",
            operation="travel.book_hotel",
            requested_spend_cents=20_000,
            sandbox_lifecycle_status="funded",
        )
    )
    host = _make_host(bootstrap=bootstrap)

    @dataclass
    class MockOpenAITool:
        name: str
        description: str
        params_json_schema: dict[str, Any]
        on_invoke_tool: Any
        tool_input_guardrails: list[Any] | None = None
        needs_approval: bool = False

    async def book_hotel(_ctx: Any, _input_json: str) -> str:
        return '{"status":"completed","cost_cents":20000}'

    tools = [
        MockOpenAITool(
            name="travel.book_hotel",
            description="Book hotel",
            params_json_schema={"type": "object", "properties": {}},
            on_invoke_tool=book_hotel,
        )
    ]

    agents = MagicMock()
    agents.ToolInputGuardrail = MagicMock
    agents.ToolGuardrailFunctionOutput = MagicMock()
    agents.RunConfig = MagicMock(side_effect=lambda **kwargs: kwargs)
    agents.ToolExecutionConfig = MagicMock(side_effect=lambda **kwargs: kwargs)

    with patch("paybond_kit.openai_agents.config._require_openai_agents", return_value=agents):
        with patch("paybond_kit.openai_agents.config.is_openai_function_tool", return_value=True):
            result = await create_guarded_agent(
                host,  # type: ignore[arg-type]
                CreateGuardedAgentInput(
                    policy=TRAVEL_POLICY,
                    framework="openai-agents",
                    tools=tools,
                ),
            )

    assert result.framework == "openai-agents"
    assert result.openai_agents_adapter is not None
    assert result.run_config is not None
    assert result.agent_tools
    bootstrap.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_guarded_agent_rejects_vercel_framework() -> None:
    host = _make_host()

    with pytest.raises(ValueError, match="https://docs.paybond.ai/kit/vercel-ai"):
        await create_guarded_agent(
            host,  # type: ignore[arg-type]
            CreateGuardedAgentInput(
                policy=TRAVEL_POLICY,
                framework="vercel-ai",
                tools={},
            ),
        )
