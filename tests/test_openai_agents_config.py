"""Tests for OpenAI Agents runner helper."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry
from paybond_kit.openai_agents.config import (
    create_openai_agents_adapter,
    create_paybond_openai_agents_config,
    map_paybond_decision_to_openai_tool_guardrail,
)
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError

# The `openai-agents` package is an optional extra (`paybond-kit[openai-agents]`)
# and is not part of the `dev` extra installed in CI. Tests that exercise the real
# guardrail path outside the `_require_openai_agents` patch need it installed.
_OPENAI_AGENTS_AVAILABLE = importlib.util.find_spec("agents") is not None


@dataclass
class MockToolGuardrailOutput:
    output_info: Any = None
    behavior: dict[str, Any] = field(default_factory=lambda: {"type": "allow"})

    @classmethod
    def allow(cls, *, output_info: Any = None) -> MockToolGuardrailOutput:
        return cls(output_info=output_info, behavior={"type": "allow"})

    @classmethod
    def reject_content(cls, message: str, *, output_info: Any = None) -> MockToolGuardrailOutput:
        return cls(
            output_info=output_info,
            behavior={"type": "reject_content", "message": message},
        )


@dataclass
class MockFunctionTool:
    name: str
    description: str
    params_json_schema: dict[str, Any]
    on_invoke_tool: Any
    strict_json_schema: bool = True
    tool_input_guardrails: list[Any] | None = None
    needs_approval: bool = False


@dataclass
class MockToolInputGuardrail:
    guardrail_function: Any
    name: str | None = None

    async def run(self, data: Any) -> Any:
        result = self.guardrail_function(data)
        if hasattr(result, "__await__"):
            return await result
        return result


@dataclass
class MockToolInputGuardrailData:
    context: Any
    agent: Any = None


@dataclass
class MockToolContext:
    tool_name: str
    tool_call_id: str
    tool_arguments: str


def _mock_agents_module() -> MagicMock:
    module = MagicMock()
    module.FunctionTool = MockFunctionTool
    module.ToolInputGuardrail = MockToolInputGuardrail
    module.ToolInputGuardrailData = MockToolInputGuardrailData
    module.ToolGuardrailFunctionOutput = MockToolGuardrailOutput
    module.RunConfig = MagicMock(side_effect=lambda **kwargs: {"run_config": kwargs})
    module.ToolExecutionConfig = MagicMock(side_effect=lambda **kwargs: kwargs)
    return module


def _make_registry() -> Any:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: int(args.get("estimatedPriceCents", 0)),
                    "evidence_preset": "cost_and_completion",
                    "evidence_mapper": lambda result, _ctx: {
                        "status": result["reservation"]["status"],
                        "cost_cents": result["reservation"]["price_cents"],
                    },
                },
            },
            "default_deny": True,
        }
    )


def _make_host(*, allow: bool = True) -> MagicMock:
    guard = MagicMock()
    if allow:
        guard.assert_spend_authorized = AsyncMock(
            return_value=MagicMock(allow=True, audit_id="audit-1", decision_id="decision-1")
        )
    else:
        guard.assert_spend_authorized = AsyncMock(
            side_effect=PaybondSpendDeniedError(
                MagicMock(allow=False, code="denied", message="capability denied", decision_id=None)
            )
        )
    guard.complete_spend_authorization = AsyncMock()

    host = MagicMock()
    host.harbor.tenant_id = "tenant-a"
    host.guardrails.bootstrap_sandbox = AsyncMock(
        return_value=MagicMock(
            tenant_id="tenant-a",
            intent_id=UUID("00000000-0000-4000-8000-000000000001"),
            capability_token="cap-sandbox",
            operation="travel.book_hotel",
            requested_spend_cents=20_000,
            sandbox_lifecycle_status="funded",
        )
    )
    host.guardrails.submit_sandbox_evidence = AsyncMock(
        return_value=MagicMock(
            tenant_id="tenant-a",
            intent_id=UUID("00000000-0000-4000-8000-000000000001"),
            sandbox_lifecycle_status="completed",
            predicate_passed=True,
        )
    )
    host.spend_guard = MagicMock(return_value=guard)
    return host


def test_map_paybond_decision_to_openai_tool_guardrail() -> None:
    agents = _mock_agents_module()
    with patch("paybond_kit.openai_agents.config._require_openai_agents", return_value=agents):
        allow = map_paybond_decision_to_openai_tool_guardrail(
            {"kind": "allow", "audit_id": "audit-1", "operation": "travel.book_hotel"}
        )
        deny = map_paybond_decision_to_openai_tool_guardrail(
            {"kind": "deny", "message": "budget exceeded"}
        )

    assert allow.behavior["type"] == "allow"
    assert deny.behavior["type"] == "reject_content"
    assert deny.behavior["message"] == "budget exceeded"


@pytest.mark.asyncio
async def test_create_paybond_openai_agents_config_wraps_side_effecting_tools() -> None:
    host = _make_host()
    run = await PaybondAgentRun.bind(
        host,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _make_registry(),
        },
    )

    async def book_hotel(_ctx: Any, input_json: str) -> str:
        return (
            '{"reservation": {"status": "confirmed", "price_cents": 18700}}'
        )

    async def search_web(_ctx: Any, _input_json: str) -> str:
        return "ok"

    tools = [
        MockFunctionTool(
            name="travel.book_hotel",
            description="Book hotel",
            params_json_schema={"type": "object", "properties": {}},
            on_invoke_tool=book_hotel,
        ),
        MockFunctionTool(
            name="search.web",
            description="Search web",
            params_json_schema={"type": "object", "properties": {}},
            on_invoke_tool=search_web,
        ),
    ]

    agents = _mock_agents_module()
    with patch("paybond_kit.openai_agents.config._require_openai_agents", return_value=agents):
        with patch("paybond_kit.openai_agents.config.is_openai_function_tool", return_value=True):
            config = create_paybond_openai_agents_config(run, tools)

    assert len(config.tools) == 2
    assert config.run_config is not None
    assert config.tools[0].tool_input_guardrails
    assert config.tools[1] is tools[1]

    ctx = MockToolContext(
        tool_name="travel.book_hotel",
        tool_call_id="call-1",
        tool_arguments='{"estimatedPriceCents": 18700}',
    )
    output = await config.tools[0].on_invoke_tool(ctx, ctx.tool_arguments)
    assert "confirmed" in output
    host.spend_guard.return_value.assert_spend_authorized.assert_awaited_once()
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()


@pytest.mark.skipif(
    not _OPENAI_AGENTS_AVAILABLE,
    reason="requires the optional 'openai-agents' extra (paybond-kit[openai-agents])",
)
@pytest.mark.asyncio
async def test_create_openai_agents_adapter_exposes_guardrails() -> None:
    host = _make_host()
    run = await PaybondAgentRun.bind(
        host,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _make_registry(),
        },
    )

    agents = _mock_agents_module()
    with patch("paybond_kit.openai_agents.config._require_openai_agents", return_value=agents):
        adapter = create_openai_agents_adapter(run)

    assert adapter.name == "openai-agents"
    guardrail = adapter.input_guardrail_for("travel.book_hotel")
    assert guardrail.name == "paybond_spend_travel.book_hotel"

    data = MockToolInputGuardrailData(
        context=MockToolContext(
            tool_name="travel.book_hotel",
            tool_call_id="call-1",
            tool_arguments='{"estimatedPriceCents": 18700}',
        )
    )
    result = await guardrail.run(data)
    assert result.behavior["type"] == "allow"
