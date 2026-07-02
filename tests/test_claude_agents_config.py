"""Tests for Claude Agent SDK runner helper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry
from paybond_kit.claude_agents import create_paybond_claude_agents_config


def _make_registry() -> Any:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: args["estimatedPriceCents"],
                    "evidence_preset": "cost_and_completion",
                    "evidence_mapper": lambda result, _ctx: {
                        "status": result["status"],
                        "cost_cents": result["cost_cents"],
                    },
                },
            },
            "default_deny": True,
        }
    )


def _make_host() -> MagicMock:
    guard = MagicMock()
    guard.assert_spend_authorized = AsyncMock(
        return_value=MagicMock(allow=True, audit_id="audit-1", decision_id="decision-1")
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


@dataclass
class MockSdkTool:
    name: str
    description: str
    handler: Any


@pytest.mark.asyncio
async def test_create_paybond_claude_agents_config_wraps_side_effecting_tools() -> None:
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

    book_hotel_handler = AsyncMock(
        return_value={
            "content": [{"type": "text", "text": '{"status": "completed", "cost_cents": 18700}'}],
            "structuredContent": {"status": "completed", "cost_cents": 18_700},
        }
    )
    search_web_handler = AsyncMock(return_value={"content": [{"type": "text", "text": "[]"}]})

    tools = [
        MockSdkTool(name="travel.book_hotel", description="Book a hotel", handler=book_hotel_handler),
        MockSdkTool(name="search.web", description="Search the web", handler=search_web_handler),
    ]
    fake_mcp_server = {"name": "paybond", "tools": tools}

    with patch(
        "paybond_kit.claude_agents.config._require_claude_agent_sdk",
        return_value=MagicMock(
            create_sdk_mcp_server=lambda **kwargs: {**fake_mcp_server, **kwargs}
        ),
    ):
        config = create_paybond_claude_agents_config(run, tools, server_name="paybond")

    assert config.allowed_tools == [
        "mcp__paybond__travel.book_hotel",
        "mcp__paybond__search.web",
    ]
    assert config.agent_tools is tools

    result = await tools[0].handler({"estimatedPriceCents": 18_700}, {"toolUseID": "call-claude-1"})
    assert result["structuredContent"] == {"status": "completed", "cost_cents": 18_700}
    book_hotel_handler.assert_awaited_once()
    host.spend_guard.return_value.assert_spend_authorized.assert_awaited_once()
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()

    await tools[1].handler({"query": "paris hotels"}, {"toolUseID": "call-claude-2"})
    search_web_handler.assert_awaited_once()
    assert host.spend_guard.return_value.assert_spend_authorized.await_count == 1


@pytest.mark.asyncio
async def test_create_paybond_claude_agents_config_rejects_invalid_tools() -> None:
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

    with patch(
        "paybond_kit.claude_agents.config._require_claude_agent_sdk",
        return_value=MagicMock(create_sdk_mcp_server=lambda **kwargs: kwargs),
    ):
        with pytest.raises(TypeError, match="handler callable"):
            create_paybond_claude_agents_config(
                run,
                [MockSdkTool(name="travel.book_hotel", description="", handler=None)],  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError, match="SDK tool"):
            create_paybond_claude_agents_config(run, "not-a-list")  # type: ignore[arg-type]
