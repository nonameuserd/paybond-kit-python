from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.langgraph_hooks import (
    create_paybond_langgraph_hooks,
    paybond_tool_node,
)
from paybond_kit.mcp_tool_surface import create_paybond_mcp_tool_surface


def _registry() -> object:
    return create_paybond_tool_registry(
        {
            "default_deny": True,
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda _args: 100,
                    "evidence_preset": "cost_and_completion",
                },
            },
        }
    )


def _make_host() -> SimpleNamespace:
    guard = SimpleNamespace(
        assert_spend_authorized=AsyncMock(
            return_value=SimpleNamespace(allow=True, audit_id="audit-1", decision_id="decision-1"),
        ),
        complete_spend_authorization=AsyncMock(),
    )
    return SimpleNamespace(
        harbor=SimpleNamespace(tenant_id="tenant-a"),
        guardrails=SimpleNamespace(
            bootstrap_sandbox=AsyncMock(
                return_value=SimpleNamespace(
                    tenant_id="tenant-a",
                    intent_id="intent-sandbox",
                    capability_token="cap-sandbox",
                    operation="travel.book_hotel",
                    requested_spend_cents=20_000,
                    sandbox_lifecycle_status="funded",
                )
            ),
            submit_sandbox_evidence=AsyncMock(),
        ),
        spend_guard=lambda *_args, **_kwargs: guard,
    )


@pytest.mark.asyncio
async def test_create_paybond_langgraph_hooks_wires_run() -> None:
    host = _make_host()
    run = await PaybondAgentRun.bind(
        host,  # type: ignore[arg-type]
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
        },
    )

    hooks = create_paybond_langgraph_hooks(run)

    assert callable(hooks.awrap_tool_call)
    assert callable(hooks.create_tool_node)


@pytest.mark.asyncio
async def test_paybond_tool_node_uses_awrap_tool_call() -> None:
    try:
        from langgraph.prebuilt import ToolNode
    except ImportError:
        pytest.skip("langgraph not installed")

    host = _make_host()
    run = await PaybondAgentRun.bind(
        host,  # type: ignore[arg-type]
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
        },
    )

    node = paybond_tool_node([], run)
    assert isinstance(node, ToolNode)


@pytest.mark.asyncio
async def test_create_paybond_mcp_tool_surface_returns_install_payload() -> None:
    host = _make_host()
    run = await PaybondAgentRun.bind(
        host,  # type: ignore[arg-type]
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
        },
    )

    surface = create_paybond_mcp_tool_surface(run, env_file=".env.local")

    assert surface.server_config.env["PAYBOND_ENV_FILE"] == ".env.local"
    payload = json.loads(surface.install_payload("json"))
    assert "mcpServers" in payload
    assert "paybond" in payload["mcpServers"]
