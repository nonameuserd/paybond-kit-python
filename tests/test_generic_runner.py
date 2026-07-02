"""Tests for agent-agnostic generic runner helpers."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from paybond_kit.agent import (
    PaybondAgentRun,
    create_paybond_generic_agent_config,
    create_paybond_generic_input_guard,
    create_paybond_tool_registry,
)


def _make_registry() -> Any:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: args["estimated_price_cents"],
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


@pytest.mark.asyncio
async def test_create_paybond_generic_agent_config_wraps_tools_and_exposes_input_guard() -> None:
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

    async def book_hotel(args: dict[str, Any]) -> dict[str, Any]:
        return {"status": "completed", "cost_cents": args["estimated_price_cents"]}

    config = create_paybond_generic_agent_config(
        run,
        {"travel.book_hotel": book_hotel},
    )

    assert len(config.tools) == 1
    assert config.tools[0]["name"] == "travel.book_hotel"
    assert config.input_guard.name == "tool-input-guard"
    assert create_paybond_generic_input_guard(run).name == "tool-input-guard"

    result = await config.tools[0]["execute"](
        {
            "tool_name": "travel.book_hotel",
            "tool_call_id": "call-1",
            "arguments": {"estimated_price_cents": 18_700},
        }
    )

    assert result["tool_result"] == {"status": "completed", "cost_cents": 18_700}
    assert result["evidence"].submitted is True
