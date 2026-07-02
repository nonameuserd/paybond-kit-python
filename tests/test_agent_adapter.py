"""Tests for framework adapter contract and generic tool executor."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from paybond_kit.agent import (
    PaybondAgentRun,
    create_generic_tool_executor,
    create_paybond_tool_registry,
    paybond_generic_tool_executor_adapter,
)


def _make_registry() -> Any:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: args["estimated_price_cents"],
                    "evidence_preset": "cost_and_completion",
                    "evidence_mapper": lambda result, _ctx: {
                        "status": "completed"
                        if result["reservation"]["status"] == "confirmed"
                        else result["reservation"]["status"],
                        "cost_cents": result["reservation"]["price_cents"],
                    },
                },
            },
            "default_deny": True,
        }
    )


def _make_guard() -> MagicMock:
    guard = MagicMock()
    guard.assert_spend_authorized = AsyncMock(
        return_value=MagicMock(allow=True, audit_id="audit-1", decision_id="decision-1")
    )
    guard.complete_spend_authorization = AsyncMock()
    return guard


def _make_host(guard: MagicMock) -> MagicMock:
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
async def test_generic_adapter_exposes_stable_name() -> None:
    adapter = create_generic_tool_executor()
    assert adapter.name == "generic"
    assert paybond_generic_tool_executor_adapter is adapter


@pytest.mark.asyncio
async def test_generic_adapter_wraps_execute_through_interceptor() -> None:
    guard = _make_guard()
    host = _make_host(guard)
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

    adapter = create_generic_tool_executor()
    wrapped_tools = adapter.wrap_tools(
        run,
        [
            {
                "name": "travel.book_hotel",
                "description": "Book a hotel room",
                "execute": lambda args: {
                    "reservation": {
                        "status": "confirmed",
                        "price_cents": args["estimated_price_cents"],
                    }
                },
            }
        ],
    )

    assert len(wrapped_tools) == 1
    wrapped = wrapped_tools[0]
    assert wrapped["name"] == "travel.book_hotel"
    assert wrapped["description"] == "Book a hotel room"

    result = await wrapped["execute"](
        {
            "tool_name": "travel.book_hotel",
            "tool_call_id": "call-1",
            "arguments": {"city": "Lisbon", "estimated_price_cents": 18_700},
        }
    )

    assert result["tool_result"] == {
        "reservation": {"status": "confirmed", "price_cents": 18_700},
    }
    assert result["evidence"].submitted is True
    guard.assert_spend_authorized.assert_awaited_once()
    guard.complete_spend_authorization.assert_awaited_with("decision-1", "consumed")
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()


@pytest.mark.asyncio
async def test_generic_adapter_passes_read_only_tools_through() -> None:
    guard = _make_guard()
    host = _make_host(guard)
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

    wrapped = create_generic_tool_executor().wrap_tools(
        run,
        [{"name": "lookup.weather", "execute": lambda _args: {"temp_c": 21}}],
    )[0]

    result = await wrapped["execute"](
        {
            "tool_name": "lookup.weather",
            "tool_call_id": "call-readonly",
            "arguments": {},
        }
    )

    assert result == {"tool_result": {"temp_c": 21}}
    guard.assert_spend_authorized.assert_not_called()


def test_generic_adapter_rejects_invalid_tool_definitions() -> None:
    adapter = create_generic_tool_executor()
    with pytest.raises(TypeError, match="list"):
        adapter.wrap_tools(MagicMock(), "not-a-list")
    with pytest.raises(TypeError, match="execute"):
        adapter.wrap_tools(MagicMock(), [{"name": "x"}])
