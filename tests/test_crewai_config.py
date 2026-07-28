"""Tests for CrewAI runner helper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry
from paybond_kit.crewai.config import create_paybond_crewai_config
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendDeniedError


def _make_registry() -> Any:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "procurement.submit_po": {
                    "spend_cents": lambda args: int(args.get("amount_cents", 0)),
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
            operation="procurement.submit_po",
            requested_spend_cents=12_000,
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
class MockCrewTool:
    name: str
    description: str
    func: Any


@pytest.mark.asyncio
async def test_create_paybond_crewai_config_wraps_side_effecting_tools() -> None:
    host = _make_host()
    run = await PaybondAgentRun.bind(
        host,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "procurement.submit_po",
                "requested_spend_cents": 12_000,
            },
            "registry": _make_registry(),
        },
    )

    def submit_po(vendor_id: str, amount_cents: int) -> str:
        return f'{{"status": "completed", "cost_cents": {amount_cents}, "vendor_id": "{vendor_id}"}}'

    def search_catalog(query: str) -> str:
        return "[]"

    tools = [
        MockCrewTool(name="procurement.submit_po", description="Submit PO", func=submit_po),
        MockCrewTool(name="procurement.search_catalog", description="Search catalog", func=search_catalog),
    ]

    with patch("paybond_kit.crewai.config._require_crewai_tools", return_value=MagicMock()):
        with patch("paybond_kit.crewai.config.is_crewai_base_tool", return_value=False):
            config = create_paybond_crewai_config(run, tools)

    assert len(config.tools) == 2
    assert callable(config.wrap_tool)

    result = config.tools[0].func(vendor_id="vendor-a", amount_cents=12_000)
    assert '"cost_cents": 12000' in result
    host.spend_guard.return_value.assert_spend_authorized.assert_awaited_once()
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()

    catalog_result = config.tools[1].func(query="widgets")
    assert catalog_result == "[]"
    assert host.spend_guard.return_value.assert_spend_authorized.await_count == 1


@pytest.mark.asyncio
async def test_create_paybond_crewai_config_propagates_approval_hold() -> None:
    guard = MagicMock()
    guard.assert_spend_authorized = AsyncMock(
        side_effect=PaybondSpendApprovalRequiredError(
            MagicMock(
                allow=False,
                code="approval_required",
                message="approval required",
                decision_id="decision-hold-1",
            )
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
            operation="procurement.submit_po",
            requested_spend_cents=12_000,
            sandbox_lifecycle_status="funded",
        )
    )
    host.guardrails.submit_sandbox_evidence = AsyncMock()
    host.spend_guard = MagicMock(return_value=guard)

    run = await PaybondAgentRun.bind(
        host,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "procurement.submit_po",
                "requested_spend_cents": 12_000,
            },
            "registry": _make_registry(),
        },
    )

    def submit_po(vendor_id: str, amount_cents: int) -> str:
        return f'{{"status": "completed", "cost_cents": {amount_cents}}}'

    tools = [MockCrewTool(name="procurement.submit_po", description="Submit PO", func=submit_po)]

    with patch("paybond_kit.crewai.config._require_crewai_tools", return_value=MagicMock()):
        with patch("paybond_kit.crewai.config.is_crewai_base_tool", return_value=False):
            config = create_paybond_crewai_config(run, tools)

    result = config.tools[0].func(vendor_id="vendor-a", amount_cents=12_000)
    assert "Paybond capability approval required" in result
    assert "decision-hold-1" in result


@pytest.mark.asyncio
async def test_create_paybond_crewai_config_rejects_invalid_tools() -> None:
    host = _make_host()
    run = await PaybondAgentRun.bind(
        host,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "procurement.submit_po",
                "requested_spend_cents": 12_000,
            },
            "registry": _make_registry(),
        },
    )

    with patch("paybond_kit.crewai.config._require_crewai_tools", return_value=MagicMock()):
        with pytest.raises(TypeError, match="sequence"):
            create_paybond_crewai_config(run, "not-a-sequence")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="non-empty name"):
            create_paybond_crewai_config(run, [object()])
