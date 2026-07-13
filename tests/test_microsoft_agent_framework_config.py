"""Tests for Microsoft Agent Framework runner helper."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry
from paybond_kit.microsoft_agent_framework.config import (
    create_paybond_microsoft_agent_framework_config,
    process_paybond_function_invocation,
)
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


class _FakeFunctionMiddleware:
    """Stand-in for agent_framework.FunctionMiddleware."""


@pytest.mark.asyncio
async def test_create_paybond_microsoft_agent_framework_config_builds_middleware() -> None:
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

    def submit_po(amount_cents: int) -> dict[str, Any]:
        return {"status": "completed", "cost_cents": amount_cents}

    with patch(
        "paybond_kit.microsoft_agent_framework.config._require_function_middleware",
        return_value=_FakeFunctionMiddleware,
    ):
        config = create_paybond_microsoft_agent_framework_config(run, [submit_po])

    assert len(config.tools) == 1
    assert len(config.middleware) == 1
    assert callable(config.wrap_tool)
    assert config.wrap_tool(submit_po) is submit_po


@pytest.mark.asyncio
async def test_process_paybond_function_invocation_authorizes_and_executes() -> None:
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

    executed = False

    async def call_next() -> None:
        nonlocal executed
        executed = True
        context.result = {"status": "completed", "cost_cents": 12_000}

    context = SimpleNamespace(
        function=SimpleNamespace(name="procurement.submit_po"),
        arguments={"amount_cents": 12_000},
        metadata={"call_id": "call-1"},
        result=None,
    )

    await process_paybond_function_invocation(run, context, call_next)

    assert executed is True
    assert context.result == {"status": "completed", "cost_cents": 12_000}
    host.spend_guard.return_value.assert_spend_authorized.assert_awaited_once()
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()


@pytest.mark.asyncio
async def test_process_paybond_function_invocation_sets_result_on_deny_without_call_next() -> None:
    host = _make_host(allow=False)
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

    executed = False

    async def call_next() -> None:
        nonlocal executed
        executed = True

    context = SimpleNamespace(
        function=SimpleNamespace(name="procurement.submit_po"),
        arguments={"amount_cents": 12_000},
        metadata={"call_id": "call-deny"},
        result=None,
    )

    await process_paybond_function_invocation(run, context, call_next)

    assert executed is False
    assert isinstance(context.result, str)
    assert context.result.startswith("Paybond capability denied:")
    host.guardrails.submit_sandbox_evidence.assert_not_awaited()


@pytest.mark.asyncio
async def test_process_paybond_function_invocation_approval_hold_without_call_next() -> None:
    host = _make_host()
    host.spend_guard.return_value.assert_spend_authorized = AsyncMock(
        side_effect=PaybondSpendApprovalRequiredError(
            MagicMock(
                allow=False,
                code="approval_required",
                message="needs approval",
                decision_id="dec-hold",
            )
        )
    )
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

    executed = False

    async def call_next() -> None:
        nonlocal executed
        executed = True

    context = SimpleNamespace(
        function=SimpleNamespace(name="procurement.submit_po"),
        arguments=SimpleNamespace(model_dump=lambda: {"amount_cents": 12_000}),
        metadata={},
        result=None,
    )

    await process_paybond_function_invocation(run, context, call_next)

    assert executed is False
    assert isinstance(context.result, str)
    assert "approval required" in context.result
    assert "dec-hold" in context.result


@pytest.mark.asyncio
async def test_process_paybond_function_invocation_passthrough_non_side_effecting() -> None:
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

    executed = False

    async def call_next() -> None:
        nonlocal executed
        executed = True
        context.result = ["ok"]

    context = SimpleNamespace(
        function=SimpleNamespace(name="procurement.search_catalog"),
        arguments={"query": "widgets"},
        metadata={"call_id": "call-ro"},
        result=None,
    )

    await process_paybond_function_invocation(run, context, call_next)

    assert executed is True
    assert context.result == ["ok"]
    host.spend_guard.return_value.assert_spend_authorized.assert_not_awaited()


@pytest.mark.asyncio
async def test_process_paybond_function_invocation_falls_back_to_uuid_call_id() -> None:
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

    async def call_next() -> None:
        context.result = {"status": "completed", "cost_cents": 12_000}

    context = SimpleNamespace(
        function=SimpleNamespace(name="procurement.submit_po"),
        arguments={"amount_cents": 12_000},
        metadata={},
        result=None,
    )

    await process_paybond_function_invocation(run, context, call_next)

    assert context.result == {"status": "completed", "cost_cents": 12_000}
    auth_kwargs = host.spend_guard.return_value.assert_spend_authorized.await_args.kwargs
    tool_call_id = auth_kwargs["tool_call_id"]
    assert isinstance(tool_call_id, str)
    assert len(tool_call_id) >= 32


@pytest.mark.asyncio
async def test_create_paybond_microsoft_agent_framework_config_rejects_non_sequence_tools() -> None:
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
    with patch(
        "paybond_kit.microsoft_agent_framework.config._require_function_middleware",
        return_value=_FakeFunctionMiddleware,
    ):
        with pytest.raises(TypeError, match="sequence of tool"):
            create_paybond_microsoft_agent_framework_config(run, "not-a-sequence")  # type: ignore[arg-type]
