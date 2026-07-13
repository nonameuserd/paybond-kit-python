"""Tests for Google ADK runner helper."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry
from paybond_kit.google_adk.config import create_paybond_google_adk_config
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


class _FakeFunctionTool:
    def __init__(self, func: Any, *, require_confirmation: bool = False) -> None:
        name = getattr(func, "__name__", "tool")
        doc = getattr(func, "__doc__", "") or f"Tool {name}"
        self.name = name
        self.description = doc
        self.func = func
        self._require_confirmation = require_confirmation


@pytest.mark.asyncio
async def test_create_paybond_google_adk_config_wraps_side_effecting_tools() -> None:
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

    def submit_po(vendor_id: str, amount_cents: int) -> dict[str, Any]:
        return {"status": "completed", "cost_cents": amount_cents, "vendor_id": vendor_id}

    def search_catalog(query: str) -> list[Any]:
        return []

    submit_po.__name__ = "procurement.submit_po"
    search_catalog.__name__ = "procurement.search_catalog"

    tools = [
        _FakeFunctionTool(submit_po),
        _FakeFunctionTool(search_catalog),
    ]

    with patch(
        "paybond_kit.google_adk.config._require_function_tool",
        return_value=_FakeFunctionTool,
    ):
        with patch(
            "paybond_kit.google_adk.config.is_google_adk_function_tool",
            side_effect=lambda v: isinstance(v, _FakeFunctionTool),
        ):
            config = create_paybond_google_adk_config(run, tools)

    assert len(config.tools) == 2
    assert callable(config.wrap_tool)

    result = config.tools[0].func(vendor_id="vendor-a", amount_cents=12_000)
    assert result["cost_cents"] == 12_000
    host.spend_guard.return_value.assert_spend_authorized.assert_awaited_once()
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()

    catalog_result = config.tools[1].func(query="widgets")
    assert catalog_result == []
    assert host.spend_guard.return_value.assert_spend_authorized.await_count == 1


@pytest.mark.asyncio
async def test_create_paybond_google_adk_config_raises_on_approval_hold() -> None:
    host = _make_host()
    host.spend_guard.return_value.assert_spend_authorized = AsyncMock(
        side_effect=PaybondSpendApprovalRequiredError(
            MagicMock(
                allow=False,
                code="approval_required",
                message="approval required",
                decision_id="decision-hold-1",
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

    def submit_po(vendor_id: str, amount_cents: int) -> dict[str, Any]:
        return {"status": "completed", "cost_cents": amount_cents}

    submit_po.__name__ = "procurement.submit_po"
    tools = [_FakeFunctionTool(submit_po)]

    with patch(
        "paybond_kit.google_adk.config._require_function_tool",
        return_value=_FakeFunctionTool,
    ):
        with patch(
            "paybond_kit.google_adk.config.is_google_adk_function_tool",
            side_effect=lambda v: isinstance(v, _FakeFunctionTool),
        ):
            config = create_paybond_google_adk_config(run, tools)

            with pytest.raises(RuntimeError, match="Paybond capability approval required") as exc_info:
                config.tools[0].func(vendor_id="vendor-a", amount_cents=12_000)

    assert "decision-hold-1" in str(exc_info.value)
    host.guardrails.submit_sandbox_evidence.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_paybond_google_adk_config_uses_stored_approval_token() -> None:
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
    run.store_approval_token("adk-call-9", "operator-token-456")

    def submit_po(vendor_id: str, amount_cents: int) -> dict[str, Any]:
        return {"status": "completed", "cost_cents": amount_cents, "vendor_id": vendor_id}

    submit_po.__name__ = "procurement.submit_po"
    tools = [_FakeFunctionTool(submit_po)]

    class ToolContext:
        def __init__(self, function_call_id: str) -> None:
            self.function_call_id = function_call_id

    with patch(
        "paybond_kit.google_adk.config._require_function_tool",
        return_value=_FakeFunctionTool,
    ):
        with patch(
            "paybond_kit.google_adk.config.is_google_adk_function_tool",
            side_effect=lambda v: isinstance(v, _FakeFunctionTool),
        ):
            config = create_paybond_google_adk_config(run, tools)
            result = config.tools[0].func(
                vendor_id="vendor-a",
                amount_cents=12_000,
                tool_context=ToolContext("adk-call-9"),
            )

    assert result["cost_cents"] == 12_000
    host.spend_guard.return_value.assert_spend_authorized.assert_awaited_once()
    auth_kwargs = host.spend_guard.return_value.assert_spend_authorized.await_args.kwargs
    assert auth_kwargs["tool_call_id"] == "adk-call-9"
    assert auth_kwargs["approval_token"] == "operator-token-456"


@pytest.mark.asyncio
async def test_create_paybond_google_adk_config_raises_on_deny() -> None:
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

    def submit_po(vendor_id: str, amount_cents: int) -> dict[str, Any]:
        return {"status": "completed", "cost_cents": amount_cents}

    submit_po.__name__ = "procurement.submit_po"
    tools = [_FakeFunctionTool(submit_po)]

    with patch(
        "paybond_kit.google_adk.config._require_function_tool",
        return_value=_FakeFunctionTool,
    ):
        with patch(
            "paybond_kit.google_adk.config.is_google_adk_function_tool",
            side_effect=lambda v: isinstance(v, _FakeFunctionTool),
        ):
            config = create_paybond_google_adk_config(run, tools)

            with pytest.raises(RuntimeError, match="Paybond capability denied"):
                config.tools[0].func(vendor_id="vendor-a", amount_cents=12_000)

    host.guardrails.submit_sandbox_evidence.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_paybond_google_adk_config_rejects_invalid_tools() -> None:
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
        "paybond_kit.google_adk.config._require_function_tool",
        return_value=_FakeFunctionTool,
    ):
        with pytest.raises(TypeError, match="sequence"):
            create_paybond_google_adk_config(run, "not-a-sequence")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="FunctionTool instance or a plain callable"):
            create_paybond_google_adk_config(run, [object()])


class _FakeLongRunningFunctionTool(_FakeFunctionTool):
    def __init__(self, func: Any, *, require_confirmation: bool = False) -> None:
        super().__init__(func, require_confirmation=require_confirmation)
        self.is_long_running = True


class _FakeToolContext:
    def __init__(self, function_call_id: str) -> None:
        self.function_call_id = function_call_id


@pytest.mark.asyncio
async def test_create_paybond_google_adk_config_preserves_long_running_class() -> None:
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

    def submit_po(vendor_id: str, amount_cents: int) -> dict[str, Any]:
        return {"status": "completed", "cost_cents": amount_cents}

    submit_po.__name__ = "procurement.submit_po"
    tools = [_FakeLongRunningFunctionTool(submit_po)]

    with patch(
        "paybond_kit.google_adk.config._require_function_tool",
        return_value=_FakeFunctionTool,
    ):
        with patch(
            "paybond_kit.google_adk.config.is_google_adk_function_tool",
            side_effect=lambda v: isinstance(v, _FakeFunctionTool),
        ):
            config = create_paybond_google_adk_config(run, tools)

    assert isinstance(config.tools[0], _FakeLongRunningFunctionTool)
    assert config.tools[0].is_long_running is True


@pytest.mark.asyncio
async def test_create_paybond_google_adk_config_uses_function_call_id() -> None:
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

    def submit_po(vendor_id: str, amount_cents: int) -> dict[str, Any]:
        return {"status": "completed", "cost_cents": amount_cents}

    submit_po.__name__ = "procurement.submit_po"
    tools = [_FakeFunctionTool(submit_po)]

    with patch(
        "paybond_kit.google_adk.config._require_function_tool",
        return_value=_FakeFunctionTool,
    ):
        with patch(
            "paybond_kit.google_adk.config.is_google_adk_function_tool",
            side_effect=lambda v: isinstance(v, _FakeFunctionTool),
        ):
            config = create_paybond_google_adk_config(run, tools)
            # ADK injects tool_context into FunctionTool.func; original tools need not declare it.
            config.tools[0].func(
                vendor_id="vendor-a",
                amount_cents=12_000,
                tool_context=_FakeToolContext("adk-call-42"),
            )

    called = host.spend_guard.return_value.assert_spend_authorized.await_args
    assert called is not None
    assert called.kwargs["tool_call_id"] == "adk-call-42"
