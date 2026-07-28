"""Tests for Pydantic AI runner helper."""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry
from paybond_kit.pydantic_ai.config import create_paybond_pydantic_ai_config
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


class _FakeModelRetry(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class _FakeTool:
    def __init__(self, function: Any, *, name: str | None = None, description: str = "", takes_ctx: bool = False, **kwargs: Any) -> None:
        self.function = function
        self.name = name or getattr(function, "__name__", "tool")
        self.description = description
        self.takes_ctx = takes_ctx
        self.max_retries = kwargs.get("max_retries")
        self.prepare = kwargs.get("prepare")
        self.args_validator = kwargs.get("args_validator")
        self.docstring_format = kwargs.get("docstring_format", "auto")
        self.require_parameter_descriptions = kwargs.get("require_parameter_descriptions", False)
        self.strict = kwargs.get("strict")
        self.sequential = kwargs.get("sequential", False)
        self.requires_approval = kwargs.get("requires_approval", False)
        self.metadata = kwargs.get("metadata")
        self.timeout = kwargs.get("timeout")
        self.defer_loading = kwargs.get("defer_loading", False)
        self.include_return_schema = kwargs.get("include_return_schema")


@pytest.mark.asyncio
async def test_create_paybond_pydantic_ai_config_wraps_side_effecting_tools() -> None:
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

    tools = [
        _FakeTool(submit_po, name="procurement.submit_po", description="Submit PO"),
        _FakeTool(search_catalog, name="procurement.search_catalog", description="Search"),
    ]

    fake_module = MagicMock()
    fake_module.Tool = _FakeTool
    fake_module.ModelRetry = _FakeModelRetry

    with patch("paybond_kit.pydantic_ai.config._require_pydantic_ai", return_value=fake_module):
        with patch("paybond_kit.pydantic_ai.config.is_pydantic_ai_tool", side_effect=lambda v: isinstance(v, _FakeTool)):
            config = create_paybond_pydantic_ai_config(run, tools)

    assert len(config.tools) == 2
    assert callable(config.wrap_tool)

    result = config.tools[0].function(vendor_id="vendor-a", amount_cents=12_000)
    assert result["cost_cents"] == 12_000
    host.spend_guard.return_value.assert_spend_authorized.assert_awaited_once()
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()

    catalog_result = config.tools[1].function(query="widgets")
    assert catalog_result == []
    assert host.spend_guard.return_value.assert_spend_authorized.await_count == 1


@pytest.mark.asyncio
async def test_create_paybond_pydantic_ai_config_raises_model_retry_on_approval_hold() -> None:
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

    tools = [_FakeTool(submit_po, name="procurement.submit_po", description="Submit PO")]

    fake_module = MagicMock()
    fake_module.Tool = _FakeTool
    fake_module.ModelRetry = _FakeModelRetry

    with patch("paybond_kit.pydantic_ai.config._require_pydantic_ai", return_value=fake_module):
        with patch(
            "paybond_kit.pydantic_ai.config.is_pydantic_ai_tool",
            side_effect=lambda v: isinstance(v, _FakeTool),
        ):
            config = create_paybond_pydantic_ai_config(run, tools)

            with pytest.raises(
                _FakeModelRetry, match="Paybond capability approval required"
            ) as exc_info:
                config.tools[0].function(vendor_id="vendor-a", amount_cents=12_000)

    assert "decision-hold-1" in str(exc_info.value)
    host.guardrails.submit_sandbox_evidence.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_paybond_pydantic_ai_config_raises_model_retry_on_deny() -> None:
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

    tools = [_FakeTool(submit_po, name="procurement.submit_po", description="Submit PO")]

    fake_module = MagicMock()
    fake_module.Tool = _FakeTool
    fake_module.ModelRetry = _FakeModelRetry

    with patch("paybond_kit.pydantic_ai.config._require_pydantic_ai", return_value=fake_module):
        with patch(
            "paybond_kit.pydantic_ai.config.is_pydantic_ai_tool",
            side_effect=lambda v: isinstance(v, _FakeTool),
        ):
            config = create_paybond_pydantic_ai_config(run, tools)

            with pytest.raises(_FakeModelRetry, match="Paybond capability denied"):
                config.tools[0].function(vendor_id="vendor-a", amount_cents=12_000)

    host.guardrails.submit_sandbox_evidence.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_paybond_pydantic_ai_config_preserves_real_tool_schema() -> None:
    """Wrapping must not collapse Tool JSON schema (Agent uses function_schema.call)."""
    pytest.importorskip("pydantic_ai")
    Tool = importlib.import_module("pydantic_ai").Tool

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
        """Submit a purchase order."""
        return {"status": "completed", "cost_cents": amount_cents, "vendor_id": vendor_id}

    original = Tool(submit_po, name="procurement.submit_po")
    original_schema = original.tool_def.parameters_json_schema

    config = create_paybond_pydantic_ai_config(run, [original])
    guarded = config.tools[0]

    assert guarded.tool_def.parameters_json_schema == original_schema
    assert guarded.function_schema.function is guarded.function

    result = await guarded.function_schema.call(
        {"vendor_id": "vendor-a", "amount_cents": 12_000},
        None,
    )
    assert result["cost_cents"] == 12_000
    host.spend_guard.return_value.assert_spend_authorized.assert_awaited_once()
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_paybond_pydantic_ai_config_rejects_invalid_tools() -> None:
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

    fake_module = MagicMock()
    fake_module.Tool = _FakeTool
    fake_module.ModelRetry = _FakeModelRetry

    with patch("paybond_kit.pydantic_ai.config._require_pydantic_ai", return_value=fake_module):
        with pytest.raises(TypeError, match="sequence"):
            create_paybond_pydantic_ai_config(run, "not-a-sequence")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Tool instance or a plain callable"):
            create_paybond_pydantic_ai_config(run, [object()])
