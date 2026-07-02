"""Tests for agent-agnostic tool input guard adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from paybond_kit.agent import (
    PaybondAgentRun,
    create_paybond_tool_registry,
    create_tool_input_guard_adapter,
)
from paybond_kit.guardrails import SandboxGuardrailBootstrapResult, SandboxGuardrailEvidenceResult
from paybond_kit.harbor import VerifyCapabilityResult
from paybond_kit.spend_guard import PaybondSpendApprovalRequiredError, PaybondSpendGuard


def _registry() -> Any:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: args["estimated_price_cents"],
                    "evidence_preset": "cost_and_completion",
                },
            },
            "default_deny": True,
        }
    )


@dataclass
class _FakeHarbor:
    tenant_id: str = "tenant-a"
    complete_spend_decision: AsyncMock = field(default_factory=AsyncMock)
    submit_evidence: AsyncMock = field(default_factory=AsyncMock)

    async def verify_capability(self, **kwargs: Any) -> VerifyCapabilityResult:
        intent_id = kwargs.get("intent_id")
        if not isinstance(intent_id, UUID):
            intent_id = uuid4()
        return VerifyCapabilityResult(
            allow=True,
            audit_id=uuid4(),
            tenant=self.tenant_id,
            intent_id=intent_id,
            code=None,
            message=None,
            decision_id=uuid4(),
        )

    async def get_intent(self, intent_id: UUID) -> dict[str, str | list[str]]:
        return {"tenant_id": self.tenant_id, "allowed_tools": ["travel.book_hotel"]}


@dataclass
class _FakeGuardrails:
    intent_id: UUID | None = None

    async def bootstrap_sandbox(self, **kwargs: Any) -> SandboxGuardrailBootstrapResult:
        intent_id = uuid4()
        self.intent_id = intent_id
        return SandboxGuardrailBootstrapResult(
            tenant_id="tenant-a",
            intent_id=intent_id,
            capability_token="cap-sandbox",
            operation="travel.book_hotel",
            requested_spend_cents=20_000,
            sandbox_lifecycle_status="funded",
        )

    submit_sandbox_evidence: AsyncMock = AsyncMock(
        return_value=SandboxGuardrailEvidenceResult(
            tenant_id="tenant-a",
            intent_id=uuid4(),
            operation="travel.book_hotel",
            requested_spend_cents=20_000,
            sandbox_lifecycle_status="completed",
            predicate_passed=True,
        )
    )


@dataclass
class _Host:
    harbor: _FakeHarbor = field(default_factory=_FakeHarbor)
    guardrails: _FakeGuardrails = field(default_factory=_FakeGuardrails)

    def spend_guard(self, intent_id: UUID, capability_token: str) -> PaybondSpendGuard:
        return PaybondSpendGuard(
            harbor=self.harbor,
            intent_id=intent_id,
            capability_token=capability_token,
        )


@pytest.mark.asyncio
async def test_tool_input_guard_evaluate_allows_read_only_tools() -> None:
    run = await PaybondAgentRun.bind(
        _Host(),
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
        },
    )

    adapter = create_tool_input_guard_adapter(run)
    decision = await adapter.evaluate(
        {
            "tool_name": "lookup.weather",
            "tool_call_id": "call-readonly",
            "arguments": {"city": "Lisbon"},
        }
    )
    assert decision.get("kind") == "allow"
    assert decision.get("passthrough") is True


@pytest.mark.asyncio
async def test_tool_input_guard_evaluate_maps_approval_hold() -> None:
    harbor = _FakeHarbor()

    async def _hold(**kwargs: Any) -> VerifyCapabilityResult:
        raise PaybondSpendApprovalRequiredError(
            VerifyCapabilityResult(
                allow=False,
                audit_id=uuid4(),
                tenant=harbor.tenant_id,
                intent_id=kwargs["intent_id"],
                code="approval_required",
                message="needs approval",
            )
        )

    harbor.verify_capability = _hold  # type: ignore[method-assign]

    run = await PaybondAgentRun.bind(
        _Host(harbor=harbor),
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
        },
    )

    decision = await create_tool_input_guard_adapter(run).evaluate(
        {
            "tool_name": "travel.book_hotel",
            "tool_call_id": "call-hold",
            "arguments": {"estimated_price_cents": 100},
        }
    )
    assert decision.get("kind") == "approval_required"


@pytest.mark.asyncio
async def test_authorize_cache_avoids_double_verify_on_wrap_execute() -> None:
    harbor = _FakeHarbor()
    verify = AsyncMock(side_effect=harbor.verify_capability)
    harbor.verify_capability = verify  # type: ignore[method-assign]

    run = await PaybondAgentRun.bind(
        _Host(harbor=harbor),
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
        },
    )

    adapter = create_tool_input_guard_adapter(run)
    await adapter.evaluate(
        {
            "tool_name": "travel.book_hotel",
            "tool_call_id": "call-1",
            "arguments": {"estimated_price_cents": 18_700},
        }
    )

    [wrapped] = adapter.wrap_executors(
        [
            {
                "name": "travel.book_hotel",
                "execute": lambda _args: {"reservation": {"status": "confirmed", "price_cents": 18_700}},
            }
        ]
    )

    await wrapped["execute"](
        {
            "tool_name": "travel.book_hotel",
            "tool_call_id": "call-1",
            "arguments": {"estimated_price_cents": 18_700},
        }
    )

    assert verify.await_count == 1
