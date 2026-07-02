from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from paybond_kit.agent import (
    PaybondAgentRun,
    PaybondAgentRunBindError,
    PaybondToolRegistryValidationError,
    create_paybond_tool_registry,
)
from paybond_kit.agent.types import PaybondRunProductionEvidenceCredentials
from paybond_kit.guardrails import SandboxGuardrailBootstrapResult, SandboxGuardrailEvidenceResult
from paybond_kit.harbor import VerifyCapabilityResult
from paybond_kit.spend_guard import PaybondSpendGuard


def _registry():
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: args["estimated_price_cents"],
                    "evidence_preset": "cost_and_completion",
                }
            },
            "default_deny": True,
        }
    )


@dataclass
class _FakeHarbor:
    tenant_id: str = "tenant-a"
    complete_spend_decision: AsyncMock = AsyncMock()
    submit_evidence: AsyncMock = AsyncMock(
        return_value={
            "intent_id": "550e8400-e29b-41d4-a716-446655440000",
            "state": "completed",
            "predicate_passed": True,
        }
    )

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
        return {
            "tenant_id": self.tenant_id,
            "allowed_tools": ["travel.book_hotel"],
        }


@dataclass
class _FakeGuardrails:
    async def bootstrap_sandbox(self, **kwargs: Any) -> SandboxGuardrailBootstrapResult:
        return SandboxGuardrailBootstrapResult(
            tenant_id="tenant-a",
            intent_id=uuid4(),
            capability_token="cap-sandbox",
            operation=str(kwargs["operation"]),
            requested_spend_cents=int(kwargs["requested_spend_cents"]),
            sandbox_lifecycle_status="funded",
        )

    submit_sandbox_evidence = AsyncMock(
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
class _FakePaybond:
    harbor: _FakeHarbor
    guardrails: _FakeGuardrails

    def spend_guard(self, intent_id: UUID, capability_token: str) -> PaybondSpendGuard:
        return PaybondSpendGuard(harbor=self.harbor, intent_id=intent_id, capability_token=capability_token)


@pytest.mark.asyncio
async def test_agent_run_bind_sandbox_bootstrap() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    run = await PaybondAgentRun.bind(
        paybond,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
            "run_id": "run-test-1",
        },
    )

    assert run.run_id == "run-test-1"
    assert run.tenant_id == "tenant-a"
    assert run.capability_token == "cap-sandbox"
    assert run.allowed_tools == ("travel.book_hotel",)
    assert run.binding.sandbox is not None
    assert run.binding.sandbox.operation == "travel.book_hotel"
    assert run.binding.sandbox.requested_spend_cents == 20_000
    assert run.binding.sandbox.sandbox_lifecycle_status == "funded"


def _production_evidence() -> PaybondRunProductionEvidenceCredentials:
    return {
        "payee_did": "did:web:vendor.example",
        "payee_signing_seed": b"\x01" * 32,
        "agent_recognition_key_id": "kid-1",
        "agent_recognition_signing_seed": b"\x02" * 32,
    }


@pytest.mark.asyncio
async def test_agent_run_bind_attach_with_explicit_allowed_tools() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    intent_id = uuid4()
    run = await PaybondAgentRun.bind(
        paybond,
        {
            "attach": {
                "intent_id": str(intent_id),
                "capability_token": "cap-prod",
                "allowed_tools": ["travel.book_hotel"],
                "production_evidence": _production_evidence(),
            },
            "registry": _registry(),
        },
    )

    assert run.intent_id == intent_id
    assert run.capability_token == "cap-prod"
    assert run.allowed_tools == ("travel.book_hotel",)
    assert run.binding.sandbox is None


@pytest.mark.asyncio
async def test_agent_run_bind_attach_loads_allowed_tools_from_harbor() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    intent_id = uuid4()
    run = await PaybondAgentRun.bind(
        paybond,
        {
            "attach": {
                "intent_id": str(intent_id),
                "capability_token": "cap-prod",
                "production_evidence": _production_evidence(),
            },
            "registry": _registry(),
        },
    )

    assert run.allowed_tools == ("travel.book_hotel",)


@pytest.mark.asyncio
async def test_agent_run_bind_rejects_bootstrap_and_attach() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    with pytest.raises(PaybondAgentRunBindError, match="exactly one"):
        await PaybondAgentRun.bind(
            paybond,
            {
                "bootstrap": {
                    "kind": "sandbox",
                    "operation": "travel.book_hotel",
                    "requested_spend_cents": 100,
                },
                "attach": {
                    "intent_id": str(uuid4()),
                    "capability_token": "cap-1",
                    "allowed_tools": ["travel.book_hotel"],
                },
                "registry": _registry(),
            },
        )


@pytest.mark.asyncio
async def test_agent_run_bind_validates_registry_for_allowed_tools() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    with pytest.raises(PaybondToolRegistryValidationError, match="defaultDeny"):
        await PaybondAgentRun.bind(
            paybond,
            {
                "attach": {
                    "intent_id": str(uuid4()),
                    "capability_token": "cap-1",
                    "allowed_tools": ["travel.book_hotel", "travel.book_flight"],
                    "production_evidence": _production_evidence(),
                },
                "registry": _registry(),
            },
        )


@pytest.mark.asyncio
async def test_agent_run_bind_requires_production_evidence_for_attach() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    with pytest.raises(PaybondAgentRunBindError, match="production_evidence"):
        await PaybondAgentRun.bind(
            paybond,
            {
                "attach": {
                    "intent_id": str(uuid4()),
                    "capability_token": "cap-prod",
                    "allowed_tools": ["travel.book_hotel"],
                },
                "registry": _registry(),
            },
        )
