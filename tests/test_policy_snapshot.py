from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.guardrails import SandboxGuardrailBootstrapResult, SandboxGuardrailEvidenceResult
from paybond_kit.harbor import VerifyCapabilityResult
from paybond_kit.policy.schema import parse_paybond_policy_document_v1
from paybond_kit.policy.snapshot import create_policy_snapshot
from paybond_kit.spend_guard import PaybondSpendGuard


@dataclass
class _FakeHarbor:
    tenant_id: str = "tenant-a"
    complete_spend_decision: AsyncMock = field(default_factory=AsyncMock)
    submit_evidence: AsyncMock = field(default_factory=AsyncMock)

    async def verify_capability(self, **kwargs: Any) -> VerifyCapabilityResult:
        intent_id = kwargs.get("intent_id")
        if not isinstance(intent_id, UUID):
            intent_id = UUID("40000000-0000-4000-8000-000000000001")
        return VerifyCapabilityResult(
            allow=True,
            audit_id=UUID("40000000-0000-4000-8000-000000000002"),
            tenant=self.tenant_id,
            intent_id=intent_id,
            code=None,
            message=None,
            decision_id=UUID("40000000-0000-4000-8000-000000000003"),
        )

    async def get_intent(self, intent_id: UUID) -> dict[str, Any]:
        _ = intent_id
        return {"allowed_tools": ["travel.book_hotel"]}


@dataclass
class _FakeGuardrails:
    async def bootstrap_sandbox(self, **kwargs: Any) -> SandboxGuardrailBootstrapResult:
        return SandboxGuardrailBootstrapResult(
            tenant_id="tenant-a",
            intent_id=UUID("40000000-0000-4000-8000-000000000001"),
            capability_token="cap-sandbox",
            operation=str(kwargs.get("operation", "travel.book_hotel")),
            requested_spend_cents=int(kwargs.get("requested_spend_cents", 100)),
            sandbox_lifecycle_status="funded",
        )

    async def submit_sandbox_evidence(
        self,
        intent_id: UUID,
        payload: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> SandboxGuardrailEvidenceResult:
        _ = payload
        return SandboxGuardrailEvidenceResult(
            tenant_id="tenant-a",
            intent_id=intent_id,
            operation=str(kwargs.get("operation", "travel.book_hotel")),
            requested_spend_cents=int(kwargs.get("requested_spend_cents", 100)),
            sandbox_lifecycle_status="funded",
            predicate_passed=True,
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
async def test_paybond_agent_run_tracks_policy_snapshot() -> None:
    document = parse_paybond_policy_document_v1(
        {
            "version": 1,
            "name": "travel-agent-v1",
            "default_deny": True,
            "tools": {
                "travel.book_hotel": {
                    "side_effecting": True,
                    "evidence_preset": "cost_and_completion",
                }
            },
        }
    )
    registry = create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {"evidence_preset": "cost_and_completion"},
            }
        }
    )
    snapshot = create_policy_snapshot(
        document=document,
        registry=registry,
        source="file",
        loaded_at="2030-01-01T00:00:00+00:00",
    )

    run = await PaybondAgentRun.bind(
        _Host(),
        {
            "registry": registry,
            "policy_snapshot": snapshot,
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
            },
        },
    )

    assert run.current_snapshot is snapshot
    assert run.policy_digest == snapshot.digest
    assert run.policy_version == snapshot.version
    assert run.binding.policy_snapshot is snapshot
