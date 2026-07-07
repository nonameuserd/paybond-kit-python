"""Agent Receipt Standard Phase 1: bind-time agentContext resolution, verify-call context
propagation, and unsigned receipt draft composition. Mirrors
``kit/ts/tests/agent/agent-receipt-draft.test.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry
from paybond_kit.agent_receipt import (
    ConfigHashInput,
    agent_receipt_message_digest_sha256_hex,
    config_hash_sha256_hex,
    prompt_hash_sha256_hex,
)
from paybond_kit.agent.types import PaybondRunProductionEvidenceCredentials
from paybond_kit.guardrails import SandboxGuardrailBootstrapResult, SandboxGuardrailEvidenceResult
from paybond_kit.harbor import VerifyCapabilityResult
from paybond_kit.policy.schema import parse_paybond_policy_document_v1
from paybond_kit.policy.snapshot import create_policy_snapshot
from paybond_kit.spend_guard import PaybondSpendGuard

_INTENT_ID = UUID("550e8400-e29b-41d4-a716-446655440000")
_AUDIT_ID = UUID("9f1c2b3a-4d5e-6f70-8192-a3b4c5d6e7f8")
_DECISION_ID = UUID("1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809")


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


def _snapshot():
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
    return create_policy_snapshot(
        document=document,
        registry=_registry(),
        source="file",
        loaded_at="2030-01-01T00:00:00.000Z",
    )


@dataclass
class _FakeHarbor:
    tenant_id: str = "tenant-a"
    intent_id: UUID = _INTENT_ID
    allowed_tools: list[str] = field(default_factory=lambda: ["travel.book_hotel"])
    verify_calls: list[dict[str, Any]] = field(default_factory=list)
    complete_spend_decision: AsyncMock = field(default_factory=AsyncMock)
    submit_evidence: AsyncMock | None = None

    async def verify_capability(self, **kwargs: Any) -> VerifyCapabilityResult:
        self.verify_calls.append(kwargs)
        return VerifyCapabilityResult(
            allow=True,
            audit_id=_AUDIT_ID,
            tenant=self.tenant_id,
            intent_id=kwargs.get("intent_id") or self.intent_id,
            code=None,
            message=None,
            decision_id=_DECISION_ID,
        )

    async def get_intent(self, intent_id: UUID) -> dict[str, Any]:
        return {"tenant_id": self.tenant_id, "allowed_tools": self.allowed_tools}


@dataclass
class _FakeGuardrails:
    submit_sandbox_evidence: AsyncMock = field(
        default_factory=lambda: AsyncMock(
            return_value=SandboxGuardrailEvidenceResult(
                tenant_id="tenant-a",
                intent_id=uuid4(),
                operation="travel.book_hotel",
                requested_spend_cents=100,
                sandbox_lifecycle_status="completed",
                predicate_passed=True,
            )
        )
    )

    async def bootstrap_sandbox(self, **kwargs: Any) -> SandboxGuardrailBootstrapResult:
        return SandboxGuardrailBootstrapResult(
            tenant_id="tenant-a",
            intent_id=uuid4(),
            capability_token="cap-sandbox",
            operation=str(kwargs["operation"]),
            requested_spend_cents=int(kwargs["requested_spend_cents"]),
            sandbox_lifecycle_status="funded",
        )


@dataclass
class _FakePaybond:
    harbor: _FakeHarbor
    guardrails: _FakeGuardrails

    def spend_guard(self, intent_id: UUID, capability_token: str) -> PaybondSpendGuard:
        return PaybondSpendGuard(harbor=self.harbor, intent_id=intent_id, capability_token=capability_token)


def _production_evidence() -> PaybondRunProductionEvidenceCredentials:
    return {
        "payee_did": "did:web:vendor.example",
        "payee_signing_seed": b"\x01" * 32,
        "agent_recognition_key_id": "kid-1",
        "agent_recognition_signing_seed": b"\x02" * 32,
    }


@pytest.mark.asyncio
async def test_bind_auto_computes_config_hash_and_prompt_hash_from_materials() -> None:
    snapshot = _snapshot()
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    tools_manifest = [{"name": "travel.book_hotel"}]

    run = await PaybondAgentRun.bind(
        paybond,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
            "policy_snapshot": snapshot,
            "agent_context": {
                "model_family": "gpt-5",
                "model_instance_id": "run-abc",
                "config_hash_materials": {
                    "system_prompt": "You are a travel booking agent.",
                    "tools_manifest": tools_manifest,
                },
                "normalized_user_prompt": "book a hotel in lisbon",
                "principal_did": "did:web:acme.example",
                "operator_did": "did:web:acme.example:operator",
                "policy_template_id": "travel-agent-v1",
            },
        },
    )

    expected_config_hash = config_hash_sha256_hex(
        ConfigHashInput(
            system_prompt="You are a travel booking agent.",
            tools_manifest=tools_manifest,
            policy_snapshot_id=snapshot.digest.removeprefix("sha256:"),
        )
    )
    expected_prompt_hash = prompt_hash_sha256_hex("book a hotel in lisbon")

    agent_context = run.binding.agent_context
    assert agent_context is not None
    assert agent_context.model_family == "gpt-5"
    assert agent_context.model_instance_id == "run-abc"
    assert agent_context.config_hash_hex == expected_config_hash
    assert agent_context.prompt_hash_hex == expected_prompt_hash
    assert agent_context.principal_did == "did:web:acme.example"
    assert agent_context.operator_did == "did:web:acme.example:operator"
    assert agent_context.policy_template_id == "travel-agent-v1"


@pytest.mark.asyncio
async def test_bind_prefers_precomputed_hashes_over_materials() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    precomputed_config_hash = "a" * 64
    precomputed_prompt_hash = "b" * 64

    run = await PaybondAgentRun.bind(
        paybond,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
            "agent_context": {
                "model_family": "claude-4",
                "config_hash_hex": precomputed_config_hash,
                "prompt_hash_hex": precomputed_prompt_hash,
            },
        },
    )

    assert run.binding.agent_context is not None
    assert run.binding.agent_context.config_hash_hex == precomputed_config_hash
    assert run.binding.agent_context.prompt_hash_hex == precomputed_prompt_hash


@pytest.mark.asyncio
async def test_wrap_execute_forwards_agent_context_and_defaults_agent_subject() -> None:
    harbor = _FakeHarbor()
    paybond = _FakePaybond(harbor=harbor, guardrails=_FakeGuardrails())

    run = await PaybondAgentRun.bind(
        paybond,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
            "agent_context": {
                "model_family": "gpt-5",
                "config_hash_hex": "c" * 64,
                "prompt_hash_hex": "d" * 64,
                "operator_did": "did:web:acme.example:operator",
            },
        },
    )

    await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-1",
        arguments={"estimated_price_cents": 100},
        execute=lambda: {"reservation": {"status": "confirmed", "price_cents": 100}},
    )

    assert len(harbor.verify_calls) == 1
    call = harbor.verify_calls[0]
    assert call["model_family"] == "gpt-5"
    assert call["config_hash_hex"] == "c" * 64
    assert call["prompt_hash_hex"] == "d" * 64
    assert call["agent_subject"] == "did:web:acme.example:operator"


@pytest.mark.asyncio
async def test_receipt_draft_omitted_when_no_agent_context() -> None:
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
        },
    )

    result = await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-1",
        arguments={"estimated_price_cents": 100},
        execute=lambda: {"reservation": {"status": "confirmed", "price_cents": 100}},
    )

    assert result.receipt_draft is None


@pytest.mark.asyncio
async def test_receipt_draft_composed_for_production_auto_evidence_run() -> None:
    harbor = _FakeHarbor(
        submit_evidence=AsyncMock(
            return_value={
                "intent_id": str(_INTENT_ID),
                "tenant": "tenant-a",
                "state": "released",
                "predicate_passed": True,
                "payload_digest": "e" * 64,
                "artifacts_digest": "f" * 64,
            }
        )
    )
    paybond = _FakePaybond(harbor=harbor, guardrails=_FakeGuardrails())
    snapshot = _snapshot()

    run = await PaybondAgentRun.bind(
        paybond,
        {
            "attach": {
                "intent_id": str(_INTENT_ID),
                "capability_token": "cap-prod",
                "production_evidence": _production_evidence(),
            },
            "registry": _registry(),
            "policy_snapshot": snapshot,
            "agent_context": {
                "model_family": "gpt-5",
                "model_instance_id": "run-abc",
                "config_hash_hex": "c" * 64,
                "prompt_hash_hex": "d" * 64,
                "principal_did": "did:web:acme.example",
                "operator_did": "did:web:acme.example:operator",
                "policy_template_id": "travel-agent-v1",
            },
        },
    )

    result = await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-prod-1",
        arguments={"estimated_price_cents": 100},
        execute=lambda: {"reservation": {"status": "confirmed", "price_cents": 100}},
    )

    assert result.receipt_draft is not None
    draft = result.receipt_draft
    assert draft["tenant_id"] == "tenant-a"
    assert draft["scope"] == "action"
    authorization = draft["authorization"]
    assert authorization["principal_did"] == "did:web:acme.example"
    assert authorization["actor_subject"] == "did:web:acme.example:operator"
    assert authorization["decision_id"] == str(_DECISION_ID)
    assert authorization["audit_id"] == str(_AUDIT_ID)
    assert authorization["agent"] == {
        "operator_did": "did:web:acme.example:operator",
        "model_family": "gpt-5",
        "model_instance_id": "run-abc",
        "config_hash_sha256_hex": "c" * 64,
        "prompt_hash_sha256_hex": "d" * 64,
    }
    assert authorization["policy"] == {
        "template_id": "travel-agent-v1",
        "content_digest_sha256_hex": snapshot.digest.removeprefix("sha256:"),
    }
    assert authorization["requested_spend_cents"] == 100
    assert authorization["currency"] == "usd"

    execution = draft["execution"]
    assert execution["run_id"] == run.run_id
    assert execution["tool_call_id"] == "call-prod-1"
    assert execution["tool_name"] == "travel.book_hotel"
    assert execution["operation"] == "travel.book_hotel"
    assert execution["outcome"] == "executed"

    assert draft["merchant"]["payee_did"] == "did:web:vendor.example"
    assert draft["evidence"] == {
        "completion_preset_id": "cost_and_completion",
        "payload_digest_sha256_hex": "e" * 64,
        "artifacts_digest_sha256_hex": "f" * 64,
        "predicate_passed": True,
        "payee_did": "did:web:vendor.example",
    }
    assert draft["outcome"]["harbor_state"] == "released"
    assert draft["references"]["intent_id"] == str(_INTENT_ID)
    assert len(draft["receipt_id"]) == 64
    assert draft["message_digest_sha256_hex"] == agent_receipt_message_digest_sha256_hex(draft)


@pytest.mark.asyncio
async def test_receipt_draft_omitted_when_decision_id_unavailable() -> None:
    class _NoDecisionHarbor(_FakeHarbor):
        async def verify_capability(self, **kwargs: Any) -> VerifyCapabilityResult:
            self.verify_calls.append(kwargs)
            return VerifyCapabilityResult(
                allow=True,
                audit_id=_AUDIT_ID,
                tenant=self.tenant_id,
                intent_id=kwargs.get("intent_id") or self.intent_id,
                code=None,
                message=None,
                decision_id=None,
            )

    paybond = _FakePaybond(harbor=_NoDecisionHarbor(), guardrails=_FakeGuardrails())

    run = await PaybondAgentRun.bind(
        paybond,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
            "policy_snapshot": _snapshot(),
            "agent_context": {
                "model_family": "gpt-5",
                "config_hash_hex": "c" * 64,
                "prompt_hash_hex": "d" * 64,
                "principal_did": "did:web:acme.example",
                "operator_did": "did:web:acme.example:operator",
                "policy_template_id": "travel-agent-v1",
            },
        },
    )

    result = await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-1",
        arguments={"estimated_price_cents": 100},
        execute=lambda: {"reservation": {"status": "confirmed", "price_cents": 100}},
    )

    assert result.receipt_draft is None
