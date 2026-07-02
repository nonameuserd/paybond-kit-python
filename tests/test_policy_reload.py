from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.guardrails import SandboxGuardrailBootstrapResult, SandboxGuardrailEvidenceResult
from paybond_kit.harbor import VerifyCapabilityResult
from paybond_kit.policy.digest import policy_document_to_dict
from paybond_kit.policy.reload import (
    PaybondPolicyReloadError,
    detect_policy_loosening,
    reload_policy_on_run,
    requires_intent_rebind,
)
from paybond_kit.policy.schema import parse_paybond_policy_document_v1
from paybond_kit.policy.snapshot import create_policy_snapshot
from paybond_kit.spend_guard import PaybondSpendGuard


def _document_to_json(document) -> str:
    return json.dumps(policy_document_to_dict(document))


@dataclass
class _FakeHarbor:
    tenant_id: str = "tenant-a"
    complete_spend_decision: AsyncMock = field(default_factory=AsyncMock)
    submit_evidence: AsyncMock = field(
        default_factory=lambda: AsyncMock(
            return_value={
                "intent_id": "40000000-0000-4000-8000-000000000001",
                "state": "completed",
                "predicate_passed": True,
            }
        )
    )

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


def _travel_document(max_spend_cents: int = 20_000):
    return parse_paybond_policy_document_v1(
        {
            "version": 1,
            "name": "travel-agent-v1",
            "default_deny": True,
            "tools": {
                "travel.book_hotel": {
                    "side_effecting": True,
                    "max_spend_cents": max_spend_cents,
                    "evidence_preset": "cost_and_completion",
                }
            },
            "intent": {"allowed_tools": ["travel.book_hotel"]},
        }
    )


def _snapshot_from_document(document):
    registry = create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "evidence_preset": "cost_and_completion",
                    "spend_cents": document.tools["travel.book_hotel"].max_spend_cents,
                }
            },
            "default_deny": document.default_deny,
        }
    )
    return create_policy_snapshot(document=document, registry=registry, source="file")


@pytest.mark.asyncio
async def test_reload_applies_stricter_cap(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text(_document_to_json(_travel_document(20_000)), encoding="utf-8")
    snapshot = _snapshot_from_document(_travel_document(20_000))

    run = await PaybondAgentRun.bind(
        _Host(),
        {
            "registry": snapshot.registry,
            "policy_snapshot": snapshot,
            "policy_file": str(policy_path),
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
            },
        },
    )

    policy_path.write_text(_document_to_json(_travel_document(5_000)), encoding="utf-8")
    result = await run.reload_policy({"file": str(policy_path)})
    assert result.applied is True
    assert run.registry.resolve_spend_cents("travel.book_hotel", {}) == 5_000


@pytest.mark.asyncio
async def test_reload_retains_registry_on_parse_failure(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    snapshot = _snapshot_from_document(_travel_document())
    policy_path.write_text(_document_to_json(snapshot.document), encoding="utf-8")

    run = await PaybondAgentRun.bind(
        _Host(),
        {
            "registry": snapshot.registry,
            "policy_snapshot": snapshot,
            "policy_file": str(policy_path),
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
            },
        },
    )

    previous_digest = run.policy_digest
    policy_path.write_text("not: valid: yaml: [", encoding="utf-8")
    with pytest.raises(Exception):
        await run.reload_policy({"file": str(policy_path)})
    assert run.policy_digest == previous_digest


@pytest.mark.asyncio
async def test_reload_denies_loosening_by_default(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text(_document_to_json(_travel_document(5_000)), encoding="utf-8")
    snapshot = _snapshot_from_document(_travel_document(5_000))

    run = await PaybondAgentRun.bind(
        _Host(),
        {
            "registry": snapshot.registry,
            "policy_snapshot": snapshot,
            "policy_file": str(policy_path),
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
            },
        },
    )

    policy_path.write_text(_document_to_json(_travel_document(50_000)), encoding="utf-8")
    with pytest.raises(PaybondPolicyReloadError) as exc:
        await run.reload_policy({"file": str(policy_path)})
    assert exc.value.code == "loosening_denied"


def test_detect_policy_loosening_flags_higher_caps() -> None:
    reasons = detect_policy_loosening(_travel_document(5_000), _travel_document(50_000))
    assert any("max_spend_cents increased" in reason for reason in reasons)


def test_requires_intent_rebind_when_allowed_tools_drift() -> None:
    document = parse_paybond_policy_document_v1(
        {
            "version": 1,
            "name": "travel-agent-v1",
            "default_deny": True,
            "tools": {
                "travel.book_hotel": {
                    "side_effecting": True,
                    "evidence_preset": "cost_and_completion",
                },
                "travel.book_flight": {
                    "side_effecting": True,
                    "evidence_preset": "cost_and_completion",
                },
            },
            "intent": {"allowed_tools": ["travel.book_hotel", "travel.book_flight"]},
        }
    )
    assert requires_intent_rebind(document, ("travel.book_hotel",)) is True


@pytest.mark.asyncio
async def test_reload_updates_interceptor_registry(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text(_document_to_json(_travel_document(20_000)), encoding="utf-8")
    snapshot = _snapshot_from_document(_travel_document(20_000))

    run = await PaybondAgentRun.bind(
        _Host(),
        {
            "registry": snapshot.registry,
            "policy_snapshot": snapshot,
            "policy_file": str(policy_path),
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
            },
        },
    )

    policy_path.write_text(_document_to_json(_travel_document(5_000)), encoding="utf-8")
    await run.reload_policy({"file": str(policy_path)})

    assert run.registry.resolve_spend_cents("travel.book_hotel", {}) == 5_000
    assert run.interceptor._binding.registry.resolve_spend_cents("travel.book_hotel", {}) == 5_000


@pytest.mark.asyncio
async def test_reload_pins_policy_digest_for_in_flight_wrap_execute(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text(_document_to_json(_travel_document(20_000)), encoding="utf-8")
    snapshot = _snapshot_from_document(_travel_document(20_000))

    host = _Host()

    run = await PaybondAgentRun.bind(
        host,
        {
            "registry": snapshot.registry,
            "policy_snapshot": snapshot,
            "policy_file": str(policy_path),
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
            },
        },
    )

    pinned_digest = run.policy_digest
    gate = asyncio.Event()

    async def _execute() -> dict[str, object]:
        await gate.wait()
        return {"status": "completed", "cost_cents": 100}

    execute_task = asyncio.create_task(
        run.interceptor.wrap_execute(
            tool_name="travel.book_hotel",
            tool_call_id="call-1",
            arguments={},
            execute=_execute,
        )
    )

    policy_path.write_text(_document_to_json(_travel_document(5_000)), encoding="utf-8")
    reload_task = asyncio.create_task(run.reload_policy({"file": str(policy_path)}))
    await asyncio.sleep(0.05)
    gate.set()

    wrapped = await execute_task
    reload_result = await reload_task

    assert wrapped.authorization is not None
    assert wrapped.authorization.get("policy_digest") == pinned_digest
    assert reload_result.applied is True


@pytest.mark.asyncio
async def test_effective_poll_skips_unchanged_digest(tmp_path: Path) -> None:
    policy_path = tmp_path / "tenant-overlay.policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "version": 2,
                "name": "tenant-overlay",
                "default_deny": True,
                "extends": {"org_policy_id": "org-pol-1", "org_id": "org_acme"},
                "tools": {},
                "overrides": {"tools": {"travel.book_hotel": {"max_spend_cents": 20_000}}},
            }
        ),
        encoding="utf-8",
    )
    snapshot = _snapshot_from_document(_travel_document())

    run = await PaybondAgentRun.bind(
        _Host(),
        {
            "registry": snapshot.registry,
            "policy_snapshot": snapshot,
            "policy_file": str(policy_path),
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
            },
        },
    )

    class _Gateway:
        async def resolve_policy_effective(self, *_args, **_kwargs):
            return type(
                "Resolved",
                (),
                {
                    "effective_policy": {},
                    "effective_policy_digest": snapshot.digest,
                    "effective_policy_version": snapshot.version,
                    "merge_report": type(
                        "Report",
                        (),
                        {
                            "org_policy_id": None,
                            "org_id": None,
                            "base_policy_name": "",
                            "overlay_policy_name": None,
                            "overrides_applied": (),
                            "denied_widenings": (),
                        },
                    )(),
                    "org_base_version_seq": 1,
                    "org_base_content_digest": "sha256:abc",
                    "unchanged": True,
                },
            )()

    result = await reload_policy_on_run(
        run,
        {
            "file": str(policy_path),
            "resolve_inheritance": True,
            "gateway": _Gateway(),
        },
    )
    assert result.unchanged is True
    assert result.applied is False
