"""Tests for PaybondToolInterceptor.wrap_execute."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from paybond_kit.agent import (
    PaybondAgentRun,
    PaybondEvidenceSubmitError,
    PaybondUnregisteredSideEffectingToolError,
    create_paybond_tool_registry,
)
from paybond_kit.agent.attach_bundle import (
    AttachBundlePayloadV1,
    production_evidence_from_attach_bundle,
)
from paybond_kit.guardrails import SandboxGuardrailBootstrapResult, SandboxGuardrailEvidenceResult
from paybond_kit.harbor import VerifyCapabilityResult
from paybond_kit.spend_guard import (
    PaybondSpendApprovalRequiredError,
    PaybondSpendDeniedError,
    PaybondSpendGuard,
)


def _registry() -> Any:
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
                "search.web": {
                    "evidence_preset": "api_response_ok",
                },
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
            "allowed_tools": ["travel.book_hotel", "search.web"],
        }


@dataclass
class _FakeGuardrails:
    intent_id: UUID | None = None
    last_operation: str = "travel.book_hotel"

    async def bootstrap_sandbox(self, **kwargs: Any) -> SandboxGuardrailBootstrapResult:
        self.intent_id = uuid4()
        self.last_operation = str(kwargs["operation"])
        return SandboxGuardrailBootstrapResult(
            tenant_id="tenant-a",
            intent_id=self.intent_id,
            capability_token="cap-sandbox",
            operation=self.last_operation,
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
async def test_interceptor_passthrough_read_only_tools() -> None:
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
        tool_name="lookup.weather",
        tool_call_id="call-readonly",
        arguments={"city": "Lisbon"},
        execute=lambda: {"hits": 3},
    )

    assert result.tool_result == {"hits": 3}
    assert result.authorization is None
    assert result.evidence is None


@pytest.mark.asyncio
async def test_interceptor_authorizes_executes_and_submits_evidence() -> None:
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
        arguments={"city": "Lisbon", "estimated_price_cents": 18_700},
        execute=lambda: {
            "reservation": {"status": "confirmed", "price_cents": 18_700},
        },
    )

    assert result.tool_result == {
        "reservation": {"status": "confirmed", "price_cents": 18_700},
    }
    assert result.authorization is not None
    assert result.authorization["allow"] is True
    assert result.authorization["audit_id"]
    assert result.authorization["decision_id"]
    assert result.evidence is not None
    assert result.evidence.submitted is True
    assert result.evidence.predicate_passed is True
    paybond.guardrails.submit_sandbox_evidence.assert_awaited_once()
    call_kwargs = paybond.guardrails.submit_sandbox_evidence.await_args.kwargs
    assert call_kwargs["payload"] == {"status": "completed", "cost_cents": 18_700}
    assert call_kwargs["idempotency_key"] == f"evidence:{run.intent_id}:call-1"


@pytest.mark.asyncio
async def test_interceptor_prefers_sandbox_bind_spend_over_policy_max() -> None:
    """Capability max matches bind spend, not policy max_spend_cents on the tool."""
    captured: dict[str, Any] = {}

    @dataclass
    class _SpendCapturingHarbor(_FakeHarbor):
        async def verify_capability(self, **kwargs: Any) -> VerifyCapabilityResult:
            captured.update(kwargs)
            return await super().verify_capability(**kwargs)

        async def get_intent(self, intent_id: UUID) -> dict[str, str | list[str]]:
            return {
                "tenant_id": self.tenant_id,
                "allowed_tools": ["saas.provision_seat"],
            }

    registry = create_paybond_tool_registry(
        {
            "default_deny": True,
            "side_effecting": {
                "saas.provision_seat": {
                    "spend_cents": 5_000,
                    "evidence_preset": "cost_and_completion",
                },
            },
        }
    )
    paybond = _FakePaybond(harbor=_SpendCapturingHarbor(), guardrails=_FakeGuardrails())
    run = await PaybondAgentRun.bind(
        paybond,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "saas.provision_seat",
                "requested_spend_cents": 2_900,
            },
            "registry": registry,
        },
    )

    await run.interceptor.wrap_execute(
        tool_name="saas.provision_seat",
        tool_call_id="smoke-1",
        arguments={},
        execute=lambda: {"status": "completed", "cost_cents": 2_900},
    )

    assert captured["requested_spend_cents"] == 2_900


@pytest.mark.asyncio
async def test_interceptor_denies_unregistered_side_effecting_tools() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    run = await PaybondAgentRun.bind(
        paybond,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": create_paybond_tool_registry(
                {
                    "side_effecting": {
                        "book_hotel_alias": {
                            "operation": "travel.book_hotel",
                            "spend_cents": 100,
                            "evidence_preset": "cost_and_completion",
                        },
                    },
                    "default_deny": True,
                }
            ),
        },
    )

    with pytest.raises(PaybondUnregisteredSideEffectingToolError):
        await run.interceptor.wrap_execute(
            tool_name="travel.book_hotel",
            tool_call_id="call-deny",
            arguments={},
            execute=lambda: {"ok": True},
        )


@pytest.mark.asyncio
async def test_interceptor_releases_spend_when_execute_fails() -> None:
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

    guard = run.guard
    paybond.harbor.complete_spend_decision = AsyncMock()

    with pytest.raises(RuntimeError, match="vendor down"):
        await run.interceptor.wrap_execute(
            tool_name="travel.book_hotel",
            tool_call_id="call-fail",
            arguments={"estimated_price_cents": 100},
            execute=_raise_vendor_down,
        )

    paybond.harbor.complete_spend_decision.assert_awaited()
    assert paybond.harbor.complete_spend_decision.await_args.kwargs["outcome"] == "released"


def _raise_vendor_down() -> None:
    raise RuntimeError("vendor down")


@pytest.mark.asyncio
async def test_interceptor_surfaces_evidence_submit_failures() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    paybond.guardrails.submit_sandbox_evidence = AsyncMock(side_effect=RuntimeError("gateway evidence rejected"))
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

    tool_result = {"reservation": {"status": "confirmed", "price_cents": 100}}

    with pytest.raises(PaybondEvidenceSubmitError) as exc:
        await run.interceptor.wrap_execute(
            tool_name="travel.book_hotel",
            tool_call_id="call-evidence-fail",
            arguments={"estimated_price_cents": 100},
            execute=lambda: tool_result,
        )

    assert exc.value.tool_result == tool_result
    assert "gateway evidence rejected" in str(exc.value)


@pytest.mark.asyncio
async def test_interceptor_propagates_approval_and_deny_errors() -> None:
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

    paybond.harbor.verify_capability = AsyncMock(
        return_value=VerifyCapabilityResult(
            allow=False,
            audit_id=uuid4(),
            tenant="tenant-a",
            intent_id=run.intent_id,
            code="approval_required",
            message="approval required",
        )
    )

    with pytest.raises(PaybondSpendApprovalRequiredError):
        await run.interceptor.wrap_execute(
            tool_name="travel.book_hotel",
            tool_call_id="call-hold",
            arguments={"estimated_price_cents": 100},
            execute=lambda: {"ok": True},
        )

    paybond.harbor.verify_capability = AsyncMock(
        return_value=VerifyCapabilityResult(
            allow=False,
            audit_id=uuid4(),
            tenant="tenant-a",
            intent_id=run.intent_id,
            code="denied",
            message="denied",
        )
    )

    with pytest.raises(PaybondSpendDeniedError):
        await run.interceptor.wrap_execute(
            tool_name="travel.book_hotel",
            tool_call_id="call-deny-auth",
            arguments={"estimated_price_cents": 100},
            execute=lambda: {"ok": True},
        )


@pytest.mark.asyncio
async def test_interceptor_reauthorizes_when_cached_authorization_is_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from paybond_kit.agent import authorization_cache

    now = {"value": 1_000.0}
    monkeypatch.setattr(authorization_cache.time, "monotonic", lambda: now["value"])

    harbor = _FakeHarbor()
    verify = AsyncMock(side_effect=harbor.verify_capability)
    harbor.verify_capability = verify  # type: ignore[method-assign]
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
        },
    )

    await run.interceptor.authorize_tool_call(
        tool_name="travel.book_hotel",
        tool_call_id="call-stale",
        arguments={"estimated_price_cents": 100},
    )

    now["value"] += authorization_cache.AUTHORIZATION_CACHE_TTL_SEC + 1

    await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-stale",
        arguments={"estimated_price_cents": 100},
        execute=lambda: {"reservation": {"status": "confirmed", "price_cents": 100}},
    )

    assert verify.await_count == 2


@pytest.mark.asyncio
async def test_interceptor_reauthorizes_when_cache_was_overwritten_for_same_tool_call() -> None:
    harbor = _FakeHarbor()
    verify = AsyncMock(side_effect=harbor.verify_capability)
    harbor.verify_capability = verify  # type: ignore[method-assign]
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
        },
    )

    await run.interceptor.authorize_tool_call(
        tool_name="travel.book_hotel",
        tool_call_id="call-overwrite",
        arguments={"estimated_price_cents": 100},
    )
    await run.interceptor.authorize_tool_call(
        tool_name="travel.book_hotel",
        tool_call_id="call-overwrite",
        arguments={"estimated_price_cents": 5_000},
    )

    await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-overwrite",
        arguments={"estimated_price_cents": 100},
        execute=lambda: {"reservation": {"status": "confirmed", "price_cents": 100}},
    )

    assert verify.await_count == 3


@pytest.mark.asyncio
async def test_interceptor_submits_production_auto_evidence_with_recognition_proof() -> None:
    submit_evidence = AsyncMock(
        return_value={
            "intent_id": "550e8400-e29b-41d4-a716-446655440000",
            "state": "completed",
            "predicate_passed": True,
        }
    )
    harbor = _FakeHarbor()
    harbor.submit_evidence = submit_evidence
    paybond = _FakePaybond(harbor=harbor, guardrails=_FakeGuardrails())
    run = await PaybondAgentRun.bind(
        paybond,
        {
            "attach": {
                "intent_id": "550e8400-e29b-41d4-a716-446655440000",
                "capability_token": "cap-prod",
                "production_evidence": {
                    "payee_did": "did:web:vendor.example",
                    "payee_signing_seed": b"\x01" * 32,
                    "agent_recognition_key_id": "kid-1",
                    "agent_recognition_signing_seed": b"\x02" * 32,
                },
            },
            "registry": _registry(),
        },
    )

    result = await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-prod-1",
        arguments={"estimated_price_cents": 100},
        execute=lambda: {
            "reservation": {"status": "confirmed", "price_cents": 100},
        },
    )

    assert result.evidence is not None
    assert result.evidence.intent_state == "completed"
    assert result.evidence.predicate_passed is True
    submit_evidence.assert_awaited_once()
    await_args = submit_evidence.await_args
    assert await_args is not None
    args, kwargs = await_args
    _intent_id, wire = args
    assert wire["payload"] == {"status": "completed", "cost_cents": 100}
    assert kwargs["recognition_proof"]["purpose"] == "harbor.intent.evidence.submit"
    assert kwargs["recognition_proof"]["key_id"] == "kid-1"
    assert kwargs["idempotency_key"] == f"evidence:{run.intent_id}:call-prod-1"


@pytest.mark.asyncio
async def test_interceptor_signs_recognition_proof_from_attach_bundle_credentials() -> None:
    bundle_payload = AttachBundlePayloadV1(
        payee_did="did:paybond:middleware:acme:amk_demo:payee",
        payee_signing_seed_hex="a" * 64,
        agent_recognition_key_id="amk_demo",
        agent_recognition_signing_seed_hex="b" * 64,
    )
    production_evidence = production_evidence_from_attach_bundle(bundle_payload)
    intent_id = "550e8400-e29b-41d4-a716-446655440001"
    submit_evidence = AsyncMock(
        return_value={
            "intent_id": intent_id,
            "state": "completed",
            "predicate_passed": True,
        }
    )
    harbor = _FakeHarbor()
    harbor.submit_evidence = submit_evidence
    paybond = _FakePaybond(harbor=harbor, guardrails=_FakeGuardrails())
    run = await PaybondAgentRun.bind(
        paybond,
        {
            "attach": {
                "intent_id": intent_id,
                "capability_token": "cap-bundle",
                "production_evidence": production_evidence,
            },
            "registry": _registry(),
        },
    )

    await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-bundle-1",
        arguments={"estimated_price_cents": 100},
        execute=lambda: {
            "reservation": {"status": "confirmed", "price_cents": 100},
        },
    )

    submit_evidence.assert_awaited_once()
    await_args = submit_evidence.await_args
    assert await_args is not None
    _args, kwargs = await_args
    assert kwargs["recognition_proof"]["purpose"] == "harbor.intent.evidence.submit"
    assert kwargs["recognition_proof"]["key_id"] == "amk_demo"


@pytest.mark.asyncio
async def test_interceptor_emits_structured_trace_events() -> None:
    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    trace_events: list[dict[str, object]] = []
    run = await PaybondAgentRun.bind(
        paybond,
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": _registry(),
            "trace_sink": trace_events.append,
        },
    )

    await run.interceptor.wrap_execute(
        tool_name="travel.book_hotel",
        tool_call_id="call-trace-1",
        arguments={"estimated_price_cents": 18_700},
        execute=lambda: {"reservation": {"status": "confirmed", "price_cents": 18_700}},
    )

    assert [event["type"] for event in trace_events] == [
        "tool_selected",
        "spend_authorized",
        "tool_executed",
        "spend_finalized",
        "evidence_submitted",
    ]
    evidence_event = next(event for event in trace_events if event["type"] == "evidence_submitted")
    assert str(evidence_event["evidence_id"]).endswith(":call-trace-1")
    assert evidence_event["preset_id"] == "cost_and_completion"


@pytest.mark.asyncio
async def test_langgraph_awrap_tool_call_delegates_to_interceptor() -> None:
    pytest.importorskip("langchain_core")
    from unittest.mock import AsyncMock, MagicMock

    from paybond_kit.langgraph_hooks import paybond_awrap_tool_call

    paybond = _FakePaybond(harbor=_FakeHarbor(), guardrails=_FakeGuardrails())
    paybond.guardrails.submit_sandbox_evidence.reset_mock()
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
    wrap = paybond_awrap_tool_call(run)
    req = MagicMock()
    req.tool_call = {
        "name": "travel.book_hotel",
        "id": "call-lg-1",
        "args": {"estimated_price_cents": 18_700},
    }
    executed = AsyncMock(
        return_value={
            "reservation": {"status": "confirmed", "price_cents": 18_700},
        }
    )

    out = await wrap(req, executed)

    assert out == {"reservation": {"status": "confirmed", "price_cents": 18_700}}
    executed.assert_awaited_once()
    paybond.guardrails.submit_sandbox_evidence.assert_awaited_once()
