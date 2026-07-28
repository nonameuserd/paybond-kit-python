from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

pytest.importorskip("langchain_core")

from langchain_core.messages import ToolMessage

from paybond_kit.capability_binding import PaybondCapabilityBinding
from paybond_kit.harbor import HarborClient, VerifyCapabilityResult
from paybond_kit.langgraph_hooks import paybond_awrap_tool_call, paybond_awrap_tool_call_capability


class _FakeHarbor:
    def __init__(self, result: VerifyCapabilityResult) -> None:
        self.result = result
        self.complete_spend_decision = AsyncMock()

    async def verify_capability(self, **kwargs: object) -> VerifyCapabilityResult:
        return self.result


@pytest.mark.asyncio
async def test_langgraph_awrap_completes_spend_after_success() -> None:
    intent_id = uuid.uuid4()
    decision_id = uuid.uuid4()
    harbor = _FakeHarbor(
        VerifyCapabilityResult(
            allow=True,
            audit_id=uuid.uuid4(),
            tenant="tenant-a",
            intent_id=intent_id,
            code=None,
            message=None,
            decision_id=decision_id,
        )
    )
    binding = PaybondCapabilityBinding(
        harbor=cast(HarborClient, harbor),
        intent_id=intent_id,
        capability_token="cap-token",
    )
    with pytest.warns(DeprecationWarning, match="paybond_awrap_tool_call_capability"):
        wrap = paybond_awrap_tool_call_capability(binding)
    req = MagicMock()
    req.tool_call = {"name": "demo_tool", "id": "call-1", "args": {}}
    executed = AsyncMock(
        return_value=ToolMessage(content="ok", tool_call_id="call-1", name="demo_tool")
    )

    out = await wrap(req, executed)

    assert out.content == "ok"
    executed.assert_awaited_once()
    harbor.complete_spend_decision.assert_awaited_once_with(
        decision_id=str(decision_id),
        outcome="consumed",
    )


@pytest.mark.asyncio
@respx.mock
async def test_langgraph_awrap_allows_then_executes() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "tenant-a",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
            },
        )
    )
    harbor = HarborClient("https://harbor.test", "tenant-a", static_harbor_bearer_token="test-bearer")
    binding = PaybondCapabilityBinding(
        harbor=harbor,
        intent_id=intent_id,
        capability_token="Cg==",
    )
    wrap = paybond_awrap_tool_call_capability(binding)
    req = MagicMock()
    req.tool_call = {"name": "demo_tool", "id": "call-1", "args": {}}
    executed = AsyncMock(
        return_value=ToolMessage(content="ok", tool_call_id="call-1", name="demo_tool")
    )
    try:
        out = await wrap(req, executed)
        assert out.content == "ok"
        executed.assert_awaited_once()
    finally:
        await harbor.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_langgraph_awrap_resolves_spend_from_request() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "tenant-a",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
            },
        )
    )
    harbor = HarborClient("https://harbor.test", "tenant-a", static_harbor_bearer_token="test-bearer")
    binding = PaybondCapabilityBinding(
        harbor=harbor,
        intent_id=intent_id,
        capability_token="Cg==",
    )
    wrap = paybond_awrap_tool_call_capability(
        binding,
        requested_spend_cents=lambda request: int(request.tool_call["args"]["price_cents"]),
    )
    req = MagicMock()
    req.tool_call = {"name": "demo_tool", "id": "call-1", "args": {"price_cents": 15_500}}
    executed = AsyncMock(
        return_value=ToolMessage(content="ok", tool_call_id="call-1", name="demo_tool")
    )
    try:
        await wrap(req, executed)
        verify_call = next(call for call in respx.calls if call.request.url.path.endswith("/verify"))
        assert verify_call.request.content is not None
        assert b'"requested_spend_cents":15500' in verify_call.request.content
    finally:
        await harbor.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_langgraph_awrap_denies_without_execute() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": False,
                "audit_id": str(audit_id),
                "tenant": "tenant-a",
                "intent_id": str(intent_id),
                "code": "deny",
                "message": "blocked",
            },
        )
    )
    harbor = HarborClient("https://harbor.test", "tenant-a", static_harbor_bearer_token="test-bearer")
    binding = PaybondCapabilityBinding(
        harbor=harbor,
        intent_id=intent_id,
        capability_token="Cg==",
    )
    wrap = paybond_awrap_tool_call_capability(binding)
    req = MagicMock()
    req.tool_call = {"name": "demo_tool", "id": "call-1", "args": {}}
    executed = AsyncMock()
    try:
        out = await wrap(req, executed)
        assert isinstance(out, ToolMessage)
        assert out.status == "error"
        assert "blocked" in out.content
        executed.assert_not_called()
    finally:
        await harbor.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_langgraph_awrap_tool_call_resolves_spend_from_registry() -> None:
    """paybond_awrap_tool_call(run) forwards tool args to registry spend resolvers."""
    from dataclasses import dataclass
    from typing import Any
    from uuid import uuid4

    from paybond_kit.agent import PaybondAgentRun, create_paybond_tool_registry
    from paybond_kit.guardrails import SandboxGuardrailBootstrapResult, SandboxGuardrailEvidenceResult
    from paybond_kit.spend_guard import PaybondSpendGuard

    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "tenant-a",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
                "decision_id": str(uuid4()),
            },
        )
    )
    respx.post(url__regex=r".*/v1/spend/decisions/.*/complete").mock(
        return_value=httpx.Response(200, json={})
    )

    harbor_client = HarborClient("https://harbor.test", "tenant-a", static_harbor_bearer_token="test-bearer")

    @dataclass
    class _FakeHarborRun:
        harbor_client: HarborClient
        tenant_id: str = "tenant-a"

        async def verify_capability(self, **kwargs: Any) -> VerifyCapabilityResult:
            return await self.harbor_client.verify_capability(**kwargs)

        async def get_intent(self, intent_id: uuid.UUID) -> dict[str, Any]:
            return {"tenant_id": self.tenant_id, "allowed_tools": ["travel.book_hotel"]}

        async def complete_spend_decision(self, **kwargs: Any) -> None:
            complete = getattr(self.harbor_client, "complete_spend_decision", None)
            if complete is not None:
                await complete(**kwargs)

        async def submit_evidence(
            self,
            intent_id: uuid.UUID,
            evidence_body: dict[str, Any],
            *,
            recognition_proof: Mapping[str, Any],
            idempotency_key: str | None = None,
        ) -> dict[str, Any]:
            _ = evidence_body, recognition_proof, idempotency_key
            return {
                "intent_id": str(intent_id),
                "state": "completed",
                "predicate_passed": True,
            }

    @dataclass
    class _FakeGuardrails:
        async def bootstrap_sandbox(self, **kwargs: Any) -> SandboxGuardrailBootstrapResult:
            return SandboxGuardrailBootstrapResult(
                tenant_id="tenant-a",
                intent_id=intent_id,
                capability_token="cap-sandbox",
                operation=str(kwargs["operation"]),
                requested_spend_cents=int(kwargs["requested_spend_cents"]),
                sandbox_lifecycle_status="funded",
            )

        async def submit_sandbox_evidence(
            self,
            intent_id: uuid.UUID,
            payload: Mapping[str, Any] | None = None,
            *,
            vendor_payload: Mapping[str, Any] | None = None,
            artifacts: list[str] | None = None,
            operation: str | None = None,
            requested_spend_cents: int | None = None,
            metadata: Mapping[str, Any] | None = None,
            idempotency_key: str | None = None,
        ) -> SandboxGuardrailEvidenceResult:
            _ = payload, vendor_payload, artifacts, metadata, idempotency_key
            return SandboxGuardrailEvidenceResult(
                tenant_id="tenant-a",
                intent_id=intent_id,
                operation=operation or "travel.book_hotel",
                requested_spend_cents=requested_spend_cents or 15_500,
                sandbox_lifecycle_status="completed",
                predicate_passed=True,
            )

    @dataclass
    class _FakePaybond:
        harbor: _FakeHarborRun
        guardrails: _FakeGuardrails

        def spend_guard(self, intent_id: uuid.UUID, capability_token: str) -> PaybondSpendGuard:
            return PaybondSpendGuard(
                harbor=self.harbor,
                intent_id=intent_id,
                capability_token=capability_token,
            )

    registry = create_paybond_tool_registry(
        {
            "default_deny": True,
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: int(args["price_cents"]),
                    "evidence_preset": "cost_and_completion",
                    "evidence_mapper": lambda result, _ctx: {
                        "status": result.get("status"),
                        "cost_cents": result.get("cost_cents"),
                    },
                }
            },
        }
    )
    run = await PaybondAgentRun.bind(
        _FakePaybond(harbor=_FakeHarborRun(harbor_client), guardrails=_FakeGuardrails()),
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 20_000,
            },
            "registry": registry,
        },
    )
    wrap = paybond_awrap_tool_call(run)
    req = MagicMock()
    req.tool_call = {
        "name": "travel.book_hotel",
        "id": "call-registry-spend",
        "args": {"price_cents": 15_500},
    }
    executed = AsyncMock(return_value={"status": "confirmed", "cost_cents": 15_500})

    try:
        await wrap(req, executed)
        verify_call = next(call for call in respx.calls if call.request.url.path.endswith("/verify"))
        assert verify_call.request.content is not None
        assert b'"requested_spend_cents":15500' in verify_call.request.content
        executed.assert_awaited_once()
    finally:
        await harbor_client.aclose()
