from __future__ import annotations

import uuid

import httpx
import pytest
import respx

from paybond_kit import (
    PaybondSpendApprovalRequiredError,
    PaybondSpendDeniedError,
    PaybondSpendGuard,
    guard_tool,
    paybond_agent_tool_spend_guard,
    paybond_runtime_neutral_tool_spend_guard,
)
from paybond_kit.harbor import HarborClient


@pytest.mark.asyncio
@respx.mock
async def test_spend_guard_calls_handler_after_allow() -> None:
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
    harbor = HarborClient("https://harbor.test", "tenant-a")
    called: list[str] = []

    async def tool(city: str) -> dict[str, str]:
        called.append(city)
        return {"city": city}

    try:
        guard = PaybondSpendGuard(
            harbor=harbor,
            intent_id=intent_id,
            capability_token="Cg==",
        )
        guarded = guard.guard_tool(
            operation="travel.book_hotel",
            requested_spend_cents=20_000,
            handler=tool,
        )
        assert await guarded("NYC") == {"city": "NYC"}
        assert called == ["NYC"]
    finally:
        await harbor.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_spend_guard_rejects_before_handler_on_deny() -> None:
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
                "code": "policy_mismatch",
                "message": "budget exceeded",
            },
        )
    )
    harbor = HarborClient("https://harbor.test", "tenant-a")
    called = False

    async def tool() -> str:
        nonlocal called
        called = True
        return "ok"

    try:
        guard = PaybondSpendGuard(
            harbor=harbor,
            intent_id=intent_id,
            capability_token="Cg==",
        )
        guarded = guard.guard_tool(operation="travel.book_hotel", handler=tool)
        with pytest.raises(PaybondSpendDeniedError):
            await guarded()
        assert called is False
    finally:
        await harbor.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_spend_guard_raises_approval_required_separately() -> None:
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
                "code": "approval_required",
                "message": "operator approval required",
                "approval_request_id": str(uuid.uuid4()),
                "reason_codes": ["approval_threshold_exceeded"],
            },
        )
    )
    harbor = HarborClient("https://harbor.test", "tenant-a")
    called = False

    async def tool() -> str:
        nonlocal called
        called = True
        return "ok"

    try:
        guard = PaybondSpendGuard(
            harbor=harbor,
            intent_id=intent_id,
            capability_token="Cg==",
        )
        guarded = guard.guard_tool(
            operation="travel.book_hotel",
            vendor_id="vendor_acme",
            handler=tool,
        )
        with pytest.raises(PaybondSpendApprovalRequiredError):
            await guarded()
        assert called is False
    finally:
        await harbor.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_spend_guard_forwards_metadata_to_verify() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    route = respx.post("https://harbor.test/verify").mock(
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
    harbor = HarborClient("https://harbor.test", "tenant-a")

    async def tool() -> str:
        return "ok"

    try:
        guard = PaybondSpendGuard(
            harbor=harbor,
            intent_id=intent_id,
            capability_token="Cg==",
        )
        guarded = guard.guard_tool(
            operation="travel.book_hotel",
            requested_spend_cents=20_000,
            vendor_id="vendor_acme",
            task_id="task-1",
            workflow_id="wf-1",
            tool_call_id="call-1",
            tool_name="book_hotel",
            handler=tool,
        )
        assert await guarded() == "ok"
        assert route.calls.last.request.content is not None
        payload = route.calls.last.request.content.decode()
        assert "vendor_acme" in payload
        assert "task-1" in payload
        assert "wf-1" in payload
        assert "call-1" in payload
        assert "book_hotel" in payload
    finally:
        await harbor.aclose()


def test_runtime_neutral_guard_aliases() -> None:
    assert paybond_agent_tool_spend_guard is guard_tool
    assert paybond_runtime_neutral_tool_spend_guard is guard_tool
