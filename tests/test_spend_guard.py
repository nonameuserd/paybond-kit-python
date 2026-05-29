from __future__ import annotations

import uuid

import httpx
import pytest
import respx

from paybond_kit import (
    PaybondCapabilityBinding,
    PaybondSpendDeniedError,
    PaybondSpendGuard,
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
            PaybondCapabilityBinding(
                harbor=harbor,
                intent_id=intent_id,
                capability_token="Cg==",
            )
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
            PaybondCapabilityBinding(
                harbor=harbor,
                intent_id=intent_id,
                capability_token="Cg==",
            )
        )
        guarded = guard.guard_tool(operation="travel.book_hotel", handler=tool)
        with pytest.raises(PaybondSpendDeniedError):
            await guarded()
        assert called is False
    finally:
        await harbor.aclose()
