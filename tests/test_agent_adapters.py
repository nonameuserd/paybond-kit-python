from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest

from paybond_kit import PaybondSpendDeniedError, paybond_runtime_tool_call_adapter
from paybond_kit.harbor import VerifyCapabilityResult


@dataclass
class _Source:
    harbor: "_FakeHarbor"
    intent_id: UUID
    capability_token: str


class _FakeHarbor:
    def __init__(self, result: VerifyCapabilityResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    async def verify_capability(
        self,
        *,
        intent_id: UUID,
        token: str,
        operation: str,
        requested_spend_cents: int = 0,
    ) -> VerifyCapabilityResult:
        self.calls.append(
            {
                "intent_id": intent_id,
                "token": token,
                "operation": operation,
                "requested_spend_cents": requested_spend_cents,
            }
        )
        return self.result


def _result(*, intent_id: UUID, allow: bool) -> VerifyCapabilityResult:
    return VerifyCapabilityResult(
        allow=allow,
        audit_id=uuid4(),
        tenant="tenant-a",
        intent_id=intent_id,
        code=None if allow else "policy_mismatch",
        message=None if allow else "budget exceeded",
    )


@pytest.mark.asyncio
async def test_runtime_tool_call_adapter_executes_after_allow() -> None:
    intent_id = uuid4()
    harbor = _FakeHarbor(_result(intent_id=intent_id, allow=True))
    source = _Source(harbor=harbor, intent_id=intent_id, capability_token="cap-token")
    executed: list[str] = []

    async def execute(call: dict[str, object]) -> dict[str, object]:
        executed.append(str(call["city"]))
        return {"confirmation": f"demo-{call['city']}"}

    run = paybond_runtime_tool_call_adapter(
        source,
        operation=lambda call: str(call["name"]),
        requested_spend_cents=lambda call: int(call["spend"]),
        execute=execute,
    )

    assert await run({"name": "travel.book_hotel", "spend": 20_000, "city": "NYC"}) == {
        "confirmation": "demo-NYC"
    }
    assert harbor.calls == [
        {
            "intent_id": intent_id,
            "token": "cap-token",
            "operation": "travel.book_hotel",
            "requested_spend_cents": 20_000,
        }
    ]
    assert executed == ["NYC"]


@pytest.mark.asyncio
async def test_runtime_tool_call_adapter_maps_denial_without_executing() -> None:
    intent_id = uuid4()
    harbor = _FakeHarbor(_result(intent_id=intent_id, allow=False))
    source = _Source(harbor=harbor, intent_id=intent_id, capability_token="cap-token")
    executed = False

    async def execute(_: object) -> dict[str, str]:
        nonlocal executed
        executed = True
        return {"status": "ok"}

    run = paybond_runtime_tool_call_adapter(
        source,
        operation="travel.book_hotel",
        execute=execute,
        on_deny=lambda result, _: {
            "status": "blocked",
            "reason": result.message or result.code or "denied",
        },
    )

    assert await run({}) == {"status": "blocked", "reason": "budget exceeded"}
    assert executed is False


@pytest.mark.asyncio
async def test_runtime_tool_call_adapter_raises_denial_by_default() -> None:
    intent_id = uuid4()
    harbor = _FakeHarbor(_result(intent_id=intent_id, allow=False))
    source = _Source(harbor=harbor, intent_id=intent_id, capability_token="cap-token")
    run = paybond_runtime_tool_call_adapter(
        source,
        operation="travel.book_hotel",
        execute=lambda _: {"status": "ok"},
    )

    with pytest.raises(PaybondSpendDeniedError):
        await run({})
