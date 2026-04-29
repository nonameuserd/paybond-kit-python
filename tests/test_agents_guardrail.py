from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import httpx
import pytest
import respx

pytest.importorskip("agents")

from agents.tool_context import ToolContext
from agents.tool_guardrails import ToolInputGuardrailData

from paybond_kit.agents_sdk import PaybondAgentsBinding, paybond_capability_input_guardrail
from paybond_kit.harbor import HarborClient


@pytest.mark.asyncio
@respx.mock
async def test_capability_guardrail_allows_when_harbor_allows() -> None:
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
    binding = PaybondAgentsBinding(
        harbor=harbor,
        intent_id=intent_id,
        capability_token="Cg==",
    )
    try:
        ctx = ToolContext(
            binding,
            tool_name="book_hotel",
            tool_call_id="call-1",
            tool_arguments="{}",
            tool_namespace="travel",
        )
        data = ToolInputGuardrailData(context=ctx, agent=MagicMock())
        guard = paybond_capability_input_guardrail()
        out = await guard.run(data)
        assert out.behavior["type"] == "allow"
    finally:
        await harbor.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_capability_guardrail_rejects_when_harbor_denies() -> None:
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
                "message": "nope",
            },
        )
    )
    harbor = HarborClient("https://harbor.test", "tenant-a")
    binding = PaybondAgentsBinding(
        harbor=harbor,
        intent_id=intent_id,
        capability_token="Cg==",
    )
    try:
        ctx = ToolContext(
            binding,
            tool_name="book_hotel",
            tool_call_id="call-1",
            tool_arguments="{}",
            tool_namespace="travel",
        )
        data = ToolInputGuardrailData(context=ctx, agent=MagicMock())
        guard = paybond_capability_input_guardrail()
        out = await guard.run(data)
        assert out.behavior["type"] == "reject_content"
        assert "nope" in out.behavior["message"]
    finally:
        await harbor.aclose()
