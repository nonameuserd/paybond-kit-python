from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

pytest.importorskip("langchain_core")

from langchain_core.messages import ToolMessage

from paybond_kit.capability_binding import PaybondCapabilityBinding
from paybond_kit.harbor import HarborClient
from paybond_kit.langgraph_hooks import paybond_awrap_tool_call_capability


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
    harbor = HarborClient("https://harbor.test", "tenant-a")
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
    harbor = HarborClient("https://harbor.test", "tenant-a")
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
