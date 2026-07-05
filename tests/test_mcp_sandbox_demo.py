from __future__ import annotations

import pytest

from paybond_kit import Paybond
from paybond_kit.mcp_sandbox_demo import run_mcp_sandbox_demo

from .cli_agent_gateway_mock import SANDBOX_RAW_KEY, SMOKE_INTENT_ID, install_agent_gateway_mock


@pytest.mark.asyncio
async def test_run_mcp_sandbox_demo_offline_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    install_agent_gateway_mock(monkeypatch)

    paybond = await Paybond.open(
        api_key=SANDBOX_RAW_KEY,
        gateway_base_url="https://api.paybond.ai",
        expected_environment="sandbox",
    )
    try:
        demo = await run_mcp_sandbox_demo(
            paybond,
            api_key=SANDBOX_RAW_KEY,
            gateway_base_url="https://api.paybond.ai",
            operation="paid-tool",
            requested_spend_cents=100,
            evidence_preset="cost_and_completion",
        )
    finally:
        await paybond.aclose()

    assert demo["authorization"]["allow"] is True
    assert demo["evidence"]["submitted"] is True
    assert demo["tool_result"] == {"status": "completed", "cost_cents": 100}
    assert demo["bind"]["intent_id"] == SMOKE_INTENT_ID
