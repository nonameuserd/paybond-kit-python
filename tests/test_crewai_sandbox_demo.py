"""Tests for CrewAI sandbox demo."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.crewai.sandbox_demo import run_crewai_sandbox_demo


def _make_host() -> MagicMock:
    guard = MagicMock()
    guard.assert_spend_authorized = AsyncMock(
        return_value=MagicMock(allow=True, audit_id="audit-1", decision_id="decision-1")
    )
    guard.complete_spend_authorization = AsyncMock()

    host = MagicMock()
    host.harbor.tenant_id = "tenant-a"
    host.guardrails.bootstrap_sandbox = AsyncMock(
        return_value=MagicMock(
            tenant_id="tenant-a",
            intent_id=UUID("00000000-0000-4000-8000-000000000001"),
            capability_token="cap-sandbox",
            operation="procurement.submit_po",
            requested_spend_cents=12_000,
            sandbox_lifecycle_status="funded",
        )
    )
    host.guardrails.submit_sandbox_evidence = AsyncMock(
        return_value=MagicMock(
            tenant_id="tenant-a",
            intent_id=UUID("00000000-0000-4000-8000-000000000001"),
            sandbox_lifecycle_status="completed",
            predicate_passed=True,
        )
    )
    host.spend_guard = MagicMock(return_value=guard)

    async def bind(config: dict[str, Any]) -> MagicMock:
        from paybond_kit.agent.run import PaybondAgentRun

        return await PaybondAgentRun.bind(host, config)

    host.agent_run.bind = bind
    return host


@pytest.mark.asyncio
async def test_run_crewai_sandbox_demo_offline_with_mock_tool() -> None:
    host = _make_host()

    def fake_tool(name: str):
        def decorator(func):
            tool = MagicMock()
            tool.name = name
            tool.func = func
            tool.run = lambda **kwargs: tool.func(**kwargs)
            return tool

        return decorator

    with patch("paybond_kit.crewai.sandbox_demo._require_crewai_demo_deps", return_value=fake_tool):
        with patch("paybond_kit.crewai.config._require_crewai_tools", return_value=MagicMock(tool=fake_tool)):
            with patch("paybond_kit.crewai.config.is_crewai_base_tool", return_value=False):
                demo = await run_crewai_sandbox_demo(
                    host,
                    operation="procurement.submit_po",
                    requested_spend_cents=12_000,
                    evidence_preset="cost_and_completion",
                )

    assert demo["authorization"]["allow"] is True
    assert demo["evidence"]["submitted"] is True
    assert demo["tool_result"]["cost_cents"] == 12_000
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()
