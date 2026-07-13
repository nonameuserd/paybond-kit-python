"""Tests for Microsoft Agent Framework sandbox demo."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.microsoft_agent_framework.sandbox_demo import (
    run_microsoft_agent_framework_sandbox_demo,
)


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
            operation="paid-tool",
            requested_spend_cents=100,
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


class _FakeFunctionMiddleware:
    pass


@pytest.mark.asyncio
async def test_run_microsoft_agent_framework_sandbox_demo_offline() -> None:
    host = _make_host()

    with patch(
        "paybond_kit.microsoft_agent_framework.sandbox_demo.microsoft_agent_framework_runtime_available",
        return_value=True,
    ):
        with patch(
            "paybond_kit.microsoft_agent_framework.config._require_function_middleware",
            return_value=_FakeFunctionMiddleware,
        ):
            demo = await run_microsoft_agent_framework_sandbox_demo(
                host,
                operation="paid-tool",
                requested_spend_cents=100,
                evidence_preset="cost_and_completion",
            )

    assert demo["authorization"]["allow"] is True
    assert demo["evidence"]["submitted"] is True
    assert demo["tool_executed"] is True
    assert demo["tool_result"]["cost_cents"] == 100
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()
