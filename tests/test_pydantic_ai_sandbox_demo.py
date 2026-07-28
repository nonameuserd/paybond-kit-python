"""Tests for Pydantic AI sandbox demo."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.agent.types import PaybondAgentRunBindConfig
from paybond_kit.pydantic_ai.sandbox_demo import run_pydantic_ai_sandbox_demo


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

    async def bind(config: PaybondAgentRunBindConfig) -> PaybondAgentRun:
        return await PaybondAgentRun.bind(host, config)

    host.agent_run.bind = bind
    return host


class _FakeTool:
    def __init__(self, function: Any, *, name: str | None = None, description: str | None = None, **_kwargs: Any) -> None:
        self.function = function
        self.name = name or getattr(function, "__name__", "tool")
        self.description = description or ""
        self.takes_ctx = False
        self.max_retries = None
        self.prepare = None
        self.args_validator = None
        self.docstring_format = "auto"
        self.require_parameter_descriptions = False
        self.strict = None
        self.sequential = False
        self.requires_approval = False
        self.metadata = None
        self.timeout = None
        self.defer_loading = False
        self.include_return_schema = None


@pytest.mark.asyncio
async def test_run_pydantic_ai_sandbox_demo_offline_with_mock_tool() -> None:
    host = _make_host()

    fake_module = MagicMock()
    fake_module.Tool = _FakeTool
    fake_module.ModelRetry = type("ModelRetry", (Exception,), {})

    with patch("paybond_kit.pydantic_ai.sandbox_demo._require_pydantic_ai_demo_deps", return_value=_FakeTool):
        with patch("paybond_kit.pydantic_ai.sandbox_demo._model_retry_cls", return_value=fake_module.ModelRetry):
            with patch("paybond_kit.pydantic_ai.config._require_pydantic_ai", return_value=fake_module):
                with patch(
                    "paybond_kit.pydantic_ai.config.is_pydantic_ai_tool",
                    side_effect=lambda v: isinstance(v, _FakeTool),
                ):
                    demo = await run_pydantic_ai_sandbox_demo(
                        host,
                        operation="paid-tool",
                        requested_spend_cents=100,
                        evidence_preset="cost_and_completion",
                    )

    assert demo["authorization"]["allow"] is True
    assert demo["evidence"]["submitted"] is True
    assert demo["tool_result"]["cost_cents"] == 100
    host.guardrails.submit_sandbox_evidence.assert_awaited_once()
