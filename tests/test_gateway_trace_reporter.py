"""Tests for Gateway agent-run trace reporter."""

from __future__ import annotations

from typing import Any

import pytest

from paybond_kit.agent.gateway_trace_reporter import (
    AgentRunUpsertInput,
    GatewayAgentRunTraceReporter,
    create_gateway_agent_run_trace_sink,
    register_gateway_agent_run,
    trace_event_to_gateway_wire,
)


@pytest.mark.asyncio
async def test_gateway_trace_reporter_registers_run_and_posts_events() -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    async def write_json(method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        calls.append((method, path, body))
        return {}

    reporter = GatewayAgentRunTraceReporter(write_json, "00000000-0000-4000-8000-000000000001")
    sink = reporter.create_sink(
        AgentRunUpsertInput(
            intent_id="intent-1",
            operation="paid-tool",
            sandbox=False,
            allowed_tools=["paid-tool"],
            completion_preset="cost_and_completion",
        )
    )
    sink(
        {
            "type": "tool_selected",
            "run_id": "00000000-0000-4000-8000-000000000001",
            "tool_name": "paid-tool",
            "tool_call_id": "call-1",
            "operation": "paid-tool",
            "recorded_at": "2026-07-01T12:00:00Z",
        }
    )
    await reporter.flush()

    assert calls[0][0] == "PUT"
    assert calls[0][1] == "/v1/agent-runs/00000000-0000-4000-8000-000000000001"
    assert calls[0][2]["intent_id"] == "intent-1"
    assert calls[1][0] == "POST"
    assert calls[1][1].endswith("/trace-events")
    assert calls[1][2]["events"][0]["toolName"] == "paid-tool"
    assert calls[1][2]["events"][0]["recordedAt"] == "2026-07-01T12:00:00Z"


def test_trace_event_to_gateway_wire_maps_snake_case_fields() -> None:
    wire = trace_event_to_gateway_wire(
        {
            "type": "spend_authorized",
            "run_id": "run-1",
            "tool_call_id": "call-1",
            "amount_cents": 100,
            "audit_id": "audit-1",
        }
    )
    assert wire == {
        "type": "spend_authorized",
        "runId": "run-1",
        "toolCallId": "call-1",
        "amountCents": 100,
        "auditId": "audit-1",
    }


def test_trace_event_to_gateway_wire_drops_unknown_fields() -> None:
    wire = trace_event_to_gateway_wire(
        {
            "type": "tool_selected",
            "run_id": "run-1",
            "tool_name": "paid-tool",
            "capability_token": "secret-token",
            "policy_digest": "abc123",
            "nested": {"payee_signing_seed_hex": "deadbeef"},
        }
    )
    assert wire == {
        "type": "tool_selected",
        "runId": "run-1",
        "toolName": "paid-tool",
    }


@pytest.mark.asyncio
async def test_gateway_trace_reporter_swallows_write_failures() -> None:
    async def write_json(method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError(f"{method} {path} failed")

    reporter = GatewayAgentRunTraceReporter(write_json, "00000000-0000-4000-8000-000000000002")
    reporter.report_event({"type": "tool_selected", "run_id": "00000000-0000-4000-8000-000000000002"})
    await reporter.flush()


def test_create_gateway_agent_run_trace_sink_forwards_events() -> None:
    captured: list[dict[str, Any]] = []

    class _Reporter:
        def report_event(self, event: dict[str, Any]) -> None:
            captured.append(event)

    class _Harbor:
        def create_agent_run_trace_reporter(self, run_id: str) -> _Reporter:
            assert run_id == "run-1"
            return _Reporter()

    class _Paybond:
        harbor = _Harbor()

    sink = create_gateway_agent_run_trace_sink(_Paybond(), "run-1")
    event = {"type": "tool_selected", "run_id": "run-1"}
    sink(event)
    assert captured == [event]


def test_register_gateway_agent_run_upserts_metadata() -> None:
    registered: list[AgentRunUpsertInput] = []

    class _Reporter:
        def register_run(self, input: AgentRunUpsertInput) -> None:
            registered.append(input)

    class _Harbor:
        def create_agent_run_trace_reporter(self, run_id: str) -> _Reporter:
            assert run_id == "run-1"
            return _Reporter()

    class _Paybond:
        harbor = _Harbor()

    class _Sandbox:
        operation = "paid-tool"

    class _Binding:
        sandbox = _Sandbox()

    class _Run:
        run_id = "run-1"
        intent_id = "intent-1"
        allowed_tools = ("paid-tool",)
        binding = _Binding()

    register_gateway_agent_run(_Paybond(), _Run(), completion_preset="cost_and_completion")
    assert registered[0].intent_id == "intent-1"
    assert registered[0].operation == "paid-tool"
    assert registered[0].completion_preset == "cost_and_completion"
