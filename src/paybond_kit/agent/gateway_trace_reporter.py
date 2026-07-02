"""Fire-and-forget Gateway middleware trace reporter for console agent-runs."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

GatewayJsonWriter = Callable[[str, str, dict[str, Any]], Awaitable[Any]]
PaybondTraceSink = Callable[[dict[str, Any]], None]

_TRACE_EVENT_CAMEL_KEYS: dict[str, str] = {
    "run_id": "runId",
    "tool_name": "toolName",
    "tool_call_id": "toolCallId",
    "recorded_at": "recordedAt",
    "audit_id": "auditId",
    "decision_id": "decisionId",
    "amount_cents": "amountCents",
    "duration_ms": "durationMs",
    "evidence_id": "evidenceId",
    "preset_id": "presetId",
    "evidence_preset": "evidencePreset",
    "sandbox_lifecycle_status": "sandboxLifecycleStatus",
    "predicate_passed": "predicatePassed",
}

# Matches PaybondTraceEvent fields emitted by the interceptor; unknown keys are dropped.
_TRACE_EVENT_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "type",
        "run_id",
        "tool_name",
        "tool_call_id",
        "operation",
        "recorded_at",
        "audit_id",
        "decision_id",
        "amount_cents",
        "duration_ms",
        "evidence_id",
        "preset_id",
        "evidence_preset",
        "sandbox_lifecycle_status",
        "predicate_passed",
        "message",
        "code",
        "status",
    }
)


@dataclass(frozen=True)
class AgentRunUpsertInput:
    """Gateway agent-run metadata registered before trace events are appended."""

    intent_id: str
    operation: str = ""
    sandbox: bool = False
    allowed_tools: list[str] = field(default_factory=list)
    completion_preset: str = ""


def trace_event_to_gateway_wire(event: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize Kit trace dicts (snake_case) to Gateway wire shape (camelCase).

    Only allowlisted fields are forwarded; unexpected keys are dropped so a
    compromised or over-broad trace sink cannot exfiltrate arbitrary payloads.
    """
    out: dict[str, Any] = {}
    for key, value in event.items():
        if key not in _TRACE_EVENT_ALLOWED_KEYS:
            continue
        wire_key = _TRACE_EVENT_CAMEL_KEYS.get(key, key)
        out[wire_key] = value
    return out


class GatewayAgentRunTraceReporter:
    """
    Gateway-backed middleware trace reporter for tenant console agent-runs view.

    Failures are swallowed so middleware execution is never blocked on telemetry.
    """

    def __init__(self, write_json: GatewayJsonWriter, run_id: str) -> None:
        trimmed = run_id.strip()
        if not trimmed:
            raise ValueError("GatewayAgentRunTraceReporter requires a non-empty run_id")
        self._write_json = write_json
        self._run_id = trimmed
        self._pending: list[asyncio.Task[None]] = []
        self._registered = False

    def _schedule(self, coro: Awaitable[Any]) -> None:
        async def _swallow() -> None:
            try:
                await coro
            except Exception:
                return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(_swallow())
        self._pending.append(task)
        task.add_done_callback(self._discard_task)

    def _discard_task(self, task: asyncio.Task[None]) -> None:
        try:
            self._pending.remove(task)
        except ValueError:
            return

    def register_run(self, input: AgentRunUpsertInput) -> None:
        """Register run metadata once per bind (idempotent server-side upsert)."""
        if self._registered:
            return
        self._registered = True
        body = {
            "intent_id": input.intent_id,
            "operation": input.operation,
            "sandbox": input.sandbox,
            "allowed_tools": list(input.allowed_tools),
            "completion_preset": input.completion_preset,
        }
        path = f"/v1/agent-runs/{quote(self._run_id, safe='')}"
        self._schedule(self._write_json("PUT", path, body))

    def report_event(self, event: Mapping[str, Any]) -> None:
        """Append one middleware trace event to the Gateway run timeline."""
        wire_event = trace_event_to_gateway_wire(event)
        path = f"/v1/agent-runs/{quote(self._run_id, safe='')}/trace-events"
        self._schedule(self._write_json("POST", path, {"events": [wire_event]}))

    def create_sink(self, input: AgentRunUpsertInput) -> PaybondTraceSink:
        """Register run metadata and return a trace sink that forwards events to Gateway."""
        self.register_run(input)
        return self.report_event

    async def flush(self) -> None:
        """Await in-flight Gateway writes (CLI shutdown hooks)."""
        pending = list(self._pending)
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)
        self._pending.clear()


def create_gateway_agent_run_trace_sink(paybond: Any, run_id: str) -> PaybondTraceSink:
    """Forward middleware trace events to Gateway for console agent-runs view."""
    reporter = paybond.harbor.create_agent_run_trace_reporter(run_id)
    return reporter.report_event


def register_gateway_agent_run(
    paybond: Any,
    run: Any,
    *,
    completion_preset: str | None = None,
) -> None:
    """Register run metadata on Gateway after a successful bind."""
    sandbox = run.binding.sandbox
    meta = AgentRunUpsertInput(
        intent_id=str(run.intent_id),
        operation=sandbox.operation if sandbox else (run.allowed_tools[0] if run.allowed_tools else ""),
        sandbox=bool(sandbox),
        allowed_tools=list(run.allowed_tools),
        completion_preset=completion_preset or "",
    )
    paybond.harbor.create_agent_run_trace_reporter(run.run_id).register_run(meta)
