"""Persist middleware trace events for agent run follow-up commands."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from paybond_kit.cli.agent_run_store import agent_run_file_path, agent_runs_dir
from paybond_kit.cli.core import CliError

PaybondTraceSink = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class PersistedAgentRunTrace:
    run_id: str
    intent_id: str
    trace_events: list[dict[str, Any]]
    updated_at: str


def agent_run_trace_file_path(cwd: str | Path, run_id: str) -> Path:
    return agent_run_file_path(Path(cwd), run_id).with_suffix(".trace.json")


def load_agent_run_trace_if_exists(cwd: str | Path, run_id: str) -> PersistedAgentRunTrace | None:
    path = agent_run_trace_file_path(cwd, run_id)
    if not path.is_file():
        return None
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise CliError(
            f"invalid run trace at {path}",
            category="validation",
            code="cli.agent.invalid_run_trace",
        )
    return PersistedAgentRunTrace(
        run_id=str(parsed.get("run_id", run_id)),
        intent_id=str(parsed.get("intent_id", "")),
        trace_events=list(parsed.get("trace_events") or []),
        updated_at=str(parsed.get("updated_at", "")),
    )


def load_agent_run_trace(cwd: str | Path, run_id: str) -> PersistedAgentRunTrace:
    stored = load_agent_run_trace_if_exists(cwd, run_id)
    if stored is None:
        raise CliError(
            f'no trace events for run "{run_id}"; run paybond agent tool execute first',
            category="validation",
            code="cli.agent.trace_not_found",
            exit_code=1,
            details={"run_id": run_id, "path": str(agent_run_trace_file_path(cwd, run_id))},
        )
    return stored


def persist_agent_run_trace_events(
    cwd: str | Path,
    run_id: str,
    events: list[dict[str, Any]],
    intent_id: str = "",
) -> str:
    path = agent_run_trace_file_path(cwd, run_id)
    agent_runs_dir(Path(cwd)).mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id.strip(),
        "intent_id": intent_id,
        "trace_events": list(events),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    path.write_text(f"{json.dumps(payload, indent=2)}\n", encoding="utf-8")
    path.chmod(0o600)
    return str(path)


def append_agent_run_trace_event(
    cwd: str | Path,
    run_id: str,
    event: dict[str, Any],
    intent_id: str | None = None,
) -> None:
    existing = load_agent_run_trace_if_exists(cwd, run_id)
    trace_events = [*((existing.trace_events if existing else [])), event]
    resolved_intent = intent_id or (existing.intent_id if existing else "")
    persist_agent_run_trace_events(cwd, run_id, trace_events, resolved_intent)


def create_agent_run_trace_sink(
    cwd: str | Path,
    run_id: str,
    *,
    intent_id: str | None = None,
    forward: PaybondTraceSink | None = None,
) -> PaybondTraceSink:
    def sink(event: dict[str, Any]) -> None:
        append_agent_run_trace_event(cwd, run_id, event, intent_id)
        if forward is not None:
            forward(event)

    return sink


def resolve_agent_run_trace_sink(
    cwd: str | Path,
    run_id: str,
    intent_id: str | None = None,
    forward: PaybondTraceSink | None = None,
    gateway: PaybondTraceSink | None = None,
) -> PaybondTraceSink:
    sinks: list[PaybondTraceSink] = []
    if gateway is not None:
        sinks.append(gateway)
    if forward is not None:
        sinks.append(forward)
    composed: PaybondTraceSink | None
    if not sinks:
        composed = None
    elif len(sinks) == 1:
        composed = sinks[0]
    else:
        def composed_sink(event: dict[str, Any]) -> None:
            for sink in sinks:
                sink(event)

        composed = composed_sink
    return create_agent_run_trace_sink(cwd, run_id, intent_id=intent_id, forward=composed)
