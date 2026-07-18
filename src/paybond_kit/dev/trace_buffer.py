"""In-memory dev trace buffer and audit log helpers."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

DEV_TRACE_DEFAULT_PORT = 9477
DEV_AUDIT_DIR = ".paybond"
DEV_AUDIT_FILE = f"{DEV_AUDIT_DIR}/dev-audit.jsonl"
DEV_TRACE_FILE = f"{DEV_AUDIT_DIR}/dev-trace.jsonl"
DEV_DEFAULT_POLICY_FILE = "paybond.policy.yaml"
DEV_DEFAULT_PRESET = "travel"
_MAX_TRACE_EVENTS = 100

DevTraceStepPhase = Literal["agent", "tool", "authorize", "evidence", "result"]

_trace_events: list[dict[str, Any]] = []
_active_dev_trace_collector: "DevTraceCollector | None" = None
_active_dev_trace_collector_cwd: str | None = None


def read_dev_trace_events_from_disk(cwd: str | Path) -> list[dict[str, Any]]:
    path = Path(cwd) / DEV_TRACE_FILE
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def _merge_dev_trace_events(
    from_disk: list[dict[str, Any]],
    from_memory: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for event in from_disk:
        by_id[str(event.get("id") or "")] = event
    for event in from_memory:
        by_id[str(event.get("id") or "")] = event
    return sorted(by_id.values(), key=lambda event: str(event.get("recorded_at") or ""))


def list_dev_trace_events(cwd: str | Path | None = None) -> list[dict[str, Any]]:
    memory = list(_trace_events)
    if cwd is None:
        return memory
    return _merge_dev_trace_events(read_dev_trace_events_from_disk(cwd), memory)


def _trim_dev_trace_file(path: Path) -> None:
    if not path.is_file():
        return
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) <= _MAX_TRACE_EVENTS:
        return
    path.write_text("\n".join(lines[-_MAX_TRACE_EVENTS:]) + "\n", encoding="utf-8")


def _persist_dev_trace_event_sync(cwd: str | Path, event: dict[str, Any]) -> None:
    root = Path(cwd)
    audit_dir = root / DEV_AUDIT_DIR
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = root / DEV_TRACE_FILE
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{json.dumps(event)}\n")
    _trim_dev_trace_file(path)


def find_dev_trace_event_for_run(run_id: str) -> dict[str, Any] | None:
    normalized = run_id.strip()
    for event in reversed(_trace_events):
        if event.get("run_id") == normalized or event.get("id") == normalized:
            return event
    return None


def clear_dev_trace_events() -> None:
    """Reset in-memory dev trace state (tests and local dashboard restarts)."""
    global _active_dev_trace_collector, _active_dev_trace_collector_cwd
    _trace_events.clear()
    _active_dev_trace_collector = None
    _active_dev_trace_collector_cwd = None


def append_dev_trace_event(event: dict[str, Any], cwd: str | Path | None = None) -> None:
    _trace_events.append(event)
    while len(_trace_events) > _MAX_TRACE_EVENTS:
        _trace_events.pop(0)
    if cwd is not None:
        _persist_dev_trace_event_sync(cwd, event)


def dev_trace_url(port: int = DEV_TRACE_DEFAULT_PORT, run_id: str | None = None) -> str:
    base = f"http://localhost:{port}"
    if run_id:
        return f"{base}/runs/{run_id}"
    return base


def build_dev_startup_banner_lines(port: int = DEV_TRACE_DEFAULT_PORT) -> list[str]:
    return [
        "✓ Sandbox capability (or: offline mock)",
        "✓ Settlement simulator",
        f"✓ Trace dashboard → {dev_trace_url(port)}",
        f"✓ Audit log → {DEV_AUDIT_FILE}",
    ]


def dev_trace_has_credentials(
    *,
    cwd: str | Path | None = None,
    env_file: str | None = None,
) -> bool:
    if (os.environ.get("PAYBOND_API_KEY") or "").strip():
        return True
    from paybond_kit.cli.core import DEFAULT_ENV_FILE, read_env_file_value

    resolved_env_file = (env_file or os.environ.get("PAYBOND_ENV_FILE") or DEFAULT_ENV_FILE).strip()
    base = Path(cwd) if cwd is not None else Path.cwd()
    env_path = Path(resolved_env_file) if Path(resolved_env_file).is_absolute() else base / resolved_env_file
    try:
        body = env_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(read_env_file_value(body, "PAYBOND_API_KEY"))


def append_dev_audit_log(cwd: Path, entry: dict[str, Any]) -> str:
    audit_dir = cwd / DEV_AUDIT_DIR
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = cwd / DEV_AUDIT_FILE
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{json.dumps(entry)}\n")
    return str(path)


def dev_trace_steps_from_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    first_at = str(events[0].get("recorded_at") or datetime.now(timezone.utc).isoformat())
    authorized_ceiling_cents: int | None = None

    for event in events:
        event_type = event.get("type")
        recorded_at = str(event.get("recorded_at") or first_at)
        if event_type == "tool_selected":
            steps.append(
                {
                    "phase": "tool",
                    "label": f"Tool call: {event.get('tool_name')}",
                    "recorded_at": recorded_at,
                    "detail": {
                        "operation": event.get("operation"),
                        "tool_call_id": event.get("tool_call_id"),
                    },
                }
            )
        elif event_type == "spend_authorized":
            amount_cents = int(event.get("amount_cents") or 0)
            authorized_ceiling_cents = amount_cents
            steps.append(
                {
                    "phase": "authorize",
                    "label": (
                        f"Paybond authorized up to ${amount_cents / 100:.2f} "
                        f"({amount_cents:,} cents)"
                    ),
                    "recorded_at": recorded_at,
                    "detail": {
                        "audit_id": event.get("audit_id"),
                        "decision_id": event.get("decision_id"),
                        "amount_cents": amount_cents,
                    },
                }
            )
        elif event_type == "spend_denied":
            steps.append(
                {
                    "phase": "authorize",
                    "label": f"Spend denied: {event.get('message')}",
                    "recorded_at": recorded_at,
                    "detail": {"audit_id": event.get("audit_id"), "code": event.get("code")},
                }
            )
        elif event_type == "approval_required":
            steps.append(
                {
                    "phase": "authorize",
                    "label": f"Approval required: {event.get('message')}",
                    "recorded_at": recorded_at,
                    "detail": {"audit_id": event.get("audit_id"), "code": event.get("code")},
                }
            )
        elif event_type == "tool_executed":
            duration_ms = int(event.get("duration_ms") or 0)
            steps.append(
                {
                    "phase": "result",
                    "label": f"Tool executed ({duration_ms}ms)",
                    "recorded_at": recorded_at,
                    "detail": {"duration_ms": duration_ms},
                }
            )
        elif event_type == "evidence_submitted":
            predicate_passed = event.get("predicate_passed")
            reported_cost_cents = event.get("reported_cost_cents")
            if isinstance(reported_cost_cents, int) and not isinstance(reported_cost_cents, bool):
                outcome = "predicate failed" if predicate_passed is False else "predicate evaluated"
                label = (
                    f"Evidence submitted (reported cost ${reported_cost_cents / 100:.2f} "
                    f"({reported_cost_cents:,} cents); {outcome})"
                )
            else:
                label = (
                    "Evidence submitted (predicate failed)"
                    if predicate_passed is False
                    else "Evidence submitted"
                )
            steps.append(
                {
                    "phase": "evidence",
                    "label": label,
                    "recorded_at": recorded_at,
                    "detail": {
                        "evidence_preset": event.get("evidence_preset"),
                        "reported_cost_cents": reported_cost_cents,
                        "sandbox_lifecycle_status": event.get("sandbox_lifecycle_status"),
                        "predicate_passed": predicate_passed,
                    },
                }
            )
            lifecycle_status = event.get("sandbox_lifecycle_status")
            if lifecycle_status:
                # Variable-cost settlement resizes to the validated reported cost: capture the
                # reported cost and release the unused authorization. A failed predicate releases
                # the full authorization. Absent reported cost or ceiling preserves fixed-price
                # wording.
                captured_cents: int | None
                if authorized_ceiling_cents is None:
                    captured_cents = None
                elif predicate_passed is False:
                    captured_cents = 0
                elif isinstance(reported_cost_cents, int) and not isinstance(
                    reported_cost_cents, bool
                ):
                    captured_cents = min(reported_cost_cents, authorized_ceiling_cents)
                else:
                    captured_cents = None
                unused_cents = (
                    None
                    if authorized_ceiling_cents is None or captured_cents is None
                    else authorized_ceiling_cents - captured_cents
                )
                if captured_cents is None or unused_cents is None:
                    label = f"Settlement: {lifecycle_status}"
                else:
                    label = (
                        f"Settlement: {lifecycle_status} — captured "
                        f"${captured_cents / 100:.2f} ({captured_cents:,} cents); unused "
                        f"${unused_cents / 100:.2f} ({unused_cents:,} cents) released"
                    )
                steps.append(
                    {
                        "phase": "result",
                        "label": label,
                        "recorded_at": recorded_at,
                        "detail": {
                            "sandbox_lifecycle_status": lifecycle_status,
                            "authorized_amount_cents": authorized_ceiling_cents,
                            "captured_released_amount_cents": captured_cents,
                            "unused_authorization_cents": unused_cents,
                        },
                    }
                )
        elif event_type == "spend_finalized" and event.get("status") == "consumed":
            steps.append(
                {
                    "phase": "result",
                    "label": "Spend authorization consumed",
                    "recorded_at": recorded_at,
                    "detail": {"status": event.get("status")},
                }
            )

    return steps


def _summarize_trace_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    tool_selected = next((event for event in events if event.get("type") == "tool_selected"), None)
    spend_authorized = next((event for event in events if event.get("type") == "spend_authorized"), None)
    evidence_submitted = next(
        (event for event in events if event.get("type") == "evidence_submitted"),
        None,
    )
    spend_denied = any(
        event.get("type") in {"spend_denied", "approval_required"} for event in events
    )
    return {
        "operation": (tool_selected or spend_authorized or {}).get("operation") or "",
        "run_id": (tool_selected or spend_authorized or {}).get("run_id") or f"trace-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        "requested_spend_cents": spend_authorized.get("amount_cents") if spend_authorized else None,
        "authorized": bool(spend_authorized) and not spend_denied,
        "evidence_submitted": bool(evidence_submitted),
        "sandbox_lifecycle_status": evidence_submitted.get("sandbox_lifecycle_status")
        if evidence_submitted
        else None,
    }


class DevTraceCollector:
    def __init__(self, *, preset: str, intent_id: str | None = None) -> None:
        self._preset = preset
        self._intent_id = intent_id
        self._events: list[dict[str, Any]] = []

    def sink(self, event: dict[str, Any]) -> None:
        self._events.append(event)

    def finalize(self, result_body: dict[str, Any] | None = None, cwd: str | Path | None = None) -> dict[str, Any] | None:
        if not self._events:
            return None
        summary = _summarize_trace_events(self._events)
        event = {
            "id": summary["run_id"],
            "recorded_at": self._events[-1].get("recorded_at")
            or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "preset": self._preset,
            "operation": summary["operation"],
            "intent_id": self._intent_id,
            "run_id": summary["run_id"],
            "requested_spend_cents": summary["requested_spend_cents"],
            "authorized": summary["authorized"],
            "evidence_submitted": summary["evidence_submitted"],
            "sandbox_lifecycle_status": summary["sandbox_lifecycle_status"],
            "result_status": result_body.get("status") if result_body else None,
            "cost_cents": result_body.get("cost_cents") if result_body else None,
            "steps": dev_trace_steps_from_events(self._events),
            "trace_events": list(self._events),
        }
        append_dev_trace_event(event, cwd)
        return event


def activate_dev_trace_collector(
    *,
    preset: str,
    intent_id: str | None = None,
    cwd: str | Path | None = None,
) -> None:
    global _active_dev_trace_collector, _active_dev_trace_collector_cwd
    _active_dev_trace_collector = DevTraceCollector(preset=preset, intent_id=intent_id)
    _active_dev_trace_collector_cwd = str(cwd) if cwd is not None else None


def resolve_dev_trace_sink() -> Callable[[dict[str, Any]], None] | None:
    if _active_dev_trace_collector is None:
        return None
    return _active_dev_trace_collector.sink


def finalize_dev_trace_collector(
    result_body: dict[str, Any] | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any] | None:
    global _active_dev_trace_collector, _active_dev_trace_collector_cwd
    if _active_dev_trace_collector is None:
        return None
    event = _active_dev_trace_collector.finalize(
        result_body,
        cwd if cwd is not None else _active_dev_trace_collector_cwd,
    )
    _active_dev_trace_collector = None
    _active_dev_trace_collector_cwd = None
    return event


def record_smoke_trace_event(
    *,
    preset: str,
    bind: dict[str, Any],
    execute: dict[str, Any],
    result_body: dict[str, Any],
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    run_id = str(bind.get("run_id") or "smoke-1")
    recorded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    operation = str(bind.get("operation") or "")
    trace_events = [
        {
            "type": "tool_selected",
            "run_id": run_id,
            "tool_name": operation or "tool",
            "tool_call_id": "smoke-1",
            "operation": operation,
            "recorded_at": recorded_at,
        },
        {
            "type": "spend_authorized",
            "run_id": run_id,
            "tool_call_id": "smoke-1",
            "operation": operation,
            "audit_id": "smoke",
            "amount_cents": int(bind.get("requested_spend_cents") or 0),
            "recorded_at": recorded_at,
        },
        {
            "type": "tool_executed",
            "run_id": run_id,
            "tool_call_id": "smoke-1",
            "operation": operation,
            "duration_ms": 0,
            "recorded_at": recorded_at,
        },
    ]
    if execute.get("evidence_submitted") or execute.get("evidence"):
        trace_events.append(
            {
                "type": "evidence_submitted",
                "run_id": run_id,
                "tool_call_id": "smoke-1",
                "operation": operation,
                "sandbox_lifecycle_status": execute.get("sandbox_lifecycle_status"),
                "reported_cost_cents": result_body.get("cost_cents"),
                "recorded_at": recorded_at,
            }
        )
    event = {
        "id": run_id,
        "recorded_at": recorded_at,
        "preset": preset,
        "operation": operation,
        "intent_id": bind.get("intent_id"),
        "run_id": run_id,
        "requested_spend_cents": bind.get("requested_spend_cents"),
        "authorized": True,
        "evidence_submitted": bool(execute.get("evidence_submitted") or execute.get("evidence")),
        "sandbox_lifecycle_status": execute.get("sandbox_lifecycle_status") or bind.get("sandbox_lifecycle_status"),
        "result_status": result_body.get("status"),
        "cost_cents": result_body.get("cost_cents"),
        "steps": dev_trace_steps_from_events(trace_events),
        "trace_events": trace_events,
    }
    append_dev_trace_event(event, cwd)
    return event
