from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from paybond_kit.dev.trace_buffer import (
    DEV_TRACE_FILE,
    activate_dev_trace_collector,
    append_dev_trace_event,
    build_dev_startup_banner_lines,
    dev_trace_steps_from_events,
    dev_trace_url,
    finalize_dev_trace_collector,
    list_dev_trace_events,
    read_dev_trace_events_from_disk,
    record_smoke_trace_event,
    resolve_dev_trace_sink,
)


def test_record_smoke_trace_event_includes_steps() -> None:
    before = len(list_dev_trace_events())
    event = record_smoke_trace_event(
        preset="travel",
        bind={
            "run_id": "run-test-1",
            "operation": "travel.book_hotel",
            "intent_id": "intent-1",
            "requested_spend_cents": 20_000,
        },
        execute={"evidence_submitted": True, "sandbox_lifecycle_status": "released"},
        result_body={"status": "completed", "cost_cents": 18_700},
    )
    assert event["id"] == "run-test-1"
    assert event["steps"]
    labels = {step["label"] for step in event["steps"]}
    assert "Paybond authorized up to $200.00 (20,000 cents)" in labels
    assert (
        "Evidence submitted (reported cost $187.00 (18,700 cents); predicate evaluated)"
        in labels
    )
    assert (
        "Settlement: released — captured $187.00 (18,700 cents); unused $13.00 "
        "(1,300 cents) released"
        in labels
    )
    assert len(list_dev_trace_events()) == before + 1


def test_dev_trace_url_with_run_id() -> None:
    assert dev_trace_url(9477, "run-test-1") == "http://localhost:9477/runs/run-test-1"


def test_build_dev_startup_banner_lines() -> None:
    assert build_dev_startup_banner_lines() == [
        "✓ Sandbox capability (or: offline mock)",
        "✓ Settlement simulator",
        "✓ Trace dashboard → http://localhost:9477",
        "✓ Audit log → .paybond/dev-audit.jsonl",
    ]


def test_dev_trace_collector_builds_dashboard_event() -> None:
    activate_dev_trace_collector(preset="travel")
    sink = resolve_dev_trace_sink()
    assert sink is not None
    sink(
        {
            "type": "tool_selected",
            "run_id": "run-collector-1",
            "tool_name": "travel.book_hotel",
            "tool_call_id": "call-1",
            "operation": "travel.book_hotel",
            "recorded_at": "2026-07-01T12:00:00.000Z",
        }
    )
    sink(
        {
            "type": "spend_authorized",
            "run_id": "run-collector-1",
            "tool_call_id": "call-1",
            "operation": "travel.book_hotel",
            "audit_id": "audit-1",
            "amount_cents": 20_000,
            "recorded_at": "2026-07-01T12:00:01.000Z",
        }
    )
    sink(
        {
            "type": "tool_executed",
            "run_id": "run-collector-1",
            "tool_call_id": "call-1",
            "operation": "travel.book_hotel",
            "duration_ms": 12,
            "recorded_at": "2026-07-01T12:00:02.000Z",
        }
    )
    sink(
        {
            "type": "evidence_submitted",
            "run_id": "run-collector-1",
            "tool_call_id": "call-1",
            "operation": "travel.book_hotel",
            "sandbox_lifecycle_status": "released",
            "reported_cost_cents": 18_700,
            "recorded_at": "2026-07-01T12:00:03.000Z",
        }
    )

    event = finalize_dev_trace_collector({"status": "completed", "cost_cents": 18_700})
    assert event is not None
    assert event["id"] == "run-collector-1"
    assert [step["phase"] for step in event["steps"]] == [
        "tool",
        "authorize",
        "result",
        "evidence",
        "result",
    ]
    assert dev_trace_steps_from_events(event["trace_events"])
    labels = {step["label"] for step in event["steps"]}
    assert "Paybond authorized up to $200.00 (20,000 cents)" in labels
    assert (
        "Evidence submitted (reported cost $187.00 (18,700 cents); predicate evaluated)"
        in labels
    )
    assert (
        "Settlement: released — captured $187.00 (18,700 cents); unused $13.00 "
        "(1,300 cents) released"
        in labels
    )


def test_ring_buffer_drops_oldest_events() -> None:
    start = len(list_dev_trace_events())
    for index in range(105):
        append_dev_trace_event(
            {
                "id": f"overflow-{index}",
                "recorded_at": "2026-07-01T12:00:00.000Z",
                "preset": "travel",
                "operation": "travel.book_hotel",
                "authorized": True,
                "evidence_submitted": True,
            }
        )
    events = list_dev_trace_events()
    assert len(events) <= 100
    assert len(events) == min(100, start + 105)


def test_persists_trace_events_to_disk_for_cross_process_dev_trace() -> None:
    with TemporaryDirectory(prefix="paybond-dev-trace-disk-") as cwd:
        record_smoke_trace_event(
            preset="travel",
            bind={
                "run_id": "run-disk-1",
                "operation": "travel.book_hotel",
                "requested_spend_cents": 18_700,
            },
            execute={"evidence_submitted": True, "sandbox_lifecycle_status": "released"},
            result_body={"status": "completed", "cost_cents": 18_700},
            cwd=cwd,
        )
        from_disk = read_dev_trace_events_from_disk(cwd)
        assert len(from_disk) == 1
        assert from_disk[0]["id"] == "run-disk-1"
        assert "authorize" in {step["phase"] for step in from_disk[0]["steps"]}
        assert list_dev_trace_events(cwd)[-1]["id"] == "run-disk-1"
        assert (Path(cwd) / DEV_TRACE_FILE).is_file()
