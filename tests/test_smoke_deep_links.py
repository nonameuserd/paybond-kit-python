from __future__ import annotations

from paybond_kit.cli.smoke_deep_links import (
    append_smoke_deep_link_checklist_lines,
    build_agent_sandbox_smoke_deep_links,
)


def test_build_agent_sandbox_smoke_deep_links(monkeypatch) -> None:
    monkeypatch.setenv("PAYBOND_PUBLIC_BASE_URL", "https://paybond.ai")
    monkeypatch.setenv("PAYBOND_CONSOLE_BASE_URL", "https://console.paybond.ai")

    links = build_agent_sandbox_smoke_deep_links(
        {
            "run_id": "smoke-travel-1",
            "intent_id": "00000000-0000-4000-8000-000000000001",
        }
    )

    assert links["trace_url"] == "http://localhost:9477/runs/smoke-travel-1"
    assert links["console_url"] == (
        "https://console.paybond.ai/console/operations/intents/"
        "00000000-0000-4000-8000-000000000001"
    )
    assert links["agent_trace_url"] == (
        "https://paybond.ai/demo/agent-trace?intent=00000000-0000-4000-8000-000000000001"
    )


def test_append_smoke_deep_link_checklist_lines() -> None:
    lines = append_smoke_deep_link_checklist_lines(
        ["✓ Policy loaded (travel)", "Success"],
        {
            "trace_url": "http://localhost:9477/runs/smoke-1",
            "console_url": "https://console.paybond.ai/console/operations/intents/intent-1",
            "agent_trace_url": "https://paybond.ai/demo/agent-trace?intent=intent-1",
        },
        type("Globals", (), {"color": "never", "format": "table"})(),
    )
    assert lines == [
        "✓ Policy loaded (travel)",
        "✓ Trace → http://localhost:9477/runs/smoke-1",
        "✓ Console → https://console.paybond.ai/console/operations/intents/intent-1",
        "✓ Replay → https://paybond.ai/demo/agent-trace?intent=intent-1",
        "Success",
    ]
