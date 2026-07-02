from __future__ import annotations

import json
import threading
import urllib.request

from paybond_kit.dev.trace_buffer import record_smoke_trace_event
from paybond_kit.dev.trace_security_headers import DEV_TRACE_SECURITY_HEADERS
from paybond_kit.dev.trace_server import start_dev_trace_server
from paybond_kit.dev.trace_ui import load_dev_trace_dashboard_html


def assert_dev_trace_security_headers(headers: object) -> None:
    for name, value in DEV_TRACE_SECURITY_HEADERS.items():
        assert headers.get(name) == value  # type: ignore[attr-defined]


def test_load_dev_trace_dashboard_html_contains_vertical_timeline() -> None:
    html = load_dev_trace_dashboard_html()
    assert "Paybond dev trace" in html
    assert 'class="v-timeline"' in html
    assert "v-timeline-step" in html
    assert "/api/events" in html


def test_dev_trace_server_serves_dashboard_and_events() -> None:
    record_smoke_trace_event(
        preset="travel",
        bind={
            "run_id": "run-dashboard-test",
            "operation": "travel.book_hotel",
            "requested_spend_cents": 18_700,
        },
        execute={"evidence_submitted": True, "sandbox_lifecycle_status": "released"},
        result_body={"status": "completed", "cost_cents": 18_700},
    )

    server = start_dev_trace_server(port=0)
    host, port, *_ = server.server_address
    assert isinstance(port, int)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/runs/run-dashboard-test", timeout=5) as response:
            assert_dev_trace_security_headers(response.headers)
            html = response.read().decode("utf-8")
        assert "v-timeline" in html
        assert "Recent runs" in html

        with urllib.request.urlopen(f"http://{host}:{port}/api/events", timeout=5) as response:
            assert_dev_trace_security_headers(response.headers)
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["events"]
        assert payload["events"][-1]["operation"] == "travel.book_hotel"
        assert any(step["phase"] == "authorize" for step in payload["events"][-1]["steps"])
        assert "has_credentials" in payload
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
