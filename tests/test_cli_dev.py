from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from paybond_kit.cli.router import run_cli
from paybond_kit.dev.trace_buffer import list_dev_trace_events, record_smoke_trace_event
from paybond_kit.dev.trace_server import start_dev_trace_server
from .cli_agent_gateway_mock import LIVE_RAW_KEY, SANDBOX_RAW_KEY, install_agent_gateway_mock


@pytest.mark.asyncio
async def test_dev_smoke_wraps_travel_preset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)
    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "dev", "smoke"], stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is True
    assert payload["data"]["bind"]["operation"] == "travel.book_hotel"
    trace_url = str(payload["data"]["trace_url"])
    assert "/runs/" in trace_url
    run_id = trace_url.rsplit("/", 1)[-1]
    events = list_dev_trace_events()
    assert any(event.get("id") == run_id or event.get("run_id") == run_id for event in events)
    assert payload["data"]["audit_log"].endswith("dev-audit.jsonl")
    assert any("Policy loaded (travel)" in line for line in payload["data"]["checklist_lines"])


@pytest.mark.asyncio
async def test_dev_smoke_renders_checklist_table(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(["--no-color", "dev", "smoke"], stdout=stdout)
    assert code == 0
    output = stdout.getvalue()
    assert "Policy loaded (travel)" in output
    assert "travel.book_hotel" in output
    assert "Success" in output
    assert '"bind"' not in output


@pytest.mark.asyncio
async def test_dev_loop_runs_policy_validate_and_smoke(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "dev", "loop", "--no-login"], stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is True
    assert [step["name"] for step in payload["data"]["steps"]] == [
        "login",
        "policy_init",
        "validate_tools",
        "smoke",
    ]
    assert payload["data"]["steps"][0]["skipped"] is True
    assert payload["data"]["steps"][2]["ok"] is True
    assert payload["data"]["smoke"]["bind"]["operation"] == "travel.book_hotel"
    assert payload["data"]["banner_lines"] == [
        "✓ Sandbox capability (or: offline mock)",
        "✓ Settlement simulator",
        "✓ Trace dashboard → http://localhost:9477",
        "✓ Audit log → .paybond/dev-audit.jsonl",
    ]
    assert any("Trace → http://localhost:" in line for line in payload["data"]["checklist_lines"])


@pytest.mark.asyncio
async def test_dev_smoke_offline_without_api_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PAYBOND_API_KEY", raising=False)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "dev", "smoke", "--offline"], stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is True
    assert payload["data"]["offline"] is True
    assert payload["data"]["bind"]["operation"] == "travel.book_hotel"


@pytest.mark.asyncio
async def test_dev_loop_offline_skips_login(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PAYBOND_API_KEY", raising=False)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "dev", "loop", "--offline"], stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is True
    assert payload["data"]["offline"] is True
    assert payload["data"]["steps"][0]["skipped"] is True
    assert "offline" in payload["data"]["steps"][0]["message"]
    assert payload["data"]["banner_lines"][0] == "✓ Sandbox capability (or: offline mock)"
    assert any("Trace → http://localhost:" in line for line in payload["data"]["checklist_lines"])


@pytest.mark.asyncio
async def test_dev_smoke_offline_rejects_production_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", LIVE_RAW_KEY)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "dev", "smoke", "--offline"], stdout=stdout)
    assert code != 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert payload["error"]["code"] == "cli.dev.offline_production_key"


@pytest.mark.asyncio
async def test_dev_loop_offline_rejects_production_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", LIVE_RAW_KEY)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "dev", "loop", "--offline"], stdout=stdout)
    assert code != 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert payload["error"]["code"] == "cli.dev.offline_production_key"


@pytest.mark.asyncio
async def test_dev_smoke_offline_rejects_production_api_key_from_env_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PAYBOND_API_KEY", raising=False)
    (tmp_path / ".env.local").write_text(f"PAYBOND_API_KEY={LIVE_RAW_KEY}\n", encoding="utf-8")

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "dev", "smoke", "--offline"], stdout=stdout)
    assert code != 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert payload["error"]["code"] == "cli.dev.offline_production_key"


def test_dev_trace_server_serves_buffered_events() -> None:
    import threading
    import urllib.request

    record_smoke_trace_event(
        preset="travel",
        bind={
            "run_id": "run-trace-test",
            "operation": "travel.book_hotel",
            "requested_spend_cents": 18_700,
        },
        execute={"evidence_submitted": True},
        result_body={"status": "completed", "cost_cents": 18_700},
    )

    server = start_dev_trace_server(port=0)
    host, port, *_ = server.server_address
    assert isinstance(port, int)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/api/events", timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["events"]
        assert payload["events"][-1]["operation"] == "travel.book_hotel"
        assert "has_credentials" in payload
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
