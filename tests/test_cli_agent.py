from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from paybond_kit.agent.registry_file import parse_agent_registry_text, validate_agent_registry_document
from paybond_kit.cli.router import run_cli
from .cli_agent_gateway_mock import (
    ATTACH_INTENT_ID,
    LIVE_RAW_KEY,
    PRODUCTION_ATTACH_SEEDS,
    SANDBOX_RAW_KEY,
    SMOKE_INTENT_ID,
    install_agent_gateway_mock,
)


def test_validate_agent_registry_document_accepts_valid_yaml() -> None:
    doc = parse_agent_registry_text(
        """
version: 1
default_deny: true
tools:
  travel.book_hotel:
    side_effecting: true
    evidence_preset: cost_and_completion
  search.web:
    side_effecting: false
"""
    )
    validation = validate_agent_registry_document(doc)
    assert validation["ok"] is True
    assert validation["side_effecting_count"] == 1


@pytest.mark.asyncio
async def test_agent_registry_validate_cli(tmp_path: Path) -> None:
    registry_path = tmp_path / "paybond.agent.registry.yaml"
    registry_path.write_text(
        """version: 1
default_deny: true
tools:
  paid-tool:
    side_effecting: true
    evidence_preset: cost_and_completion
""",
        encoding="utf-8",
    )
    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "agent", "registry", "validate", "--file", str(registry_path)],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["ok"] is True


@pytest.mark.asyncio
async def test_agent_sandbox_smoke_preset_travel_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "sandbox",
            "smoke",
            "--preset",
            "travel",
            "--result-body",
            '{"status":"completed","cost_cents":18700}',
        ],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 0
    assert payload["data"]["bind"]["operation"] == "travel.book_hotel"
    assert payload["data"]["bind"]["policy_file"].endswith("travel.yaml")
    assert payload["data"]["execute"]["evidence"]["submitted"] is True
    assert payload["data"]["checklist_lines"] == [
        "✓ Policy loaded (travel)",
        "✓ Sandbox intent created",
        "✓ Tool call: travel.book_hotel",
        "✓ Spend approved ($187.00)",
        "✓ Evidence validated (cost_and_completion)",
        "✓ Settlement simulated",
        "✓ Trace → http://localhost:9477/runs/" + payload["data"]["bind"]["run_id"],
        "✓ Console → http://127.0.0.1:3000/console/operations/intents/"
        + payload["data"]["bind"]["intent_id"],
        "✓ Replay → http://127.0.0.1:3000/demo/agent-trace?intent="
        + payload["data"]["bind"]["intent_id"],
        "Success",
    ]
    assert payload["data"]["trace_url"].startswith("http://localhost:9477/runs/")
    assert "/console/operations/intents/" in payload["data"]["console_url"]
    assert "/demo/agent-trace?intent=" in payload["data"]["agent_trace_url"]


@pytest.mark.asyncio
async def test_agent_sandbox_smoke_preset_travel_solution_defaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "agent", "sandbox", "smoke", "--preset", "travel"],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 0
    assert payload["data"]["bind"]["operation"] == "travel.book_hotel"
    assert payload["data"]["execute"]["evidence"]["submitted"] is True


@pytest.mark.asyncio
async def test_agent_sandbox_smoke_preset_travel_table_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--no-color",
            "agent",
            "sandbox",
            "smoke",
            "--preset",
            "travel",
            "--result-body",
            '{"status":"completed","cost_cents":18700}',
        ],
        stdout=stdout,
    )
    output = stdout.getvalue()
    assert code == 0
    assert "Policy loaded (travel)" in output
    assert "Tool call: travel.book_hotel" in output
    assert "Spend approved ($187.00)" in output
    assert "Evidence validated (cost_and_completion)" in output
    assert "Settlement simulated" in output
    assert "Success" in output


@pytest.mark.asyncio
async def test_agent_sandbox_smoke_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "sandbox",
            "smoke",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--evidence-preset",
            "cost_and_completion",
            "--result-body",
            '{"status":"ok","cost_cents":100}',
        ],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 0
    assert payload["data"]["bind"]["intent_id"] == SMOKE_INTENT_ID
    assert payload["data"]["execute"]["evidence"]["submitted"] is True


@pytest.mark.asyncio
async def test_agent_run_bind_status_execute_validate_flow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    bind_stdout = io.StringIO()
    bind_code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "run",
            "bind",
            "--sandbox",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--completion-preset",
            "cost_and_completion",
            "--write-env",
            "--env-file",
            ".env.agent",
        ],
        stdout=bind_stdout,
    )
    bind_payload = json.loads(bind_stdout.getvalue())
    assert bind_code == 0
    run_id = bind_payload["data"]["run_id"]
    env_text = (tmp_path / ".env.agent").read_text(encoding="utf-8")
    assert f"PAYBOND_RUN_ID={run_id}" in env_text
    assert f"PAYBOND_INTENT_ID={SMOKE_INTENT_ID}" in env_text

    status_stdout = io.StringIO()
    status_code = await run_cli(
        ["--format", "json", "agent", "run", "status", "--run-id", run_id],
        stdout=status_stdout,
    )
    status_payload = json.loads(status_stdout.getvalue())
    assert status_code == 0
    assert status_payload["data"]["intent_id"] == SMOKE_INTENT_ID

    validate_stdout = io.StringIO()
    validate_code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "tool",
            "validate",
            "--run-id",
            run_id,
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
        ],
        stdout=validate_stdout,
    )
    validate_payload = json.loads(validate_stdout.getvalue())
    assert validate_code == 0
    assert validate_payload["data"]["authorization"]["allow"] is True

    execute_stdout = io.StringIO()
    execute_code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "tool",
            "execute",
            "--run-id",
            run_id,
            "--operation",
            "paid-tool",
            "--tool-call-id",
            "call-flow-1",
            "--result-body",
            '{"status":"ok","cost_cents":100}',
        ],
        stdout=execute_stdout,
    )
    execute_payload = json.loads(execute_stdout.getvalue())
    assert execute_code == 0
    assert execute_payload["data"]["evidence"]["submitted"] is True


@pytest.mark.asyncio
async def test_agent_run_bind_production_attach_requires_evidence_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", LIVE_RAW_KEY)
    install_agent_gateway_mock(monkeypatch, environment="live")

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "run",
            "bind",
            "--production",
            "--attach-intent-id",
            ATTACH_INTENT_ID,
            "--capability-token",
            "cap-prod-1",
        ],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 1
    assert payload["error"]["code"] == "cli.agent.production_evidence_incomplete"


@pytest.mark.asyncio
async def test_agent_run_bind_production_attach_persists_production_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", LIVE_RAW_KEY)
    install_agent_gateway_mock(monkeypatch, environment="live")

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "run",
            "bind",
            "--production",
            "--attach-intent-id",
            ATTACH_INTENT_ID,
            "--capability-token",
            "cap-prod-1",
            "--payee-did",
            PRODUCTION_ATTACH_SEEDS["payee_did"],
            "--payee-signing-seed-hex",
            PRODUCTION_ATTACH_SEEDS["payee_signing_seed_hex"],
            "--agent-recognition-key-id",
            PRODUCTION_ATTACH_SEEDS["agent_recognition_key_id"],
            "--agent-recognition-signing-seed-hex",
            PRODUCTION_ATTACH_SEEDS["agent_recognition_signing_seed_hex"],
        ],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 0
    run_id = payload["data"]["run_id"]
    stored = json.loads((tmp_path / ".paybond" / "runs" / f"{run_id}.json").read_text(encoding="utf-8"))
    assert stored["intent_id"] == ATTACH_INTENT_ID
    assert stored["sandbox"] is False
    assert stored["production_evidence"] == {
        "payee_did": PRODUCTION_ATTACH_SEEDS["payee_did"],
        "agent_recognition_key_id": PRODUCTION_ATTACH_SEEDS["agent_recognition_key_id"],
    }
    assert "payee_signing_seed_hex" not in stored["production_evidence"]


@pytest.mark.asyncio
async def test_agent_run_bind_rejects_live_key_without_production(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", LIVE_RAW_KEY)
    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "run",
            "bind",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
        ],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 1
    assert payload["error"]["code"] == "cli.agent.production_required"


@pytest.mark.asyncio
async def test_agent_tool_execute_denied_when_verify_rejects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch, allow_verify=False)

    bind_stdout = io.StringIO()
    await run_cli(
        [
            "--format",
            "json",
            "agent",
            "run",
            "bind",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--completion-preset",
            "cost_and_completion",
        ],
        stdout=bind_stdout,
    )
    run_id = json.loads(bind_stdout.getvalue())["data"]["run_id"]

    execute_stdout = io.StringIO()
    execute_code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "tool",
            "execute",
            "--run-id",
            run_id,
            "--operation",
            "paid-tool",
            "--tool-call-id",
            "call-deny",
            "--result-body",
            '{"status":"ok","cost_cents":100}',
        ],
        stdout=execute_stdout,
    )
    execute_payload = json.loads(execute_stdout.getvalue())
    assert execute_code == 3
    assert execute_payload["error"]["code"] == "cli.agent.authorization_denied"


@pytest.mark.asyncio
async def test_doctor_agent_includes_middleware_smoke_check(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)
    (tmp_path / ".env.local").write_text(f"PAYBOND_API_KEY={SANDBOX_RAW_KEY}\n", encoding="utf-8")

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "doctor", "--agent", "--env-file", ".env.local"],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    names = {check["name"] for check in payload["data"]["checks"]}
    assert "agent_middleware_smoke" in names
    smoke = next(item for item in payload["data"]["checks"] if item["name"] == "agent_middleware_smoke")
    assert smoke["ok"] is True
    assert code in (0, 1)


@pytest.mark.asyncio
async def test_agent_demo_langgraph_smoke_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pytest.importorskip("langgraph")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "demo",
            "langgraph",
            "smoke",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--evidence-preset",
            "cost_and_completion",
        ],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 0
    assert payload["data"]["authorization"]["allow"] is True
    assert payload["data"]["tool_message"]["status"] == "success"
    assert payload["data"]["bind"]["intent_id"] == SMOKE_INTENT_ID


@pytest.mark.asyncio
async def test_agent_demo_generic_smoke_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "demo",
            "generic",
            "smoke",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--evidence-preset",
            "cost_and_completion",
        ],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 0
    assert payload["data"]["authorization"]["allow"] is True
    assert payload["data"]["execute"]["tool_result"] is not None
    assert payload["data"]["bind"]["intent_id"] == SMOKE_INTENT_ID


@pytest.mark.asyncio
async def test_agent_demo_claude_agents_smoke_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pytest.importorskip("claude_agent_sdk")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", SANDBOX_RAW_KEY)
    install_agent_gateway_mock(monkeypatch)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "agent",
            "demo",
            "claude-agents",
            "smoke",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--evidence-preset",
            "cost_and_completion",
        ],
        stdout=stdout,
    )
    payload = json.loads(stdout.getvalue())
    assert code == 0
    assert payload["data"]["evidence"]["submitted"] is True
    assert payload["data"]["tool_result"] is not None
    assert payload["data"]["bind"]["intent_id"] == SMOKE_INTENT_ID
