from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from paybond_kit.cli.router import run_cli

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

INTENT_ID = "550e8400-e29b-41d4-a716-446655440000"
TOOL_CALL_ID = "call_1"


@pytest.mark.asyncio
async def test_receipts_get_agent_resolves_action_receipt_by_intent_and_tool_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    seen: dict[str, object] = {}

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        seen["method"] = method
        seen["path"] = path
        return {"scope": "action", "receipt_id": "digest-1"}

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "receipts",
            "get",
            "--kind",
            "agent",
            "--intent-id",
            INTENT_ID,
            "--tool-call-id",
            TOOL_CALL_ID,
        ],
        stdout=stdout,
    )
    assert code == 0
    assert seen["method"] == "GET"
    assert seen["path"] == f"/protocol/v2/agent-receipts?intent_id={INTENT_ID}&tool_call_id={TOOL_CALL_ID}"
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["scope"] == "action"


@pytest.mark.asyncio
async def test_receipts_get_agent_resolves_intent_terminal_receipt_by_intent_id_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    seen: dict[str, object] = {}

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        seen["method"] = method
        seen["path"] = path
        return {"scope": "intent_terminal", "receipt_id": INTENT_ID}

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "receipts", "get", "--kind", "agent", "--intent-id", INTENT_ID],
        stdout=stdout,
    )
    assert code == 0
    assert seen["path"] == f"/protocol/v2/agent-receipts?intent_id={INTENT_ID}"
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["scope"] == "intent_terminal"


@pytest.mark.asyncio
async def test_receipts_verify_agent_by_intent_id_fetches_then_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    calls: list[tuple[str, str]] = []
    fetched_receipt = {"scope": "action", "receipt_id": "digest-1"}

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        calls.append((method, path))
        if method == "GET":
            return fetched_receipt
        assert path == "/protocol/v2/agent-receipts/verify"
        assert payload == fetched_receipt
        return {"valid": True}

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "receipts",
            "verify",
            "--kind",
            "agent",
            "--intent-id",
            INTENT_ID,
            "--tool-call-id",
            TOOL_CALL_ID,
        ],
        stdout=stdout,
    )
    assert code == 0
    assert calls[0] == ("GET", f"/protocol/v2/agent-receipts?intent_id={INTENT_ID}&tool_call_id={TOOL_CALL_ID}")
    assert calls[1] == ("POST", "/protocol/v2/agent-receipts/verify")
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["valid"] is True


@pytest.mark.asyncio
async def test_receipts_get_by_receipt_id_still_works_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    seen: dict[str, object] = {}

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        seen["path"] = path
        return {"scope": "action"}

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "receipts", "get", "digest-abc", "--kind", "agent"],
        stdout=stdout,
    )
    assert code == 0
    assert seen["path"] == "/protocol/v2/agent-receipts/digest-abc"


@pytest.mark.asyncio
async def test_receipts_get_receipt_id_takes_precedence_over_intent_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit <receipt_id> is unambiguous and must win over --intent-id if both are given."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    seen: dict[str, object] = {}

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        seen["path"] = path
        return {"scope": "action"}

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "receipts",
            "get",
            "digest-abc",
            "--kind",
            "agent",
            "--intent-id",
            INTENT_ID,
        ],
        stdout=stdout,
    )
    assert code == 0
    assert seen["path"] == "/protocol/v2/agent-receipts/digest-abc"
