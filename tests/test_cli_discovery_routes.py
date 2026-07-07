from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import pytest
import respx

from paybond_kit.cli.router import run_cli

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
GATEWAY = "https://gateway.test"
OPERATOR_DID = "did:example:alice"


@pytest.mark.asyncio
@respx.mock
async def test_signal_portfolio_uses_auth_scoped_gateway_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    route = respx.get(f"{GATEWAY}/signal/v1/portfolio/summary").mock(
        return_value=httpx.Response(200, json={"tenant_id": "realm-z", "operator_count": 2})
    )

    stdout = io.StringIO()
    code = await run_cli(
        ["--gateway", GATEWAY, "--format", "json", "signal", "portfolio"],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["operator_count"] == 2
    assert route.called
    assert route.calls[0].request.url.path == "/signal/v1/portfolio/summary"


@pytest.mark.asyncio
@respx.mock
async def test_signal_reputation_uses_root_reputation_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    route = respx.get(f"{GATEWAY}/reputation/{OPERATOR_DID}").mock(
        return_value=httpx.Response(
            200,
            json={"receipt": {"tenant_id": "realm-z", "operator_did": OPERATOR_DID}},
        )
    )

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--gateway",
            GATEWAY,
            "--format",
            "json",
            "signal",
            "reputation",
            "--did",
            OPERATOR_DID,
        ],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["receipt"]["operator_did"] == OPERATOR_DID
    assert route.called
    assert route.calls[0].request.url.path == f"/reputation/{OPERATOR_DID}"


@pytest.mark.asyncio
@respx.mock
async def test_signal_fraud_uses_operator_review_status_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    route = respx.get(f"{GATEWAY}/signal/v1/operators/{OPERATOR_DID}/review-status").mock(
        return_value=httpx.Response(
            200,
            json={"tenant_id": "realm-z", "operator_did": OPERATOR_DID, "review_state": "clear"},
        )
    )

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--gateway",
            GATEWAY,
            "--format",
            "json",
            "signal",
            "fraud",
            "--did",
            OPERATOR_DID,
        ],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["review_state"] == "clear"
    assert route.called
    assert route.calls[0].request.url.path == f"/signal/v1/operators/{OPERATOR_DID}/review-status"


@pytest.mark.asyncio
@respx.mock
async def test_mandates_import_posts_to_protocol_mandates_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    body_file = tmp_path / "mandate.json"
    body_file.write_text(json.dumps({"mandate_id": "mandate-1", "payload": {"ok": True}}), encoding="utf-8")

    route = respx.post(f"{GATEWAY}/protocol/v2/mandates").mock(
        return_value=httpx.Response(200, json={"mandate_id": "mandate-1", "status": "imported"})
    )

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--gateway",
            GATEWAY,
            "--format",
            "json",
            "mandates",
            "import",
            "--body",
            str(body_file),
        ],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["status"] == "imported"
    assert route.called
    assert route.calls[0].request.url.path == "/protocol/v2/mandates"
