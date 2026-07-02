from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from paybond_kit.cli.core import CliContext, GlobalOptions, save_config_file
from paybond_kit.cli.telemetry import (
    cli_telemetry_enabled,
    hash_cli_install_id,
    report_cli_command_success,
    resolve_cli_install_id,
)


def test_hash_cli_install_id_is_stable() -> None:
    assert hash_cli_install_id("install-1") == hash_cli_install_id("install-1")
    assert len(hash_cli_install_id("install-1")) == 64


def test_resolve_cli_install_id_persists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    first = resolve_cli_install_id()
    second = resolve_cli_install_id()
    assert first == second
    config = json.loads((tmp_path / "paybond" / "config.json").read_text(encoding="utf-8"))
    assert config["install_id"] == first


def test_cli_telemetry_disabled_for_local_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PAYBOND_TELEMETRY", raising=False)
    assert cli_telemetry_enabled("http://127.0.0.1:18089") is False
    assert cli_telemetry_enabled("http://192.168.1.5:18089") is False
    monkeypatch.setenv("PAYBOND_TELEMETRY", "1")
    assert cli_telemetry_enabled("http://127.0.0.1:18089") is True


@pytest.mark.asyncio
async def test_report_cli_command_success_posts_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("PAYBOND_TELEMETRY", "1")

    posted: dict[str, object] = {}

    class _Response:
        status_code = 201

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, url: str, *, json: dict[str, object], headers: dict[str, str]):
            posted["url"] = url
            posted["json"] = json
            posted["headers"] = headers
            return _Response()

    ctx = CliContext(
        globals=GlobalOptions(gateway="https://api.paybond.ai", format="json"),
        cwd=tmp_path,
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with patch("paybond_kit.cli.telemetry.httpx.AsyncClient", return_value=_Client()):
        await report_cli_command_success(ctx, command_path="dev loop", offline=True)

    assert posted["url"] == "https://api.paybond.ai/v1/public/analytics/kit-cli"
    body = posted["json"]
    assert isinstance(body, dict)
    assert body["command_path"] == "dev loop"
    assert body["offline"] is True


def test_cli_telemetry_respects_config_opt_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("PAYBOND_TELEMETRY", raising=False)
    save_config_file({"telemetry": False})
    assert cli_telemetry_enabled("https://api.paybond.ai") is False
