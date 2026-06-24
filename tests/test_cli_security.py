from __future__ import annotations

import io
import json
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from paybond_kit.cli.router import run_cli
from paybond_kit.login import run_login as real_run_login

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


class FakeClient:
    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = responses
        self.requests: list[tuple[str, dict[str, Any]]] = []

    async def post(self, url: str, *, json: dict[str, Any]) -> httpx.Response:
        self.requests.append((url, json))
        if not self._responses:
            raise AssertionError("unexpected HTTP request")
        return self._responses.pop(0)


def json_response(body: dict[str, Any], status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=body)


def _device_start() -> dict[str, Any]:
    return {
        "device_code": "device-code",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://paybond.ai/device",
        "verification_uri_complete": "https://paybond.ai/device?code=ABCD-EFGH",
        "expires_in": 600,
        "interval": 5,
    }


def _device_token() -> dict[str, Any]:
    return {
        "access_token": RAW_KEY,
        "token_type": "bearer",
        "tenant_id": "tenant-sandbox",
        "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
        "environment": "sandbox",
        "service_account_role": "operator",
    }


@pytest.mark.asyncio
async def test_cli_login_rejects_live_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stderr = io.StringIO()
    code = await run_cli(["login", "--env", "live", "--no-open"], stderr=stderr)
    assert code == 1
    assert "live device login is not supported" in stderr.getvalue()


@pytest.mark.asyncio
async def test_cli_login_json_masks_key_and_writes_0600_env_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    monkeypatch.chdir(tmp_path)

    client = FakeClient([json_response(_device_start()), json_response(_device_token())])
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    async def fake_run_login(options, **kwargs):  # type: ignore[no-untyped-def]
        return await real_run_login(
            options,
            client=client,  # type: ignore[arg-type]
            cwd=tmp_path,
            stdout=kwargs.get("stdout"),
            sleep=sleep,
            now=lambda: 0.0,
            human_output=kwargs.get("human_output", True),
        )

    monkeypatch.setattr("paybond_kit.cli.commands.run_login", fake_run_login)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "login", "--no-open"], stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is True
    data = payload["data"]
    assert data["key_written"] is True
    assert data["key_masked"] == "paybond_sk_sandbox_01234567...cdef"
    assert data["tenant_id"] == "tenant-sandbox"
    assert RAW_KEY not in stdout.getvalue()

    env_path = tmp_path / ".env.local"
    assert env_path.read_text(encoding="utf-8") == f"PAYBOND_API_KEY={RAW_KEY}\n"
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


@pytest.mark.asyncio
async def test_cli_login_refuses_unignored_secret_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    monkeypatch.chdir(tmp_path)
    stderr = io.StringIO()
    code = await run_cli(
        ["login", "--env-file", "paybond-login-secrets", "--no-open"],
        stderr=stderr,
    )
    assert code == 1
    assert "not ignored by git" in stderr.getvalue()


@pytest.mark.asyncio
async def test_cli_rejects_tenant_flag_on_subcommands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stderr = io.StringIO()
    code = await run_cli(["intents", "list", "--tenant-id", "tenant-a"], stderr=stderr)
    assert code == 1
    assert "tenant scope comes from authenticated credentials" in stderr.getvalue()
