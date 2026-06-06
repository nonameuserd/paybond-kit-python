from __future__ import annotations

import io
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from paybond_kit.login import (
    LoginOptions,
    assert_git_ignored,
    run_login,
    write_env_file,
)

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


@pytest.mark.asyncio
async def test_login_runs_device_flow_writes_0600_env_file_and_masks_output(tmp_path: Path) -> None:
    sleeps: list[float] = []
    stdout = io.StringIO()
    client = FakeClient(
        [
            json_response(
                {
                    "device_code": "device-code",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://paybond.ai/device",
                    "verification_uri_complete": "https://paybond.ai/device?code=ABCD-EFGH",
                    "expires_in": 600,
                    "interval": 5,
                }
            ),
            json_response(
                {
                    "error": "authorization_pending",
                    "error_description": "pending",
                    "interval": 5,
                },
                400,
            ),
            json_response(
                {
                    "access_token": RAW_KEY,
                    "token_type": "bearer",
                    "tenant_id": "tenant-sandbox",
                    "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "environment": "sandbox",
                    "service_account_role": "operator",
                }
            ),
        ]
    )

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    result = await run_login(
        LoginOptions(env_file=".env.local", gateway="https://gateway.test", no_open=True),
        client=client,  # type: ignore[arg-type]
        cwd=tmp_path,
        stdout=stdout,
        sleep=sleep,
        now=lambda: 0.0,
    )

    env_path = tmp_path / ".env.local"
    assert result == 0
    assert len(client.requests) == 3
    assert sleeps == [5, 5]
    assert env_path.read_text(encoding="utf-8") == f"PAYBOND_API_KEY={RAW_KEY}\n"
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    assert "Target sandbox tenant: tenant-sandbox" in stdout.getvalue()
    assert "Key: paybond_sk_sandbox_01234567...cdef" in stdout.getvalue()
    assert RAW_KEY not in stdout.getvalue()
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in stdout.getvalue()


@pytest.mark.asyncio
async def test_login_live_requests_live_and_accepts_live_key(tmp_path: Path) -> None:
    stdout = io.StringIO()
    live_key = (
        "paybond_sk_live_0123456789abcdef0123456789abcdef_"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    client = FakeClient(
        [
            json_response(
                {
                    "device_code": "device-code",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://paybond.ai/device",
                    "expires_in": 600,
                    "interval": 5,
                }
            ),
            json_response(
                {
                    "access_token": live_key,
                    "token_type": "bearer",
                    "tenant_id": "tenant-live",
                    "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "environment": "live",
                    "service_account_role": "operator",
                    "expires_at": "2026-06-06T10:00:00Z",
                }
            ),
        ]
    )

    result = await run_login(
        LoginOptions(env_file=".env.local", gateway="https://gateway.test", environment="live", no_open=True),
        client=client,  # type: ignore[arg-type]
        cwd=tmp_path,
        stdout=stdout,
        sleep=lambda _seconds: _noop(),
        now=lambda: 0.0,
    )

    assert result == 0
    assert client.requests[0][1]["requested_environment"] == "live"
    assert (tmp_path / ".env.local").read_text(encoding="utf-8") == f"PAYBOND_API_KEY={live_key}\n"
    assert "Paybond live login" in stdout.getvalue()
    assert "PRODUCTION operator API key" in stdout.getvalue()
    assert "Target live tenant: tenant-live" in stdout.getvalue()
    assert "auto-expires at 2026-06-06T10:00:00Z" in stdout.getvalue()
    assert live_key not in stdout.getvalue()


@pytest.mark.asyncio
async def test_login_rejects_mismatched_environment(tmp_path: Path) -> None:
    client = FakeClient(
        [
            json_response(
                {
                    "device_code": "device-code",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://paybond.ai/device",
                    "expires_in": 600,
                    "interval": 5,
                }
            ),
            json_response(
                {
                    "access_token": RAW_KEY,
                    "token_type": "bearer",
                    "tenant_id": "tenant-sandbox",
                    "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
                    "environment": "sandbox",
                    "service_account_role": "operator",
                }
            ),
        ]
    )

    with pytest.raises(RuntimeError, match="sandbox key but live was requested"):
        await run_login(
            LoginOptions(env_file=".env.local", gateway="https://gateway.test", environment="live", no_open=True),
            client=client,  # type: ignore[arg-type]
            cwd=tmp_path,
            sleep=lambda _seconds: _noop(),
            now=lambda: 0.0,
        )


async def _noop() -> None:
    return None


@pytest.mark.asyncio
async def test_login_refuses_existing_api_key_before_network(tmp_path: Path) -> None:
    env_path = tmp_path / ".env.local"
    env_path.write_text("PAYBOND_API_KEY=existing\nOTHER=value\n", encoding="utf-8")
    client = FakeClient([])

    with pytest.raises(RuntimeError, match="PAYBOND_API_KEY already exists"):
        await run_login(
            LoginOptions(env_file=".env.local", gateway="https://gateway.test", no_open=True),
            client=client,  # type: ignore[arg-type]
            cwd=tmp_path,
        )

    assert client.requests == []
    assert env_path.read_text(encoding="utf-8") == "PAYBOND_API_KEY=existing\nOTHER=value\n"


def test_login_force_replaces_existing_api_key(tmp_path: Path) -> None:
    env_path = tmp_path / ".env.local"
    env_path.write_text("OTHER=value\nexport PAYBOND_API_KEY=existing\n", encoding="utf-8")

    write_env_file(env_path, RAW_KEY, force=True)

    assert env_path.read_text(encoding="utf-8") == f"OTHER=value\nPAYBOND_API_KEY={RAW_KEY}\n"
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600


def test_git_guard_refuses_env_file_that_is_not_ignored(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with pytest.raises(RuntimeError, match="not ignored by git"):
        assert_git_ignored(tmp_path / "paybond-login-secrets", cwd=tmp_path)


def test_git_guard_allows_ignored_env_file(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (tmp_path / ".gitignore").write_text("paybond-login-secrets\n", encoding="utf-8")

    assert_git_ignored(tmp_path / "paybond-login-secrets", cwd=tmp_path)
