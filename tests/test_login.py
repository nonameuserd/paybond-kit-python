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
    PaybondLoginError,
    assert_git_ignored,
    parse_args,
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
    assert result.key_written is True
    assert result.env_path == env_path
    assert result.key_masked == "paybond_sk_sandbox_01234567...cdef"
    assert len(client.requests) == 3
    assert sleeps == [5, 5]
    assert env_path.read_text(encoding="utf-8") == f"PAYBOND_API_KEY={RAW_KEY}\n"
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    assert "Target sandbox tenant: tenant-sandbox" in stdout.getvalue()
    assert "Key: paybond_sk_sandbox_01234567...cdef" in stdout.getvalue()
    assert RAW_KEY not in stdout.getvalue()
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in stdout.getvalue()


def test_login_rejects_live_flags_before_network() -> None:
    with pytest.raises(RuntimeError, match="live device login is not supported"):
        parse_args(["--env", "live"])
    with pytest.raises(RuntimeError, match="live device login is not supported"):
        parse_args(["--live"])


@pytest.mark.asyncio
async def test_login_rejects_mismatched_environment(tmp_path: Path) -> None:
    live_key = "paybond_sk_live_fixture_not_a_real_secret"
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
                }
            ),
        ]
    )

    with pytest.raises(RuntimeError, match="live key but sandbox was requested"):
        await run_login(
            LoginOptions(env_file=".env.local", gateway="https://gateway.test", environment="sandbox", no_open=True),
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


@pytest.mark.asyncio
async def test_login_adds_default_env_file_to_gitignore(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

    result = await run_login(
        LoginOptions(env_file=".env.local", gateway="https://gateway.test", no_open=True),
        client=client,  # type: ignore[arg-type]
        cwd=tmp_path,
        sleep=lambda _seconds: _noop(),
        now=lambda: 0.0,
    )

    assert result.key_written is True
    assert ".env.local" in (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert_git_ignored(tmp_path / ".env.local", cwd=tmp_path)


def test_assert_git_ignored_requires_git_inside_work_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".git").mkdir()
    env_path = tmp_path / "secrets.env"

    def missing_git(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("git not found")

    monkeypatch.setattr("paybond_kit.login._git", missing_git)
    with pytest.raises(PaybondLoginError, match="git is required"):
        assert_git_ignored(env_path, cwd=tmp_path)
