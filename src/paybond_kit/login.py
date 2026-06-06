"""Sandbox device-login CLI for writing a Paybond API key to a local env file."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

import httpx

from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL

DEFAULT_ENV_FILE = ".env.local"
CLIENT_ID = "paybond-kit-cli"
CLIENT_NAME = "Paybond CLI"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
MIN_POLL_INTERVAL_SECONDS = 1
ENV_KEY_RE = re.compile(r"^\s*(?:export\s+)?PAYBOND_API_KEY\s*=", re.MULTILINE)


class PaybondLoginError(RuntimeError):
    """Raised when the sandbox device login cannot complete safely."""


class OAuthPollError(PaybondLoginError):
    """Raised for OAuth device-token polling errors."""

    def __init__(self, error: str, description: str | None = None, interval: int | None = None) -> None:
        super().__init__(description or error)
        self.error = error
        self.interval = interval


DEVICE_ENVIRONMENTS = ("sandbox",)


@dataclass(frozen=True)
class LoginOptions:
    env_file: str = DEFAULT_ENV_FILE
    gateway: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL
    environment: str = "sandbox"
    no_open: bool = False
    force: bool = False


@dataclass(frozen=True)
class DeviceStartResponse:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None
    expires_in: int
    interval: int


@dataclass(frozen=True)
class DeviceTokenResponse:
    access_token: str
    token_type: str
    tenant_id: str
    tenant_uuid: str
    environment: str
    service_account_role: str
    expires_at: str = ""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="paybond-kit-login",
        description=(
            "Start a device login and write PAYBOND_API_KEY to a local env file. "
            "The default .env.local target is added to .gitignore when needed. "
            "Defaults to sandbox. Production keys are created in Console and stored "
            "in secret managers."
        ),
    )
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    parser.add_argument("--gateway", default=DEFAULT_PAYBOND_GATEWAY_BASE_URL)
    parser.add_argument("--env", dest="environment", default="sandbox")
    parser.add_argument("--live", dest="live", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser


def parse_args(argv: list[str] | None = None) -> LoginOptions:
    args = _parser().parse_args(argv)
    env_file = str(args.env_file).strip()
    gateway = str(args.gateway).strip()
    if bool(args.live):
        raise PaybondLoginError(
            "live device login is not supported; create production keys in Console and store them in a secret manager"
        )
    environment = str(args.environment).strip().lower()
    if not env_file:
        raise PaybondLoginError("invalid --env-file")
    if not gateway:
        raise PaybondLoginError("invalid --gateway")
    if environment not in DEVICE_ENVIRONMENTS:
        if environment == "live":
            raise PaybondLoginError(
                "live device login is not supported; create production keys in Console and store them in a secret manager"
            )
        raise PaybondLoginError("invalid --env (expected sandbox)")
    return LoginOptions(
        env_file=env_file,
        gateway=gateway,
        environment=environment,
        no_open=bool(args.no_open),
        force=bool(args.force),
    )


def _quote_env_value(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:@+-]+", value):
        return value
    return json.dumps(value)


def _replace_or_append_env_value(existing: str, raw_key: str, *, force: bool) -> str:
    line = f"PAYBOND_API_KEY={_quote_env_value(raw_key)}"
    pattern = re.compile(r"^(\s*(?:export\s+)?PAYBOND_API_KEY\s*=).*$", re.MULTILINE)
    if pattern.search(existing):
        if not force:
            raise PaybondLoginError(
                "PAYBOND_API_KEY already exists in the target env file; pass --force to replace it."
            )
        return pattern.sub(line, existing, count=1)
    suffix = "\n" if existing and not existing.endswith("\n") else ""
    return f"{existing}{suffix}{line}\n"


def assert_can_write_env_file(env_path: Path, *, force: bool) -> None:
    try:
        existing = env_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    if ENV_KEY_RE.search(existing) and not force:
        raise PaybondLoginError(
            "PAYBOND_API_KEY already exists in the target env file; pass --force to replace it."
        )


def write_env_file(env_path: Path, raw_key: str, *, force: bool) -> None:
    try:
        existing = env_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        existing = ""
    next_body = _replace_or_append_env_value(existing, raw_key, force=force)
    # Write to a sibling temp file (created 0o600 by mkstemp) and atomically rename, so a
    # crash mid-write can never truncate the existing key file or leave a partial secret.
    fd, tmp_name = tempfile.mkstemp(dir=str(env_path.parent), prefix=".paybond-env-", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(next_body)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, env_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _git(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )


def assert_git_ignored(env_path: Path, *, cwd: Path) -> None:
    _ensure_git_ignored(env_path, cwd=cwd, auto_add_default_env_file=False)


def _ensure_git_ignored(env_path: Path, *, cwd: Path, auto_add_default_env_file: bool) -> None:
    try:
        root_result = _git(["rev-parse", "--show-toplevel"], cwd=cwd)
    except FileNotFoundError:
        return
    if root_result.returncode != 0:
        return

    repo_root = Path(root_result.stdout.strip()).resolve()
    target = env_path.resolve()
    try:
        relative_target = target.relative_to(repo_root)
    except ValueError:
        return

    ignore_result = _git(
        ["-C", str(repo_root), "check-ignore", "--quiet", "--", relative_target.as_posix()],
        cwd=cwd,
    )
    if ignore_result.returncode == 0:
        return
    if ignore_result.returncode == 1:
        if auto_add_default_env_file and relative_target.as_posix() == DEFAULT_ENV_FILE:
            gitignore_path = repo_root / ".gitignore"
            try:
                existing = gitignore_path.read_text(encoding="utf-8")
            except FileNotFoundError:
                existing = ""
            suffix = "\n" if existing and not existing.endswith("\n") else ""
            gitignore_path.write_text(f"{existing}{suffix}{DEFAULT_ENV_FILE}\n", encoding="utf-8")
            recheck = _git(
                ["-C", str(repo_root), "check-ignore", "--quiet", "--", relative_target.as_posix()],
                cwd=cwd,
            )
            if recheck.returncode == 0:
                return
        raise PaybondLoginError(
            f"Refusing to write {target} because it is not ignored by git. "
            f"Add {relative_target.as_posix()} to .gitignore or pass --env-file pointing outside the repo."
        )
    raise PaybondLoginError(
        f"Unable to verify git ignore status for {target}: "
        f"{ignore_result.stderr.strip() or 'git check-ignore failed'}"
    )


def _gateway_url(gateway: str, path: str) -> str:
    return gateway.strip().rstrip("/") + path


async def _post_gateway_json(
    client: httpx.AsyncClient,
    gateway: str,
    path: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    response = await client.post(_gateway_url(gateway, path), json=payload)
    try:
        body = response.json()
    except ValueError as exc:
        raise PaybondLoginError(f"Gateway returned non-JSON response ({response.status_code}).") from exc
    if not isinstance(body, dict):
        raise PaybondLoginError(f"Gateway returned an invalid JSON response ({response.status_code}).")
    if response.is_success:
        return body
    error = str(body.get("error") or "").strip()
    if error:
        interval_value = body.get("interval")
        interval = interval_value if isinstance(interval_value, int) else None
        description = str(body.get("error_description") or body.get("message") or "").strip() or None
        raise OAuthPollError(error, description, interval)
    raise PaybondLoginError(f"Gateway {path} HTTP {response.status_code}.")


def _str_field(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    return value.strip() if isinstance(value, str) else ""


def _int_field(body: dict[str, Any], field: str, default: int) -> int:
    value = body.get(field)
    return value if isinstance(value, int) else default


def _device_start_from_body(body: dict[str, Any]) -> DeviceStartResponse:
    response = DeviceStartResponse(
        device_code=_str_field(body, "device_code"),
        user_code=_str_field(body, "user_code"),
        verification_uri=_str_field(body, "verification_uri"),
        verification_uri_complete=_str_field(body, "verification_uri_complete") or None,
        expires_in=_int_field(body, "expires_in", 600),
        interval=_int_field(body, "interval", 5),
    )
    if not response.device_code or not response.user_code or not response.verification_uri:
        raise PaybondLoginError("Gateway device start response was missing required fields.")
    return response


def _device_token_from_body(body: dict[str, Any], environment: str) -> DeviceTokenResponse:
    response = DeviceTokenResponse(
        access_token=_str_field(body, "access_token"),
        token_type=_str_field(body, "token_type"),
        tenant_id=_str_field(body, "tenant_id"),
        tenant_uuid=_str_field(body, "tenant_uuid"),
        environment=_str_field(body, "environment"),
        service_account_role=_str_field(body, "service_account_role"),
        expires_at=_str_field(body, "expires_at"),
    )
    if not response.access_token or not response.tenant_id or not response.tenant_uuid:
        raise PaybondLoginError("Gateway device token response was missing required fields.")
    if response.environment != environment:
        raise PaybondLoginError(
            f"Gateway returned a {response.environment or 'unknown'} key but {environment} was requested."
        )
    if response.service_account_role != "operator":
        raise PaybondLoginError(
            f"Gateway returned a non-operator key ({response.service_account_role or 'unknown'})."
        )
    if not response.access_token.startswith(f"paybond_sk_{environment}_"):
        raise PaybondLoginError(f"Gateway returned an unexpected {environment} API key shape.")
    return response


async def _start_device_flow(client: httpx.AsyncClient, gateway: str, environment: str) -> DeviceStartResponse:
    body = await _post_gateway_json(
        client,
        gateway,
        "/v1/public/auth/device/start",
        {
            "client_id": CLIENT_ID,
            "client_name": CLIENT_NAME,
            "requested_environment": environment,
            "service_account_role": "operator",
        },
    )
    return _device_start_from_body(body)


async def _poll_device_token(
    client: httpx.AsyncClient,
    gateway: str,
    environment: str,
    start: DeviceStartResponse,
    *,
    sleep: Any,
    now: Any,
) -> DeviceTokenResponse:
    interval_seconds = max(MIN_POLL_INTERVAL_SECONDS, int(start.interval or 5))
    expires_at = now() + max(1, start.expires_in)

    while True:
        await sleep(interval_seconds)
        if now() > expires_at + 1:
            raise PaybondLoginError("Device authorization expired before approval.")
        try:
            body = await _post_gateway_json(
                client,
                gateway,
                "/v1/public/auth/device/token",
                {
                    "grant_type": DEVICE_GRANT_TYPE,
                    "device_code": start.device_code,
                    "client_id": CLIENT_ID,
                },
            )
            return _device_token_from_body(body, environment)
        except OAuthPollError as exc:
            if exc.error == "authorization_pending":
                interval_seconds = max(interval_seconds, int(exc.interval or interval_seconds))
                continue
            if exc.error == "slow_down":
                interval_seconds = max(interval_seconds + MIN_POLL_INTERVAL_SECONDS, int(exc.interval or 0))
                continue
            if exc.error == "access_denied":
                raise PaybondLoginError("Device authorization was denied.") from exc
            if exc.error == "expired_token":
                raise PaybondLoginError("Device authorization expired before approval.") from exc
            raise PaybondLoginError(str(exc)) from exc


def mask_api_key(raw_key: str) -> str:
    parts = raw_key.strip().split("_")
    if len(parts) >= 5 and parts[0] == "paybond" and parts[1] == "sk":
        environment = parts[2]
        key_id = parts[3]
        redacted = f"{key_id[:8]}...{key_id[-4:]}" if len(key_id) > 12 else "redacted"
        return f"paybond_sk_{environment}_{redacted}"
    return "paybond_sk_..."


async def _run_login_with_client(
    options: LoginOptions,
    *,
    client: httpx.AsyncClient,
    cwd: Path,
    stdout: TextIO,
    sleep: Any,
    open_browser: Any,
    now: Any,
) -> int:
    env_path = (cwd / options.env_file).resolve() if not Path(options.env_file).is_absolute() else Path(options.env_file).resolve()
    assert_can_write_env_file(env_path, force=options.force)
    _ensure_git_ignored(env_path, cwd=cwd, auto_add_default_env_file=options.env_file == DEFAULT_ENV_FILE)

    start = await _start_device_flow(client, options.gateway, options.environment)
    verification_url = start.verification_uri_complete or start.verification_uri
    stdout.write(f"Paybond {options.environment} login\n")
    stdout.write(f"Verification URL: {verification_url}\n")
    stdout.write(f"Code: {start.user_code}\n")
    if not options.no_open and not open_browser(verification_url):
        stdout.write("Open the verification URL in a browser to approve this login.\n")
    stdout.write("Waiting for approval...\n")

    token = await _poll_device_token(client, options.gateway, options.environment, start, sleep=sleep, now=now)
    write_env_file(env_path, token.access_token, force=options.force)

    stdout.write(f"Wrote PAYBOND_API_KEY to {env_path}\n")
    stdout.write(f"Key: {mask_api_key(token.access_token)}\n")
    stdout.write(f"Target {token.environment} tenant: {token.tenant_id} ({token.tenant_uuid})\n")
    if token.expires_at:
        stdout.write(
            f"This key auto-expires at {token.expires_at}; re-run paybond login to mint a new one.\n"
        )
    return 0


async def run_login(
    options: LoginOptions,
    *,
    client: httpx.AsyncClient | None = None,
    cwd: Path | None = None,
    stdout: TextIO | None = None,
    sleep: Any = asyncio.sleep,
    open_browser: Any = webbrowser.open,
    now: Any = time.monotonic,
) -> int:
    resolved_cwd = Path.cwd() if cwd is None else cwd
    resolved_stdout = sys.stdout if stdout is None else stdout
    if client is not None:
        return await _run_login_with_client(
            options,
            client=client,
            cwd=resolved_cwd,
            stdout=resolved_stdout,
            sleep=sleep,
            open_browser=open_browser,
            now=now,
        )
    async with httpx.AsyncClient(timeout=30.0) as owned_client:
        return await _run_login_with_client(
            options,
            client=owned_client,
            cwd=resolved_cwd,
            stdout=resolved_stdout,
            sleep=sleep,
            open_browser=open_browser,
            now=now,
        )


async def async_main(argv: list[str] | None = None, *, stderr: TextIO | None = None) -> int:
    try:
        return await run_login(parse_args(argv))
    except PaybondLoginError as exc:
        (stderr or sys.stderr).write(f"{exc}\n")
        return 1


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(async_main(argv))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
