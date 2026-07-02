"""Docker WireMock lifecycle for `paybond dev up`."""

from __future__ import annotations

import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Literal

from paybond_kit.dev.offline_gateway import DEV_WIREMOCK_CONTAINER_NAME, DEV_WIREMOCK_DEFAULT_PORT

DevWiremockStatus = Literal["started", "already_running", "stopped"]


def resolve_dev_wiremock_dir(cwd: str | Path | None = None) -> Path:
    base = Path(cwd or Path.cwd())
    package_data = Path(__file__).resolve().parents[1] / "data/dev/wiremock"
    candidates = [
        base / "examples/partner-dry-run-wiremock/gateway-wiremock",
        base / "kit/dev/wiremock",
        package_data,
        Path(__file__).resolve().parents[4] / "dev/wiremock",
        Path(__file__).resolve().parents[5] / "kit/dev/wiremock",
    ]
    for candidate in candidates:
        if (candidate / "mappings").is_dir():
            return candidate
    raise RuntimeError(
        "WireMock mappings not found. Run from the Paybond monorepo or install paybond-kit with bundled dev assets."
    )


def _docker_container_running(name: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def _wait_wiremock_ready(base_url: str, *, attempts: int = 40, delay_sec: float = 0.25) -> None:
    admin_url = f"{base_url.rstrip('/')}/__admin/mappings"
    last_error: BaseException | None = None
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(admin_url, timeout=2) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            last_error = err
        time.sleep(delay_sec)
    raise RuntimeError(f"WireMock not ready at {admin_url}: {last_error!r}")


def _build_next_commands(gateway_url: str) -> list[str]:
    return [
        f"paybond dev loop --gateway {gateway_url} --no-login",
        "paybond dev smoke --offline",
        "paybond dev trace",
    ]


def run_dev_wiremock_up(*, port: int | None = None, down: bool = False) -> dict[str, Any]:
    resolved_port = port or DEV_WIREMOCK_DEFAULT_PORT
    gateway_url = f"http://127.0.0.1:{resolved_port}"
    wiremock_dir = resolve_dev_wiremock_dir()

    if down:
        if _docker_container_running(DEV_WIREMOCK_CONTAINER_NAME):
            subprocess.run(["docker", "rm", "-f", DEV_WIREMOCK_CONTAINER_NAME], check=False)
        return {
            "gateway_url": gateway_url,
            "port": resolved_port,
            "wiremock_dir": str(wiremock_dir),
            "container_name": DEV_WIREMOCK_CONTAINER_NAME,
            "status": "stopped",
            "next_commands": [],
        }

    if _docker_container_running(DEV_WIREMOCK_CONTAINER_NAME):
        return {
            "gateway_url": gateway_url,
            "port": resolved_port,
            "wiremock_dir": str(wiremock_dir),
            "container_name": DEV_WIREMOCK_CONTAINER_NAME,
            "status": "already_running",
            "next_commands": _build_next_commands(gateway_url),
        }

    run = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            DEV_WIREMOCK_CONTAINER_NAME,
            "-p",
            f"{resolved_port}:8080",
            "-v",
            f"{wiremock_dir}:/home/wiremock",
            "wiremock/wiremock:3.3.1",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if run.returncode != 0:
        message = (run.stderr or run.stdout or "docker run failed").strip()
        raise RuntimeError(message)

    _wait_wiremock_ready(gateway_url)
    return {
        "gateway_url": gateway_url,
        "port": resolved_port,
        "wiremock_dir": str(wiremock_dir),
        "container_name": DEV_WIREMOCK_CONTAINER_NAME,
        "status": "started",
        "next_commands": _build_next_commands(gateway_url),
    }
