from __future__ import annotations

import json
import select
import subprocess
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from paybond_kit.cli.mcp_install import (
    default_mcp_install_format,
    default_mcp_server_command,
    parse_mcp_install_host,
)
from paybond_kit.mcp_policy import validate_mcp_tool_schema
from paybond_kit.cli.mcp_verify_config import validate_mcp_host_config


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    message: str
    details: dict[str, Any] | None = None


def package_version() -> str:
    try:
        return version("paybond-kit")
    except PackageNotFoundError:
        return "unknown"


def encode_mcp_message(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def _consume_mcp_messages(raw: bytes) -> tuple[list[dict[str, Any]], bytes]:
    messages: list[dict[str, Any]] = []
    offset = 0
    while True:
        header_end = raw.find(b"\r\n\r\n", offset)
        if header_end < 0:
            return messages, raw[offset:]
        header_text = raw[offset:header_end].decode("ascii", errors="replace")
        content_length = 0
        for line in header_text.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
        if content_length <= 0:
            raise RuntimeError("MCP response missing Content-Length")
        body_start = header_end + 4
        body_end = body_start + content_length
        if len(raw) < body_end:
            return messages, raw[offset:]
        body = raw[body_start:body_end]
        parsed = json.loads(body.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise RuntimeError("MCP response was not a JSON object")
        messages.append(parsed)
        offset = body_end
        if offset >= len(raw):
            return messages, b""


def _read_mcp_message(stream, *, deadline: float, raw_buffer: bytearray) -> dict[str, Any]:
    while True:
        messages, remainder = _consume_mcp_messages(bytes(raw_buffer))
        raw_buffer[:] = remainder
        if messages:
            return messages[0]
        if time.monotonic() > deadline:
            raise TimeoutError("timed out waiting for MCP response")
        chunk = stream.read(1)
        if not chunk:
            raise RuntimeError("MCP server closed stdout before responding")
        raw_buffer.extend(chunk)
        if len(raw_buffer) > 1_048_576:
            raise RuntimeError("MCP stdout buffer too large")


def _stdout_is_mcp_pure(raw_stdout: bytes) -> bool:
    if not raw_stdout:
        return True
    try:
        messages, remainder = _consume_mcp_messages(raw_stdout)
    except (RuntimeError, json.JSONDecodeError, ValueError):
        return False
    if remainder.strip():
        return False
    return len(messages) > 0


def run_agent_mcp_checks(
    *,
    env_file: str,
    cwd: Path,
    host: str = "generic",
    server_command: list[str] | None = None,
    timeout_seconds: float = 10.0,
) -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
    install_host = parse_mcp_install_host(host)
    fmt = default_mcp_install_format(install_host)
    from paybond_kit.cli.mcp_install import plan_mcp_install

    plan = plan_mcp_install(
        host=install_host,
        scope="local",
        fmt=fmt,
        env_file=env_file,
        out=None,
        cwd=cwd,
        home=Path.home(),
        server_command=server_command or default_mcp_server_command(),
    )
    config_result = validate_mcp_host_config(
        host=install_host,
        fmt=fmt,
        payload=plan.payload,
        cwd=cwd,
        expected_env_file=env_file,
    )
    checks.append(
        DoctorCheck(
            name="mcp_host_config",
            ok=config_result.ok,
            message=config_result.message,
            details={"host": install_host, "format": fmt},
        )
    )

    env_path = Path(env_file) if Path(env_file).is_absolute() else cwd / env_file
    env_ok = env_path.is_file()
    checks.append(
        DoctorCheck(
            name="mcp_env_resolution",
            ok=env_ok,
            message=str(env_path.resolve()) if env_ok else f"env file not found: {env_path}",
            details={"env_file": env_file, "resolved": str(env_path.resolve())},
        )
    )
    if not env_ok:
        checks.extend(
            [
                DoctorCheck(name="mcp_launch", ok=False, message="skipped (env file missing)"),
                DoctorCheck(name="mcp_initialize", ok=False, message="skipped (env file missing)"),
                DoctorCheck(name="mcp_tools_list", ok=False, message="skipped (env file missing)"),
                DoctorCheck(name="mcp_tool_schemas", ok=False, message="skipped (env file missing)"),
                DoctorCheck(name="mcp_stdout_purity", ok=False, message="skipped (env file missing)"),
            ]
        )
        return checks

    command = server_command or default_mcp_server_command()
    env = {
        **dict(__import__("os").environ),
        "PAYBOND_ENV_FILE": str(env_path.resolve()),
    }
    for key in ("PAYBOND_API_KEY",):
        env.pop(key, None)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=env,
        )
        launch_ok = True
        launch_message = f"launched {' '.join(command)}"
    except OSError as exc:
        checks.append(DoctorCheck(name="mcp_launch", ok=False, message=f"unable to launch MCP server: {exc}"))
        checks.extend(
            [
                DoctorCheck(name="mcp_initialize", ok=False, message="skipped (launch failed)"),
                DoctorCheck(name="mcp_tools_list", ok=False, message="skipped (launch failed)"),
                DoctorCheck(name="mcp_tool_schemas", ok=False, message="skipped (launch failed)"),
                DoctorCheck(name="mcp_stdout_purity", ok=False, message="skipped (launch failed)"),
            ]
        )
        return checks

    checks.append(DoctorCheck(name="mcp_launch", ok=launch_ok, message=launch_message))
    assert process.stdin is not None
    assert process.stdout is not None
    deadline = time.monotonic() + timeout_seconds
    raw_stdout = bytearray()
    try:
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "paybond-doctor", "version": package_version()},
            },
        }
        process.stdin.write(encode_mcp_message(initialize))
        process.stdin.flush()
        init_response = _read_mcp_message(process.stdout, deadline=deadline, raw_buffer=raw_stdout)
        raw_stdout.extend(process.stdout.read() or b"")
        if init_response.get("error"):
            checks.append(
                DoctorCheck(
                    name="mcp_initialize",
                    ok=False,
                    message="MCP initialize failed",
                    details={"error": init_response["error"]},
                )
            )
            checks.extend(
                [
                    DoctorCheck(name="mcp_tools_list", ok=False, message="skipped (initialize failed)"),
                    DoctorCheck(name="mcp_tool_schemas", ok=False, message="skipped (initialize failed)"),
                    DoctorCheck(name="mcp_stdout_purity", ok=False, message="skipped (initialize failed)"),
                ]
            )
            return checks
        server_info = (init_response.get("result") or {}).get("serverInfo")
        init_ok = isinstance(server_info, dict)
        checks.append(
            DoctorCheck(
                name="mcp_initialize",
                ok=init_ok,
                message="MCP initialize succeeded" if init_ok else "MCP initialize response missing serverInfo",
                details={
                    "server_name": server_info.get("name") if isinstance(server_info, dict) else None,
                    "server_version": server_info.get("version") if isinstance(server_info, dict) else None,
                }
                if init_ok
                else None,
            )
        )
        if not init_ok:
            checks.extend(
                [
                    DoctorCheck(name="mcp_tools_list", ok=False, message="skipped (initialize failed)"),
                    DoctorCheck(name="mcp_tool_schemas", ok=False, message="skipped (initialize failed)"),
                    DoctorCheck(name="mcp_stdout_purity", ok=False, message="skipped (initialize failed)"),
                ]
            )
            return checks

        initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        process.stdin.write(encode_mcp_message(initialized))
        process.stdin.flush()
        tools_list = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        process.stdin.write(encode_mcp_message(tools_list))
        process.stdin.flush()
        tools_response = _read_mcp_message(process.stdout, deadline=deadline, raw_buffer=raw_stdout)
        raw_stdout.extend(process.stdout.read() or b"")
        if tools_response.get("error"):
            checks.append(
                DoctorCheck(
                    name="mcp_tools_list",
                    ok=False,
                    message="MCP tools/list failed",
                    details={"error": tools_response["error"]},
                )
            )
            checks.extend(
                [
                    DoctorCheck(name="mcp_tool_schemas", ok=False, message="skipped (tools/list failed)"),
                    DoctorCheck(name="mcp_stdout_purity", ok=False, message="skipped (tools/list failed)"),
                ]
            )
            return checks
        tools = (tools_response.get("result") or {}).get("tools")
        tool_count = len(tools) if isinstance(tools, list) else 0
        checks.append(
            DoctorCheck(
                name="mcp_tools_list",
                ok=tool_count > 0,
                message=f"{tool_count} tools listed",
                details={"tool_count": tool_count},
            )
        )
        schema_errors: list[str] = []
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    schema_errors.extend(validate_mcp_tool_schema(tool))
        checks.append(
            DoctorCheck(
                name="mcp_tool_schemas",
                ok=tool_count > 0 and not schema_errors,
                message="all listed tools have valid schemas"
                if not schema_errors
                else schema_errors[0],
                details={"invalid_count": len(schema_errors), "errors": schema_errors[:5]},
            )
        )
        checks.append(
            DoctorCheck(
                name="mcp_stdout_purity",
                ok=_stdout_is_mcp_pure(bytes(raw_stdout)),
                message="stdout contains only MCP-framed JSON-RPC"
                if _stdout_is_mcp_pure(bytes(raw_stdout))
                else "stdout contains non-MCP material",
            )
        )
        return checks
    except Exception as exc:  # noqa: BLE001
        stderr = ""
        if process.stderr is not None:
            readable, _, _ = select.select([process.stderr], [], [], 0)
            if readable:
                stderr = process.stderr.read().decode("utf-8", errors="replace").strip()
        detail = f": {stderr}" if stderr else ""
        checks.append(DoctorCheck(name="mcp_initialize", ok=False, message=f"MCP stdio probe failed: {exc}{detail}"))
        checks.extend(
            [
                DoctorCheck(name="mcp_tools_list", ok=False, message="skipped (probe failed)"),
                DoctorCheck(name="mcp_tool_schemas", ok=False, message="skipped (probe failed)"),
                DoctorCheck(name="mcp_stdout_purity", ok=False, message="skipped (probe failed)"),
            ]
        )
        return checks
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
