from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from paybond_kit.cli.doctor_mcp import (
    MCP_RESTRICTED_KEY_HINT,
    McpDoctorCheck,
    evaluate_mcp_credential_checks,
    run_mcp_doctor_checks,
)


def _checks(**overrides: Any) -> list[McpDoctorCheck]:
    kwargs: dict[str, Any] = {
        "key_kind": "restricted",
        "tool_policy": None,
        "tool_allowlist": None,
        "config_path": "/tmp/.paybond/mcp.json",
        "env_file": "/tmp/.env.local",
    }
    kwargs.update(overrides)
    return evaluate_mcp_credential_checks(**kwargs)


def _named(checks: list[McpDoctorCheck], name: str) -> McpDoctorCheck:
    for check in checks:
        if check.name == name:
            return check
    raise AssertionError(f"missing check {name}")


def test_restricted_key_passes() -> None:
    checks = _checks()
    assert _named(checks, "mcp_credential_kind").ok
    assert _named(checks, "mcp_credential_tool_policy").ok


def test_standard_key_warns() -> None:
    """A standard key hands an MCP host the full role surface, uncapped by the gateway."""

    kind = _named(_checks(key_kind="standard"), "mcp_credential_kind")
    assert not kind.ok
    assert "unrestricted paybond_sk_ key" in kind.message
    assert MCP_RESTRICTED_KEY_HINT in kind.message
    assert kind.details["severity"] == "warning"
    assert kind.details["remediation"] == MCP_RESTRICTED_KEY_HINT


@pytest.mark.parametrize("tool_policy", [None, "spend-write"])
def test_standard_key_without_narrowing_fails_mitigation_check(tool_policy: str | None) -> None:
    """``spend-write`` is the server's own default, so it narrows nothing."""

    policy = _named(_checks(key_kind="standard", tool_policy=tool_policy), "mcp_credential_tool_policy")
    assert not policy.ok
    assert "PAYBOND_MCP_TOOL_POLICY" in policy.message


@pytest.mark.parametrize(
    "overrides",
    [
        {"key_kind": "standard", "tool_policy": "readonly"},
        {
            "key_kind": "standard",
            "tool_policy": "allowlist",
            "tool_allowlist": "paybond_signal_reputation",
        },
    ],
)
def test_standard_key_narrowed_by_env_policy_passes_mitigation_check(overrides: dict[str, Any]) -> None:
    checks = _checks(**overrides)
    assert not _named(checks, "mcp_credential_kind").ok
    assert _named(checks, "mcp_credential_tool_policy").ok


def test_tool_policy_ignored_for_restricted_keys() -> None:
    policy = _named(_checks(tool_policy="readonly"), "mcp_credential_tool_policy")
    assert policy.ok
    assert "ignored for restricted keys" in policy.message


def test_unknown_key_is_skipped_not_passed() -> None:
    checks = _checks(key_kind="unknown")
    kind = _named(checks, "mcp_credential_kind")
    assert not kind.ok
    assert "no readable Paybond API key" in kind.message
    assert _named(checks, "mcp_credential_tool_policy").ok


def test_details_carry_config_and_env_file() -> None:
    kind = _named(_checks(), "mcp_credential_kind")
    assert kind.details["key_kind"] == "restricted"
    assert kind.details["env_file"] == "/tmp/.env.local"
    assert kind.details["config_path"] == "/tmp/.paybond/mcp.json"


def _workspace_with_key(tmp_path: Path, key: str) -> Path:
    (tmp_path / ".env.local").write_text(f"PAYBOND_API_KEY={key}\n", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("key", "expected_ok"),
    [("paybond_sk_live_example", False), ("paybond_rk_live_example", True)],
)
def test_run_grades_the_key_in_the_generated_config_env_file(
    tmp_path: Path, key: str, expected_ok: bool
) -> None:
    cwd = _workspace_with_key(tmp_path, key)
    checks = run_mcp_doctor_checks(env_file=".env.local", cwd=cwd, home=cwd, host="claude")
    kind = _named(checks, "mcp_credential_kind")
    assert kind.ok is expected_ok
    assert kind.details["env_file"] == str(cwd / ".env.local")


def test_run_reports_unreadable_host_config_instead_of_raising(tmp_path: Path) -> None:
    cwd = _workspace_with_key(tmp_path, "paybond_rk_live_example")
    checks = run_mcp_doctor_checks(
        env_file=".env.local",
        cwd=cwd,
        home=cwd,
        host="claude",
        config_path=str(cwd / "missing.json"),
    )
    kind = _named(checks, "mcp_credential_kind")
    assert not kind.ok
    assert "host config" in kind.message


def test_run_fails_when_host_config_has_no_paybond_entry(tmp_path: Path) -> None:
    """Never grade the workspace env file for a config the host cannot use."""

    cwd = _workspace_with_key(tmp_path, "paybond_rk_live_example")
    config_path = cwd / "mcp.json"
    config_path.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    checks = run_mcp_doctor_checks(
        env_file=".env.local",
        cwd=cwd,
        home=cwd,
        host="claude",
        config_path=str(config_path),
    )
    kind = _named(checks, "mcp_credential_kind")
    assert not kind.ok
    assert "no usable Paybond MCP server entry" in kind.message
