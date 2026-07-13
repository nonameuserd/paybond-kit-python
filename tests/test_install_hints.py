from __future__ import annotations

import io

import pytest

from paybond_kit.cli.install_hints import (
    PIPX_QUICKSTART_DOCS_URL,
    detect_paybond_install_method,
    format_missing_extra_message,
    run_install_context_doctor_checks,
)
from paybond_kit.cli.router import run_cli


def test_format_missing_extra_message_includes_pip_and_pipx() -> None:
    message = format_missing_extra_message(
        command="agent demo langgraph smoke",
        extra_id="langgraph",
        inject_packages=("langgraph", "langchain-core"),
    )
    assert 'paybond-kit[langgraph]' in message
    assert "pipx inject paybond-kit langgraph langchain-core" in message
    assert "pipx run --spec" in message


def test_detect_paybond_install_method_pipx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "paybond_kit.cli.install_hints.sys.prefix",
        "/Users/me/.local/pipx/venvs/paybond-kit",
    )
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    assert detect_paybond_install_method() == "pipx"


def test_detect_paybond_install_method_venv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("paybond_kit.cli.install_hints.sys.prefix", "/tmp/project/.venv")
    monkeypatch.setenv("VIRTUAL_ENV", "/tmp/project/.venv")
    assert detect_paybond_install_method() == "venv"


def test_run_install_context_doctor_checks_reports_missing_extras(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "paybond_kit.cli.install_hints.detect_paybond_install_method",
        lambda: "pipx",
    )
    monkeypatch.setattr(
        "paybond_kit.langgraph_hooks.langgraph_runtime_available",
        lambda: False,
    )
    monkeypatch.setattr(
        "paybond_kit.cli.mcp_install.mcp_runtime_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "paybond_kit.claude_agents.config.claude_agents_runtime_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "paybond_kit.pydantic_ai._peer.pydantic_ai_runtime_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "paybond_kit.google_adk._peer.google_adk_runtime_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "paybond_kit.microsoft_agent_framework._peer.microsoft_agent_framework_runtime_available",
        lambda: True,
    )
    monkeypatch.setattr(
        "paybond_kit.openai_agents._peer.openai_agents_runtime_available",
        lambda: True,
    )

    checks = run_install_context_doctor_checks()
    by_name = {check.name: check for check in checks}

    assert by_name["install_method"].ok is True
    assert "pipx" in by_name["install_method"].message
    assert PIPX_QUICKSTART_DOCS_URL in by_name["install_method"].message

    assert by_name["optional_extras"].ok is False
    assert by_name["optional_extras"].details is not None
    assert by_name["optional_extras"].details["missing"] == ["langgraph", "crewai"]
    assert "langgraph" in by_name["optional_extras"].details["remediation"]


@pytest.mark.asyncio
async def test_mcp_smoke_fails_fast_without_optional_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "paybond_kit.cli.mcp_install.mcp_runtime_available",
        lambda: False,
    )
    stderr = io.StringIO()
    code = await run_cli(
        [
            "agent",
            "demo",
            "mcp",
            "smoke",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--evidence-preset",
            "cost_and_completion",
        ],
        stderr=stderr,
    )
    assert code != 0
    message = stderr.getvalue()
    assert "mcp extra" in message
    assert 'paybond-kit[mcp]' in message
    assert "pipx inject paybond-kit mcp" in message


@pytest.mark.asyncio
async def test_claude_agents_smoke_fails_fast_without_optional_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "paybond_kit.claude_agents.config.claude_agents_runtime_available",
        lambda: False,
    )
    stderr = io.StringIO()
    code = await run_cli(
        [
            "agent",
            "demo",
            "claude-agents",
            "smoke",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--evidence-preset",
            "cost_and_completion",
        ],
        stderr=stderr,
    )
    assert code != 0
    message = stderr.getvalue()
    assert "claude-agents extra" in message
    assert 'paybond-kit[claude-agents]' in message
    assert "pipx inject paybond-kit claude-agent-sdk" in message


@pytest.mark.asyncio
async def test_microsoft_agent_framework_smoke_fails_fast_without_optional_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "paybond_kit.microsoft_agent_framework._peer.microsoft_agent_framework_runtime_available",
        lambda: False,
    )
    stderr = io.StringIO()
    code = await run_cli(
        [
            "agent",
            "demo",
            "microsoft-agent-framework",
            "smoke",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--evidence-preset",
            "cost_and_completion",
        ],
        stderr=stderr,
    )
    assert code != 0
    message = stderr.getvalue()
    assert "microsoft-agent-framework extra" in message
    assert 'paybond-kit[microsoft-agent-framework]' in message
    assert "pipx inject paybond-kit agent-framework-core" in message
