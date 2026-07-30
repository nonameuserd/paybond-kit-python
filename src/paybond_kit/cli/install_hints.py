"""Shared optional-extra and pipx install hints for CLI and doctor checks."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from paybond_kit.cli.doctor_agent import DoctorCheck

InstallMethod = Literal["pipx", "venv", "system"]

PIPX_QUICKSTART_DOCS_URL = "https://paybond.ai/docs/kit/quickstart-python#pipx-global-cli"


@dataclass(frozen=True, slots=True)
class OptionalExtraSpec:
    """Metadata for an optional paybond-kit extra and its framework smoke command."""

    extra_id: str
    available: Callable[[], bool]
    inject_packages: tuple[str, ...]
    smoke_command: str


def detect_paybond_install_method() -> InstallMethod:
    """Best-effort detection of how paybond-kit was installed in this interpreter."""

    prefix = Path(sys.prefix).resolve()
    pipx_home = os.environ.get("PIPX_HOME")
    pipx_root = Path(pipx_home).resolve() if pipx_home else Path.home() / ".local" / "pipx"
    pipx_venvs = pipx_root / "venvs"

    prefix_text = str(prefix)
    if "pipx" in prefix_text or prefix_text.startswith(str(pipx_venvs)):
        return "pipx"

    if os.environ.get("VIRTUAL_ENV"):
        return "venv"

    base_prefix = getattr(sys, "base_prefix", sys.prefix)
    if base_prefix != sys.prefix:
        return "venv"

    return "system"


def _optional_extra_specs() -> tuple[OptionalExtraSpec, ...]:
    from paybond_kit.claude_agents.config import claude_agents_runtime_available
    from paybond_kit.cli.mcp_install import mcp_runtime_available
    from paybond_kit.crewai._peer import crewai_runtime_available
    from paybond_kit.langgraph_hooks import langgraph_runtime_available
    from paybond_kit.openai_agents._peer import openai_agents_runtime_available
    from paybond_kit.pydantic_ai._peer import pydantic_ai_runtime_available
    from paybond_kit.google_adk._peer import google_adk_runtime_available
    from paybond_kit.microsoft_agent_framework._peer import (
        microsoft_agent_framework_runtime_available,
    )

    return (
        OptionalExtraSpec(
            extra_id="langgraph",
            available=langgraph_runtime_available,
            inject_packages=("langgraph", "langchain-core"),
            smoke_command="agent demo langgraph smoke",
        ),
        OptionalExtraSpec(
            extra_id="mcp",
            available=mcp_runtime_available,
            inject_packages=("mcp",),
            smoke_command="agent demo mcp smoke",
        ),
        OptionalExtraSpec(
            extra_id="claude-agents",
            available=claude_agents_runtime_available,
            inject_packages=("claude-agent-sdk",),
            smoke_command="agent demo claude-agents smoke",
        ),
        OptionalExtraSpec(
            extra_id="crewai",
            available=crewai_runtime_available,
            inject_packages=("crewai",),
            smoke_command="agent demo crewai smoke",
        ),
        OptionalExtraSpec(
            extra_id="pydantic-ai",
            available=pydantic_ai_runtime_available,
            inject_packages=("pydantic-ai",),
            smoke_command="agent demo pydantic-ai smoke",
        ),
        OptionalExtraSpec(
            extra_id="google-adk",
            available=google_adk_runtime_available,
            inject_packages=("google-adk",),
            smoke_command="agent demo google-adk smoke",
        ),
        OptionalExtraSpec(
            extra_id="microsoft-agent-framework",
            available=microsoft_agent_framework_runtime_available,
            inject_packages=("agent-framework-core",),
            smoke_command="agent demo microsoft-agent-framework smoke",
        ),
        OptionalExtraSpec(
            extra_id="openai-agents",
            available=openai_agents_runtime_available,
            inject_packages=("openai-agents",),
            smoke_command="agent demo openai-agents smoke",
        ),
    )


def format_missing_extra_message(*, command: str, extra_id: str, inject_packages: tuple[str, ...]) -> str:
    """Return a consistent CLI error hint when an optional extra is not installed."""

    pip_spec = f'pip install "paybond-kit[{extra_id}]"'
    inject = "pipx inject paybond-kit " + " ".join(inject_packages)
    one_shot = f"pipx run --spec 'paybond-kit[{extra_id}]' paybond {command} ..."
    return (
        f"{command} requires the optional {extra_id} extra; "
        f"install with {pip_spec}, {inject} (if base paybond-kit is installed), or {one_shot}"
    )


def _format_extra_remediation(extra_id: str, inject_packages: tuple[str, ...], method: InstallMethod) -> str:
    pip_spec = f'pip install "paybond-kit[{extra_id}]"'
    if method == "pipx":
        inject = "pipx inject paybond-kit " + " ".join(inject_packages)
        return f'{pip_spec}, pipx install \'paybond-kit[{extra_id}]\', or {inject}'
    return pip_spec


def run_install_context_doctor_checks() -> list[DoctorCheck]:
    """Report install method and optional framework extras for `paybond doctor --agent`."""

    method = detect_paybond_install_method()
    if method == "pipx":
        install_message = (
            "pipx global install detected; add optional extras with "
            f"pipx inject paybond-kit <packages> — see {PIPX_QUICKSTART_DOCS_URL}"
        )
    elif method == "venv":
        install_message = (
            "virtual environment detected; install optional extras with "
            f'pip install "paybond-kit[<extra>]" — see {PIPX_QUICKSTART_DOCS_URL}'
        )
    else:
        install_message = (
            "system Python install detected; use a venv or pipx for optional extras — "
            f"see {PIPX_QUICKSTART_DOCS_URL}"
        )

    checks: list[DoctorCheck] = [
        DoctorCheck(
            name="install_method",
            ok=True,
            message=install_message,
            details={"method": method, "docs_url": PIPX_QUICKSTART_DOCS_URL},
        )
    ]

    missing: list[str] = []
    remediation: dict[str, str] = {}
    for spec in _optional_extra_specs():
        if spec.available():
            continue
        missing.append(spec.extra_id)
        remediation[spec.extra_id] = _format_extra_remediation(
            spec.extra_id,
            spec.inject_packages,
            method,
        )

    if missing:
        missing_list = ", ".join(missing)
        checks.append(
            DoctorCheck(
                name="optional_extras",
                ok=False,
                message=(
                    f"optional extras not installed: {missing_list}; "
                    f"framework demo smokes need them — see {PIPX_QUICKSTART_DOCS_URL}"
                ),
                details={"missing": missing, "remediation": remediation, "method": method},
            )
        )
    else:
        checks.append(
            DoctorCheck(
                name="optional_extras",
                ok=True,
                message="langgraph, mcp, claude-agents, crewai, pydantic-ai, google-adk, and microsoft-agent-framework optional extras are importable",
            )
        )

    return checks
