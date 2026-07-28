"""Persist agent run context for CLI follow-up commands."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from paybond_kit.cli.automation import write_atomic_file
from paybond_kit.cli.agent_production_evidence import PersistedProductionEvidence
from paybond_kit.cli.agent_run_id import assert_path_inside_dir, assert_valid_agent_run_id
from paybond_kit.cli.core import CliError


@dataclass(frozen=True)
class PersistedAgentRunContext:
    run_id: str
    tenant_id: str
    intent_id: str
    capability_token: str
    operation: str
    allowed_tools: list[str]
    sandbox: bool
    sandbox_lifecycle_status: str | None = None
    requested_spend_cents: int | None = None
    completion_preset: str | None = None
    registry_file: str | None = None
    default_deny: bool | None = None
    policy_digest: str | None = None
    policy_version: str | None = None
    policy_loaded_at: str | None = None
    reload_watch: bool | None = None
    reload_poll: bool | None = None
    last_reload_at: str | None = None
    policy_bind_content: str | None = None
    production_evidence: PersistedProductionEvidence | None = None
    created_at: str = ""


def agent_runs_dir(cwd: Path) -> Path:
    return cwd / ".paybond" / "runs"


def agent_run_file_path(cwd: Path, run_id: str) -> Path:
    safe_id = assert_valid_agent_run_id(run_id)
    runs_dir = agent_runs_dir(cwd)
    return assert_path_inside_dir(runs_dir, runs_dir / f"{safe_id}.json")


def persist_agent_run_context(cwd: Path, context: PersistedAgentRunContext) -> Path:
    path = agent_run_file_path(cwd, context.run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": context.run_id,
        "tenant_id": context.tenant_id,
        "intent_id": context.intent_id,
        "capability_token": context.capability_token,
        "operation": context.operation,
        "allowed_tools": context.allowed_tools,
        "sandbox": context.sandbox,
        "sandbox_lifecycle_status": context.sandbox_lifecycle_status,
        "requested_spend_cents": context.requested_spend_cents,
        "completion_preset": context.completion_preset,
        "registry_file": context.registry_file,
        "default_deny": context.default_deny,
        "policy_digest": context.policy_digest,
        "policy_version": context.policy_version,
        "policy_loaded_at": context.policy_loaded_at,
        "reload_watch": context.reload_watch,
        "reload_poll": context.reload_poll,
        "last_reload_at": context.last_reload_at,
        "policy_bind_content": context.policy_bind_content,
        "production_evidence": context.production_evidence,
        "created_at": context.created_at or datetime.now(UTC).isoformat(),
    }
    write_atomic_file(path, json.dumps(payload, indent=2) + "\n", mode=0o600)
    return path


def load_agent_run_context(cwd: Path, run_id: str) -> dict[str, Any]:
    path = agent_run_file_path(cwd, run_id.strip())
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise CliError(
            f'unknown run_id "{run_id}"; run paybond agent run bind first',
            category="validation",
            code="cli.agent.unknown_run_id",
            details={"run_id": run_id, "path": str(path)},
        ) from exc
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise CliError(
            f"invalid run context at {path}",
            category="validation",
            code="cli.agent.invalid_run_context",
        )
    return parsed
