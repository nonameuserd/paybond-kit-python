"""Validate agent run IDs and contain paths under ``.paybond/runs/``."""

from __future__ import annotations

import re
from pathlib import Path

from paybond_kit.cli.core import CliError

_AGENT_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def assert_valid_agent_run_id(run_id: str) -> str:
    """
    Validate a CLI/API agent run id (UUID or strict slug).

    Rejects path traversal payloads such as ``../../package``.
    """
    trimmed = run_id.strip()
    if (
        not trimmed
        or not _AGENT_RUN_ID_RE.fullmatch(trimmed)
        or trimmed in {".", ".."}
    ):
        raise CliError(
            f"invalid run_id {run_id!r}; expected a UUID or slug matching "
            "[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
            category="validation",
            code="cli.agent.invalid_run_id",
            details={"run_id": run_id},
        )
    return trimmed


def assert_path_inside_dir(root_dir: Path, candidate: Path) -> Path:
    """Ensure ``candidate`` resolves strictly beneath ``root_dir``."""
    root = root_dir.resolve()
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise CliError(
            f"run path escapes runs directory: {candidate}",
            category="validation",
            code="cli.agent.run_path_escape",
            details={"root": str(root_dir), "path": str(candidate)},
        ) from exc
    if resolved == root:
        raise CliError(
            f"run path escapes runs directory: {candidate}",
            category="validation",
            code="cli.agent.run_path_escape",
            details={"root": str(root_dir), "path": str(candidate)},
        )
    return resolved
