"""Reject secret-valued CLI argv flags; prefer files or environment variables."""

from __future__ import annotations

import os
from pathlib import Path

from paybond_kit.cli.core import CliError, consume_flag


def reject_secret_argv_flag(argv: list[str], flag: str, alternatives: str) -> list[str]:
    """
    Reject secret-valued CLI flags that leak via shell history / process listings.

    Prefer env vars or ``--*-file`` paths mode 0600.
    """
    present, _value, rest = consume_flag(argv, flag)
    if present:
        raise CliError(
            f"{flag} is rejected (secrets must not appear on argv); use {alternatives}",
            category="usage",
            code="cli.secret.argv_rejected",
            details={"flag": flag},
        )
    return rest


def read_secret_file_flag(argv: list[str], file_flag: str, cwd: Path) -> tuple[str | None, list[str]]:
    """Read a secret from ``--flag-file`` (trimmed) when present."""
    _present, value, rest = consume_flag(argv, file_flag)
    trimmed = (value or "").strip()
    if not trimmed:
        return None, rest
    path = Path(trimmed)
    if not path.is_absolute():
        path = cwd / path
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise CliError(
            f"unable to read {file_flag}: {exc}",
            category="usage",
            code="cli.secret.file_unreadable",
            details={"flag": file_flag, "path": str(path)},
        ) from exc
    if not raw:
        raise CliError(
            f"{file_flag} points to an empty file",
            category="usage",
            code="cli.secret.empty_file",
            details={"flag": file_flag, "path": str(path)},
        )
    return raw, rest


def resolve_secret_from_file_or_env(
    *,
    argv: list[str],
    cwd: Path,
    rejected_flag: str,
    file_flag: str,
    env_name: str,
    alternatives: str,
) -> tuple[str | None, list[str]]:
    """Resolve a secret from file flag, else process env (never argv value flags)."""
    after_reject = reject_secret_argv_flag(argv, rejected_flag, alternatives)
    from_file, rest = read_secret_file_flag(after_reject, file_flag, cwd)
    if from_file:
        return from_file, rest
    from_env = os.environ.get(env_name, "").strip()
    return (from_env or None), rest
