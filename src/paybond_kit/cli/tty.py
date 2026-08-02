"""TTY / non-interactive detection helpers for REPL and TUI commands."""

from __future__ import annotations

import os
import sys

from paybond_kit.cli.core import GlobalOptions


def _env_truthy(name: str) -> bool:
    value = (os.environ.get(name) or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def is_interactive_tty(
    stdin_is_tty: bool | None = None,
    stdout_is_tty: bool | None = None,
) -> bool:
    stdin_ok = sys.stdin.isatty() if stdin_is_tty is None else stdin_is_tty
    stdout_ok = sys.stdout.isatty() if stdout_is_tty is None else stdout_is_tty
    return bool(stdin_ok and stdout_ok)


def must_be_non_interactive(globals_: GlobalOptions) -> bool:
    if globals_.format == "json":
        return True
    if not is_interactive_tty():
        return True
    return _env_truthy("CI") or _env_truthy("PAYBOND_CLI_NONINTERACTIVE")
