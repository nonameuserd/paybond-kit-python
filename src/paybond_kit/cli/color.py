from __future__ import annotations

import os
import sys
from typing import Literal, Protocol, TextIO

ColorMode = Literal["auto", "always", "never"]


class _ColorGlobals(Protocol):
    format: str
    color: str

ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "cyan": "\x1b[36m",
}


def resolve_color_mode_from_env() -> ColorMode:
    if os.environ.get("NO_COLOR", "").strip():
        return "never"
    return "auto"


def parse_color_mode(raw: str) -> ColorMode:
    value = raw.strip().lower()
    if value in ("auto", "always", "never"):
        return value
    raise ValueError("invalid --color (expected auto|always|never)")


def should_use_color(globals_: _ColorGlobals, stdout: TextIO | None = None) -> bool:
    if globals_.format == "json":
        return False
    if globals_.color == "never":
        return False
    if globals_.color == "always":
        return True
    stream = stdout or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def colorize(text: str, style: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{ANSI[style]}{text}{ANSI['reset']}"
