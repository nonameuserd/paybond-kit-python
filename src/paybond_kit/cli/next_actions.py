"""Structured what/why/next recovery guidance for CLI errors."""

from __future__ import annotations

from typing import Any

LOGIN_NEXT_COMMANDS: list[str] = [
    "paybond init",
    "paybond doctor",
    "paybond status",
]

KIT_HAPPY_PATH_COMMANDS: list[str] = [
    "paybond login",
    "paybond init",
    "paybond agent sandbox smoke --offline --operation paid-tool --requested-spend-cents 100 --evidence-preset cost_and_completion --result-body '{\"status\":\"ok\",\"cost_cents\":100}'",
    "paybond dev loop --offline",
    "paybond dev trace",
]


def with_next_actions(details: dict[str, Any] | None, *, what: str, why: str, next: str) -> dict[str, Any]:
    """Merge what/why/next fields into CliError details."""

    merged = dict(details or {})
    merged["what"] = what
    merged["why"] = why
    merged["next"] = next
    return merged


def read_next_actions(details: dict[str, Any] | None) -> dict[str, str] | None:
    if not details:
        return None
    what = str(details.get("what") or "").strip()
    why = str(details.get("why") or "").strip()
    next_cmd = str(details.get("next") or "").strip()
    if not what and not why and not next_cmd:
        return None
    return {
        "what": what or "command failed",
        "why": why or "see message",
        "next": next_cmd or "paybond doctor",
    }


def format_human_error_lines(message: str, details: dict[str, Any] | None) -> list[str]:
    lines = [message]
    actions = read_next_actions(details)
    if not actions:
        return lines
    lines.append(f"what: {actions['what']}")
    lines.append(f"why: {actions['why']}")
    lines.append(f"next: {actions['next']}")
    return lines
