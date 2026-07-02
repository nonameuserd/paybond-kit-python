"""Resolve dot-separated JSON paths from tool call arguments."""

from __future__ import annotations

from typing import Any

from paybond_kit.policy.schema import PaybondPolicyValidationError


def resolve_json_path(args: object, path: str) -> Any:
    """Read a dot-separated JSON path from tool call arguments."""
    current: Any = args
    for segment in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def resolve_spend_cents_from_json_path(args: object, path: str, tool_name: str) -> int | None:
    """Resolve non-negative integer spend cents from a JSON path at intercept time."""
    value = resolve_json_path(args, path)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PaybondPolicyValidationError(
            f'tool "{tool_name}" spend_from_args path "{path}" must resolve to a non-negative integer'
        )
    return value
