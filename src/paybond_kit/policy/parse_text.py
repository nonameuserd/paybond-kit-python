"""Parse paybond.policy.yaml / JSON policy file text."""

from __future__ import annotations

import json
import re
from typing import Any

from paybond_kit.policy.schema import PaybondPolicyValidationError

_YAML_LINE_RE = re.compile(r"^([^:]+?):\s*(.*)$")


def _tokenize_yaml_lines(text: str) -> list[tuple[int, str, str]]:
    lines: list[tuple[int, str, str]] = []
    for raw in text.splitlines():
        trimmed = raw.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, trimmed, raw))
    return lines


def _parse_yaml_scalar(value: str) -> Any:
    if not value:
        return ""
    if value == "true":
        return True
    if value == "false":
        return False
    if value.lstrip("-").isdigit():
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def _parse_yaml_block(
    lines: list[tuple[int, str, str]],
    start: int,
    indent: int,
    source_label: str,
) -> tuple[Any, int]:
    if start >= len(lines) or lines[start][0] < indent:
        return {}, start

    if lines[start][1].startswith("- "):
        items: list[Any] = []
        index = start
        while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            after_dash = lines[index][1][2:].strip()
            if not after_dash:
                child, next_index = _parse_yaml_block(lines, index + 1, indent + 2, source_label)
                items.append(child)
                index = next_index
                continue
            inline_match = _YAML_LINE_RE.match(after_dash)
            if inline_match and not inline_match.group(2):
                key = inline_match.group(1).strip()
                child, next_index = _parse_yaml_block(lines, index + 1, indent + 2, source_label)
                items.append({key: child})
                index = next_index
                continue
            if inline_match:
                items.append({inline_match.group(1).strip(): _parse_yaml_scalar(inline_match.group(2).strip())})
                index += 1
                continue
            items.append(_parse_yaml_scalar(after_dash))
            index += 1
        return items, index

    object_value: dict[str, Any] = {}
    index = start
    while index < len(lines) and lines[index][0] == indent:
        match = _YAML_LINE_RE.match(lines[index][1])
        if not match:
            raise PaybondPolicyValidationError(
                f"{source_label} has invalid YAML line: {lines[index][2]}",
                path=source_label,
            )
        key = match.group(1).strip()
        rest = match.group(2).strip()
        if rest:
            object_value[key] = _parse_yaml_scalar(rest)
            index += 1
            continue
        child, next_index = _parse_yaml_block(lines, index + 1, indent + 2, source_label)
        object_value[key] = child
        index = next_index
    return object_value, index


def _parse_indented_yaml(text: str, source_label: str) -> dict[str, Any]:
    lines = _tokenize_yaml_lines(text)
    if not lines:
        raise PaybondPolicyValidationError(f"{source_label} is empty", path=source_label)
    value, _ = _parse_yaml_block(lines, 0, lines[0][0], source_label)
    if not isinstance(value, dict):
        raise PaybondPolicyValidationError(f"{source_label} must be a YAML object", path=source_label)
    return value


def parse_policy_document_text(text: str, source_label: str = "policy file") -> dict[str, Any]:
    """Parse policy file text (JSON or YAML) into a raw document object."""
    trimmed = text.strip()
    if not trimmed:
        raise PaybondPolicyValidationError(f"{source_label} is empty", path=source_label)
    try:
        parsed = json.loads(trimmed)
    except json.JSONDecodeError:
        return _parse_indented_yaml(trimmed, source_label)
    if not isinstance(parsed, dict):
        raise PaybondPolicyValidationError(f"{source_label} must be a JSON object", path=source_label)
    return parsed
