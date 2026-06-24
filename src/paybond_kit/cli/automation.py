from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, TextIO

from paybond_kit.cli.core import CliError

CLI_WARN_PARTIAL_RESULTS = "cli.warn.partial_results"
CLI_WARN_GATEWAY_RETRY = "cli.warn.gateway_retry"
CLI_WARN_DEPRECATED_ALIAS = "cli.warn.deprecated_alias"
CLI_WARN_ENV_FALLBACK = "cli.warn.env_fallback"

LEGACY_INVOCATION_ALIASES = {
    "paybond-kit-login": "paybond login",
    "paybond-init": "paybond init guardrail",
    "paybond-kit-init": "paybond init guardrail",
    "paybond-mcp-server": "paybond mcp serve",
}

LIST_ARRAY_KEYS = ("items", "keys", "exports", "intents", "tools", "entries", "contracts", "jobs")


def format_warning(code: str, detail: str | None = None) -> str:
    return f"{code}: {detail}" if detail else code


def deprecated_alias_warning(argv0: str | None) -> str | None:
    base = Path(argv0 or "").name
    canonical = LEGACY_INVOCATION_ALIASES.get(base)
    if not canonical:
        return None
    return format_warning(CLI_WARN_DEPRECATED_ALIAS, f"use {canonical} instead of {base}")


def parse_json_fields(raw: str) -> list[str]:
    fields = [part.strip() for part in raw.split(",") if part.strip()]
    if not fields:
        raise CliError("invalid --json (expected comma-separated field names)", code="cli.usage.invalid_json_fields")
    return fields


def _read_nested_field(row: dict[str, Any], field: str) -> Any:
    current: Any = row
    for part in field.split("."):
        if not part:
            continue
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def select_json_fields(rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for row in rows:
        item: dict[str, Any] = {}
        for field in fields:
            item[field] = _read_nested_field(row, field) if "." in field else row.get(field)
        selected.append(item)
    return selected


def extract_list_array(data: dict[str, Any]) -> list[dict[str, Any]] | None:
    for key in LIST_ARRAY_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return None


def apply_json_field_selection(command: str, data: dict[str, Any], fields: list[str]) -> Any:
    rows = extract_list_array(data)
    if rows is not None:
        return select_json_fields(rows, fields)
    selected = select_json_fields([data], fields)
    return selected[0] if selected else {}


def _try_simple_jq_path(data: Any, expr: str) -> Any | None:
    trimmed = expr.strip()
    if not trimmed or trimmed == ".":
        return data
    current: Any = data
    for part in [segment.strip() for segment in trimmed.split("|")]:
        if part == ".":
            continue
        if part == ".[]":
            if not isinstance(current, list):
                return None
            continue
        if part.endswith("[]"):
            key = part[:-2]
            if key == ".":
                if not isinstance(current, list):
                    return None
                continue
            if not key.startswith(".") or not isinstance(current, dict):
                return None
            nested = current.get(key[1:])
            if not isinstance(nested, list):
                return None
            current = nested
            continue
        if part.startswith("."):
            import re

            match = re.match(r"^\.([^.[]+)(\[\])(?:\.(.+))?$", part)
            if match:
                field, _, subfield = match.groups()
                if not isinstance(current, dict):
                    return None
                nested = current.get(field)
                if not isinstance(nested, list):
                    return None
                if not subfield:
                    current = nested
                    continue
                current = [
                    item.get(subfield)
                    for item in nested
                    if isinstance(item, dict)
                ]
                continue
            for segment in part[1:].split("."):
                if not segment:
                    continue
                if not isinstance(current, dict):
                    return None
                current = current.get(segment)
            continue
        return None
    return current


def _run_jq_binary(data: Any, expr: str) -> Any | None:
    try:
        result = subprocess.run(
            ["jq", "-c", expr],
            input=json.dumps(data),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    if not output:
        return None
    return json.loads(output)


def apply_jq_filter(data: Any, expr: str) -> Any:
    trimmed = expr.strip()
    if not trimmed or trimmed == ".":
        return data
    simple = _try_simple_jq_path(data, trimmed)
    if simple is not None:
        return simple
    from_binary = _run_jq_binary(data, trimmed)
    if from_binary is not None:
        return from_binary
    raise CliError(f"invalid --jq expression: {expr}", code="cli.usage.invalid_jq")


def supports_automation_output(command: str) -> bool:
    return (
        command.endswith(" list")
        or command.endswith(" get")
        or command == "whoami"
        or command == "mcp tools"
        or command == "a2a contracts"
        or command == "a2a card"
    )


def apply_automation_transforms(
    command: str,
    data: dict[str, Any],
    *,
    json_fields: str | None = None,
    jq_expr: str | None = None,
) -> Any:
    if not supports_automation_output(command):
        if json_fields or jq_expr:
            raise CliError(f"--json/--jq are not supported for {command}", code="cli.usage.automation_unsupported")
        return data
    current: Any = data
    if json_fields:
        current = apply_json_field_selection(command, data, parse_json_fields(json_fields))
    if jq_expr:
        current = apply_jq_filter(current, jq_expr)
    return current


def extract_next_cursor(body: dict[str, Any]) -> str | None:
    raw = body.get("next_cursor") or body.get("nextCursor") or body.get("cursor_next")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def partial_results_warning(next_cursor: str | None) -> str | None:
    if not next_cursor:
        return None
    return format_warning(CLI_WARN_PARTIAL_RESULTS, "more items available; pass --cursor")


def build_list_query_params(limit: str | None, cursor: str | None, *, default_limit: str = "20") -> str:
    from urllib.parse import urlencode

    query: dict[str, str] = {"limit": limit.strip() if limit and limit.strip() else default_limit}
    if cursor and cursor.strip():
        query["cursor"] = cursor.strip()
    return urlencode(query)


def read_json_body(source: str, stdin: TextIO | None = None) -> dict[str, Any]:
    normalized = source.strip()
    if normalized in ("-", "stdin"):
        stream = stdin or sys.stdin
        raw = stream.read()
    else:
        raw = Path(normalized).read_text(encoding="utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise CliError("JSON body must be an object", category="validation", code="cli.validation.invalid_json_body")
    return parsed


def write_atomic_file(path: str | Path, content: str | bytes, mode: int = 0o600) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=".paybond-write-", dir=str(target.parent)))
    temp_file = temp_dir / "payload"
    try:
        if isinstance(content, str):
            temp_file.write_text(content, encoding="utf-8")
        else:
            temp_file.write_bytes(content)
        os.chmod(temp_file, mode)
        os.replace(temp_file, target)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
