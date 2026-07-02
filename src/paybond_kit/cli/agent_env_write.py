"""Append agent run env vars for downstream framework apps."""

from __future__ import annotations

import json
import re
from pathlib import Path


def _quote_env_value(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:@+-]+", value):
        return value
    return json.dumps(value)


def append_agent_run_env_vars(
    *,
    env_file: str,
    cwd: Path,
    intent_id: str,
    capability_token: str,
    run_id: str,
) -> str:
    env_path = Path(env_file) if Path(env_file).is_absolute() else cwd / env_file
    try:
        existing = env_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        existing = ""

    updates = {
        "PAYBOND_INTENT_ID": _quote_env_value(intent_id),
        "PAYBOND_CAPABILITY_TOKEN": _quote_env_value(capability_token),
        "PAYBOND_RUN_ID": _quote_env_value(run_id),
    }

    output: list[str] = []
    seen: set[str] = set()
    for raw_line in existing.splitlines():
        match = re.match(r"^\s*(?:export\s+)?([A-Z0-9_]+)\s*=", raw_line)
        if match and match.group(1) in updates:
            key = match.group(1)
            output.append(f"{key}={updates[key]}")
            seen.add(key)
            continue
        output.append(raw_line)
    for key, value in updates.items():
        if key not in seen:
            output.append(f"{key}={value}")

    body = "\n".join(output)
    if body and not body.endswith("\n"):
        body += "\n"
    env_path.write_text(body, encoding="utf-8")
    env_path.chmod(0o600)
    return str(env_path)
