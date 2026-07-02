from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote

from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.dev.trace_buffer import dev_trace_url

_HARBOR_INTENT_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_DEFAULT_LOCAL_PUBLIC_ORIGIN = "http://127.0.0.1:3000"


def _strip_trailing_slashes(value: str) -> str:
    return value.rstrip("/")


def _resolve_public_origin() -> str:
    configured = (
        os.environ.get("PAYBOND_PUBLIC_BASE_URL", "").strip()
        or os.environ.get("PAYBOND_CONSOLE_BASE_URL", "").strip()
    )
    return _strip_trailing_slashes(configured or _DEFAULT_LOCAL_PUBLIC_ORIGIN)


def _resolve_console_origin() -> str:
    configured = (
        os.environ.get("PAYBOND_CONSOLE_BASE_URL", "").strip()
        or os.environ.get("PAYBOND_PUBLIC_BASE_URL", "").strip()
    )
    return _strip_trailing_slashes(configured or _DEFAULT_LOCAL_PUBLIC_ORIGIN)


def _harbor_intent_id(bind: dict[str, Any]) -> str | None:
    raw = bind.get("intent_id")
    if not isinstance(raw, str):
        return None
    trimmed = raw.strip()
    return trimmed if _HARBOR_INTENT_UUID.fullmatch(trimmed) else None


def build_agent_sandbox_smoke_deep_links(bind: dict[str, Any]) -> dict[str, str]:
    run_id = str(bind.get("run_id") or "smoke-1")
    links: dict[str, str] = {"trace_url": dev_trace_url(run_id=run_id)}

    intent_id = _harbor_intent_id(bind)
    if not intent_id:
        return links

    console_origin = _resolve_console_origin()
    public_origin = _resolve_public_origin()
    links["console_url"] = (
        f"{console_origin}/console/operations/intents/{quote(intent_id, safe='')}"
    )
    links["agent_trace_url"] = (
        f"{public_origin}/demo/agent-trace?intent={quote(intent_id, safe='')}"
    )
    return links


def append_smoke_deep_link_checklist_lines(
    checklist_lines: list[str],
    deep_links: dict[str, str],
    globals_: Any,
) -> list[str]:
    use_color = should_use_color(globals_)
    link_lines = [
        colorize(f"✓ Trace → {deep_links['trace_url']}", "green", use_color),
    ]
    console_url = deep_links.get("console_url")
    if console_url:
        link_lines.append(colorize(f"✓ Console → {console_url}", "green", use_color))
    agent_trace_url = deep_links.get("agent_trace_url")
    if agent_trace_url:
        link_lines.append(colorize(f"✓ Replay → {agent_trace_url}", "green", use_color))

    if not checklist_lines:
        return link_lines

    last = checklist_lines[-1]
    if last == "Success" or last == colorize("Success", "green", use_color):
        return [*checklist_lines[:-1], *link_lines, last]
    return [*checklist_lines, *link_lines]
