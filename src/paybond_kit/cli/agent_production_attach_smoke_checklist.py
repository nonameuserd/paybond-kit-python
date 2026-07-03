"""Human-readable production attach smoke checklist for table output."""

from __future__ import annotations

from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.types import GlobalOptions


def format_agent_production_attach_smoke_checklist(
    *,
    bind: dict[str, object],
    execute: dict[str, object],
    globals_: GlobalOptions,
) -> list[str]:
    use_color = should_use_color(globals_)
    lines: list[str] = []

    def mark(line: str) -> str:
        if line.startswith("✓") or line == "Success":
            return colorize(line, "green", use_color)
        return line

    intent_id = str(bind.get("intent_id") or "").strip()
    if intent_id:
        lines.append(mark(f"✓ Production attach bound ({intent_id})"))

    operation = str(bind.get("operation") or "").strip()
    if operation:
        lines.append(mark(f"✓ Tool call: {operation}"))

    authorization = execute.get("authorization")
    if isinstance(authorization, dict) and authorization.get("allow"):
        lines.append(mark("✓ Spend approved"))

    evidence = execute.get("evidence")
    if isinstance(evidence, dict) and evidence.get("submitted"):
        lines.append(mark("✓ Harbor evidence submitted (/harbor/* + recognition)"))

    lines.append(mark("Success"))
    return lines
