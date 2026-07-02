"""Human-readable agent run trace table output."""

from __future__ import annotations

from typing import Any

from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.core import GlobalOptions


def format_agent_run_trace_table(
    *,
    run_id: str,
    intent_id: str,
    steps: list[dict[str, Any]],
    globals: GlobalOptions,
) -> list[str]:
    use_color = should_use_color(globals)
    lines = [
        f"run_id: {run_id}",
        f"intent_id: {intent_id}",
        "",
    ]
    if not steps:
        lines.append("No trace events recorded.")
        return lines
    for step in steps:
        label = str(step.get("label", ""))
        lines.append(colorize(f"✓ {label}", "green", use_color) if label else "")
    return [line for line in lines if line]
