"""Human-readable sandbox smoke checklist for table output."""

from __future__ import annotations

import os
from typing import Any

from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.core import GlobalOptions


def _format_usd_from_cents(cents: int) -> str:
    return f"${cents / 100:.2f}"


def format_agent_sandbox_smoke_checklist(
    *,
    preset_id: str | None,
    bind: dict[str, Any],
    execute: dict[str, Any],
    result_body: dict[str, Any],
    globals_: GlobalOptions,
) -> list[str]:
    use_color = should_use_color(globals_)

    def mark(line: str) -> str:
        if line.startswith("✓") or line == "Success":
            return colorize(line, "green", use_color)
        return line

    preset_label = (preset_id or "").strip()
    if not preset_label:
        policy_file = bind.get("policy_file")
        preset_label = os.path.basename(str(policy_file)) if policy_file else "custom"

    lines: list[str] = [mark(f"✓ Policy loaded ({preset_label})")]

    if bind.get("intent_id"):
        lines.append(mark("✓ Sandbox intent created"))

    operation = str(bind.get("operation") or "").strip()
    if operation:
        lines.append(mark(f"✓ Tool call: {operation}"))

    authorization = execute.get("authorization")
    if isinstance(authorization, dict) and authorization.get("allow"):
        cost_cents = result_body.get("cost_cents")
        if not isinstance(cost_cents, int):
            requested = bind.get("requested_spend_cents")
            cost_cents = requested if isinstance(requested, int) else None
        spend_label = _format_usd_from_cents(cost_cents) if isinstance(cost_cents, int) else "approved"
        lines.append(mark(f"✓ Spend approved ({spend_label})"))

    evidence = execute.get("evidence")
    if isinstance(evidence, dict) and evidence.get("submitted"):
        completion_preset = bind.get("completion_preset")
        preset = completion_preset if isinstance(completion_preset, str) and completion_preset else "cost_and_completion"
        lines.append(mark(f"✓ Evidence validated ({preset})"))
        lines.append(mark("✓ Settlement simulated"))

    lines.append(mark("Success"))
    return lines
