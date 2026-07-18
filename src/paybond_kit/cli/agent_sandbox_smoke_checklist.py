"""Human-readable sandbox smoke checklist for table output."""

from __future__ import annotations

import os
from typing import Any

from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.core import GlobalOptions


def _format_usd_from_cents(cents: int) -> str:
    return f"${cents / 100:.2f}"


def _format_cents_count(cents: int) -> str:
    return f"{cents:,} cents"


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
        requested = bind.get("requested_spend_cents")
        authorized_cents = (
            requested if isinstance(requested, int) and not isinstance(requested, bool) else None
        )
        lines.append(
            mark(
                "✓ Spend authorized"
                if authorized_cents is None
                else (
                    f"✓ Spend authorized up to {_format_usd_from_cents(authorized_cents)} "
                    f"({_format_cents_count(authorized_cents)})"
                )
            )
        )
        reported = result_body.get("cost_cents")
        if isinstance(reported, int) and not isinstance(reported, bool):
            lines.append(
                mark(
                    f"✓ Reported cost {_format_usd_from_cents(reported)} "
                    f"({_format_cents_count(reported)})"
                )
            )

    evidence = execute.get("evidence")
    if isinstance(evidence, dict) and evidence.get("submitted"):
        completion_preset = bind.get("completion_preset")
        preset = completion_preset if isinstance(completion_preset, str) and completion_preset else "cost_and_completion"
        lines.append(mark(f"✓ Evidence validated ({preset})"))
        lines.append(mark("✓ Settlement simulated"))

    lines.append(mark("Success"))
    return lines
