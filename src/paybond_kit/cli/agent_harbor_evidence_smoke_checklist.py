"""Human-readable harbor proxy evidence smoke checklist for table output."""

from __future__ import annotations

from typing import Any

from paybond_kit.cli.color import colorize, should_use_color
from paybond_kit.cli.types import GlobalOptions


def format_agent_harbor_evidence_smoke_checklist(
    *,
    intent_id: str,
    evidence: dict[str, Any],
    globals_: GlobalOptions,
) -> list[str]:
    use_color = should_use_color(globals_)
    lines: list[str] = []

    def mark(line: str) -> str:
        if line.startswith("✓") or line == "Success":
            return colorize(line, "green", use_color)
        return line

    resolved_intent_id = intent_id.strip()
    if resolved_intent_id:
        lines.append(mark(f"✓ Intent {resolved_intent_id}"))
    lines.append(mark("✓ POST /harbor/intents/{id}/evidence (Kit payee + recognition proof)"))

    predicate_passed = evidence.get("predicate_passed", evidence.get("predicatePassed"))
    if predicate_passed is True:
        lines.append(mark("✓ Harbor accepted evidence (no recognition replay at upstream)"))

    lines.append(mark("Success"))
    return lines
