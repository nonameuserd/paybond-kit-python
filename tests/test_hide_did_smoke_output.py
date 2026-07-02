"""Sandbox smoke CLI output must not surface DID or signing vocabulary."""

from __future__ import annotations

import re

from paybond_kit.cli.agent_sandbox_smoke_checklist import format_agent_sandbox_smoke_checklist
from paybond_kit.cli.core import GlobalOptions

_DID_VOCABULARY = (
    re.compile(r"\bdid:", re.I),
    re.compile(r"\bDID\b"),
    re.compile(r"payee[_-]did", re.I),
    re.compile(r"principal[_-]did", re.I),
    re.compile(r"signing[_\s-]seed", re.I),
    re.compile(r"recognition proof", re.I),
)


def test_sandbox_smoke_checklist_hides_did_vocabulary() -> None:
    lines = format_agent_sandbox_smoke_checklist(
        preset_id="travel",
        bind={
            "intent_id": "intent-1",
            "operation": "travel.book_hotel",
            "completion_preset": "cost_and_completion",
            "requested_spend_cents": 18700,
        },
        execute={
            "authorization": {"allow": True},
            "evidence": {"submitted": True},
        },
        result_body={"status": "completed", "cost_cents": 18700},
        globals_=GlobalOptions(
            gateway="https://api.paybond.ai",
            env_file=".env.local",
            format="table",
            color="never",
        ),
    )
    output = "\n".join(lines)
    for pattern in _DID_VOCABULARY:
        assert not pattern.search(output), f"smoke checklist must not match {pattern.pattern}"
