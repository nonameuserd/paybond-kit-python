from __future__ import annotations

from paybond_kit.cli.agent_sandbox_smoke_checklist import format_agent_sandbox_smoke_checklist
from paybond_kit.cli.core import GlobalOptions


def test_format_agent_sandbox_smoke_checklist_travel_preset() -> None:
    globals_ = GlobalOptions(
        gateway="https://api.paybond.ai",
        env_file=".env.local",
        format="table",
        color="never",
    )
    lines = format_agent_sandbox_smoke_checklist(
        preset_id="travel",
        bind={
            "intent_id": "intent-1",
            "operation": "travel.book_hotel",
            "completion_preset": "cost_and_completion",
            "requested_spend_cents": 20000,
        },
        execute={
            "authorization": {"allow": True},
            "evidence": {"submitted": True},
        },
        result_body={"status": "completed", "cost_cents": 18700},
        globals_=globals_,
    )
    assert lines == [
        "✓ Policy loaded (travel)",
        "✓ Sandbox intent created",
        "✓ Tool call: travel.book_hotel",
        "✓ Spend authorized up to $200.00 (20,000 cents)",
        "✓ Reported cost $187.00 (18,700 cents)",
        "✓ Evidence validated (cost_and_completion)",
        "✓ Settlement simulated",
        "Success",
    ]
