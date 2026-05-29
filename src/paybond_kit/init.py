"""Command-line scaffolder for Paybond spend guard wrappers."""

from __future__ import annotations

import argparse
from pathlib import Path

FRAMEWORK_NOTES = {
    "generic": "Wrap the returned function around any side-effecting tool handler.",
    "provider-agnostic": "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
    "openai-agents": "Attach the guard near your OpenAI Agents tool or guardrail wiring.",
    "claude": "Call the guarded handler before the Claude tool-use action performs paid or external work.",
    "anthropic": "Call the guarded handler before the Anthropic tool-use action performs paid or external work.",
    "gemini": "Call the guarded handler before the Gemini function call performs paid or external work.",
    "google-ai": "Call the guarded handler before the Google AI function call performs paid or external work.",
    "langgraph": "Call the guarded handler from the LangGraph node or tool wrapper that performs paid work.",
    "mcp": "Use the same operation name in your MCP tool handler before executing paid work.",
}


def _template(framework: str) -> str:
    note = FRAMEWORK_NOTES[framework]
    return f'''import os
import uuid

from paybond_kit import Paybond, PaybondCapabilityBinding, PaybondSpendGuard


async def book_hotel(city: str, max_price_cents: int) -> dict[str, str]:
    # Put the side-effecting tool call here.
    return {{"confirmation": f"demo-{{city}}-{{max_price_cents}}"}}


async def build_guarded_hotel_tool(
    *,
    intent_id: uuid.UUID,
    capability_token: str,
):
    paybond = await Paybond.open(
        api_key=os.environ["PAYBOND_API_KEY"],
        expected_environment="sandbox",
    )
    binding = PaybondCapabilityBinding(
        harbor=paybond.harbor,
        intent_id=intent_id,
        capability_token=capability_token,
    )
    guard = PaybondSpendGuard(binding)

    # {note}
    return guard.guard_tool(
        operation="travel.book_hotel",
        requested_spend_cents=20_000,
        handler=book_hotel,
    )
'''


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scaffold a Paybond spend guard wrapper for delegated agent spend controls."
    )
    parser.add_argument(
        "--framework",
        choices=sorted(FRAMEWORK_NOTES),
        default="generic",
    )
    parser.add_argument("--out", default="paybond_spend_guard.py")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    out = Path(args.out)
    if out.exists() and not args.force:
        parser.error(f"{out} already exists; pass --force to overwrite")
    out.write_text(_template(args.framework), encoding="utf-8")
    print(f"Created {out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
