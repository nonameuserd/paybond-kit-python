"""Build canonical auto-evidence payloads from tool results."""

from __future__ import annotations

from typing import Any

from paybond_kit.agent.types import PaybondSideEffectingToolEntry, PaybondToolCallContext
from paybond_kit.completion_resolve import (
    is_vendor_pack,
    map_vendor_evidence_to_canonical,
    resolve_completion_preset,
)
from paybond_kit.stripe_commerce.evidence import assert_not_stripe_funding_webhook


def assert_tool_result_not_funding_webhook(tool_result: Any) -> None:
    """Reject Stripe funding webhook envelopes before they become completion evidence.

    Funding webhooks (``payment_intent.succeeded``, ``charge.*``, event envelopes) fund
    Harbor intents; tool-completion evidence must use SDK charge/result shapes (or mapped
    ``map_stripe_tool_result_to_evidence`` outputs), not webhook bodies.
    """
    if isinstance(tool_result, dict):
        assert_not_stripe_funding_webhook(tool_result)


def build_auto_evidence_payload(
    entry: PaybondSideEffectingToolEntry,
    tool_result: Any,
    ctx: PaybondToolCallContext,
) -> dict[str, Any]:
    """Build canonical evidence payloads from a tool result using the completion catalog.

    Fail-closed: Stripe funding webhook-shaped tool results are rejected before mapping.
    """
    assert_tool_result_not_funding_webhook(tool_result)

    if entry.evidence_mapper is not None:
        mapped = entry.evidence_mapper(tool_result, ctx)
        if not isinstance(mapped, dict):
            raise ValueError("evidence_mapper must return a JSON object payload")
        return dict(mapped)

    resolved = resolve_completion_preset(entry.evidence_preset)
    preset = resolved["preset"]
    if is_vendor_pack(preset):
        if isinstance(tool_result, dict):
            return map_vendor_evidence_to_canonical(preset, tool_result)
        raise ValueError(
            f'side-effecting tool "{ctx.tool_name}" uses vendor pack preset '
            f'"{entry.evidence_preset}"; provide evidence_mapper when tool result is not a dict'
        )

    if isinstance(tool_result, dict):
        return dict(tool_result)

    return dict(resolved["archetype"]["sample_evidence"])
