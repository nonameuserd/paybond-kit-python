from __future__ import annotations

import pytest

from paybond_kit.agent.evidence import (
    assert_tool_result_not_funding_webhook,
    build_auto_evidence_payload,
)
from paybond_kit.agent.types import PaybondSideEffectingToolEntry, PaybondToolCallContext
from paybond_kit.json_digest import json_value_digest
from paybond_kit.stripe_commerce import map_stripe_tool_result_to_evidence

SAMPLE_CHARGE_RESULT = {
    "payment_intent_id": "pi_3NxExample",
    "charge_id": "ch_3NxExample",
    "cost_cents": 1250,
    "status": "succeeded",
}

FUNDING_WEBHOOK = {
    "id": "evt_123",
    "object": "event",
    "type": "payment_intent.succeeded",
    "data": {
        "object": {
            "id": "pi_123",
            "metadata": {
                "tenant_id": "tenant-a",
                "paybond_intent_id": "00000000-0000-0000-0000-000000000111",
            },
        }
    },
}


def test_rejects_stripe_funding_webhook_as_completion_evidence() -> None:
    with pytest.raises(ValueError, match="funding signals"):
        assert_tool_result_not_funding_webhook(FUNDING_WEBHOOK)

    entry = PaybondSideEffectingToolEntry(
        tool_name="payments.charge_customer",
        operation="payments.charge_customer",
        evidence_preset="stripe_charge",
    )
    ctx = PaybondToolCallContext(
        tool_name="payments.charge_customer",
        tool_call_id="call-1",
        operation="payments.charge_customer",
        arguments={},
    )
    with pytest.raises(ValueError, match="funding signals"):
        build_auto_evidence_payload(entry, FUNDING_WEBHOOK, ctx)


def test_accepts_legitimate_stripe_charge_and_cost_evidence() -> None:
    mapped = map_stripe_tool_result_to_evidence(
        SAMPLE_CHARGE_RESULT, {"preset": "stripe_charge"}
    )
    expected_digest = f"blake3:{json_value_digest({'charge_id': 'ch_3NxExample', 'cost_cents': 1250}).hex()}"
    assert mapped == {
        "charge_id": "ch_3NxExample",
        "http_status": 200,
        "response_digest": expected_digest,
    }

    entry = PaybondSideEffectingToolEntry(
        tool_name="paid-tool",
        operation="paid-tool",
        evidence_preset="cost_and_completion",
    )
    ctx = PaybondToolCallContext(
        tool_name="paid-tool",
        tool_call_id="call-2",
        operation="paid-tool",
        arguments={},
    )
    payload = build_auto_evidence_payload(entry, {"status": "ok", "cost_cents": 100}, ctx)
    assert payload == {"status": "ok", "cost_cents": 100}


def test_accepts_mapped_stripe_charge_evidence_objects() -> None:
    mapped = map_stripe_tool_result_to_evidence(
        SAMPLE_CHARGE_RESULT, {"preset": "stripe_charge"}
    )
    assert_tool_result_not_funding_webhook(mapped)
