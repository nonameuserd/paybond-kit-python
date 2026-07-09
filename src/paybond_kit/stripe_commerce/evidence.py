"""Map Stripe SDK tool results into completion-catalog evidence fields."""

from __future__ import annotations

from typing import Any

from paybond_kit.json_digest import json_value_digest
from paybond_kit.stripe_commerce.types import (
    CostAndCompletionEvidence,
    MapStripeToolResultToEvidenceOptions,
    StripeChargeVendorEvidence,
    StripeCommerceEvidencePreset,
)

STRIPE_COMMERCE_MAPPER_VERSION = "stripe_commerce_v1"

_STRIPE_FUNDING_EVENT_TYPES = frozenset(
    {
        "payment_intent.succeeded",
        "payment_intent.payment_failed",
        "payment_intent.canceled",
        "payment_intent.processing",
        "payment_intent.requires_action",
        "payment_intent.amount_capturable_updated",
        "charge.succeeded",
        "charge.failed",
        "charge.pending",
        "charge.refunded",
        "charge.updated",
        "charge.dispute.created",
        "charge.dispute.closed",
    }
)

_STRIPE_FUNDING_EVENT_PREFIXES = ("payment_intent.", "charge.", "payout.", "mandate.")


def _read_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _read_string(record: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _read_number(record: dict[str, Any], *keys: str) -> int | float | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
    return None


def _is_stripe_funding_event_type(event_type: str) -> bool:
    if event_type in _STRIPE_FUNDING_EVENT_TYPES:
        return True
    return any(event_type.startswith(prefix) for prefix in _STRIPE_FUNDING_EVENT_PREFIXES)


def assert_not_stripe_funding_webhook(input_record: dict[str, Any]) -> None:
    """Reject Stripe funding webhook envelopes used as tool-completion evidence."""
    object_kind = _read_string(input_record, "object")
    if object_kind == "event":
        raise ValueError(
            "Stripe event webhooks are funding signals, not tool-completion evidence"
        )

    event_type = _read_string(input_record, "type", "event_type", "eventType")
    if event_type and _is_stripe_funding_event_type(event_type):
        raise ValueError(
            f"{event_type} webhooks are funding signals, not tool-completion evidence"
        )

    event_id = _read_string(input_record, "id")
    if event_id and event_id.startswith("evt_") and event_type:
        raise ValueError(
            "Stripe event webhooks are funding signals, not tool-completion evidence"
        )

    data = _read_object(input_record.get("data"))
    if data and _read_object(data.get("object")):
        raise ValueError(
            "Stripe webhook data.object envelopes are funding signals, not tool-completion evidence"
        )

    if "pending_webhooks" in input_record and event_type is not None:
        raise ValueError(
            "Stripe event webhooks are funding signals, not tool-completion evidence"
        )


def _resolve_charge_id(record: dict[str, Any]) -> str:
    direct = _read_string(record, "charge_id", "chargeId")
    if direct:
        return direct

    latest_charge = record.get("latest_charge")
    if isinstance(latest_charge, str) and latest_charge.startswith("ch_"):
        return latest_charge
    latest_charge_object = _read_object(latest_charge)
    if latest_charge_object:
        nested_id = _read_string(latest_charge_object, "id")
        if nested_id and nested_id.startswith("ch_"):
            return nested_id

    top_level_id = _read_string(record, "id")
    if top_level_id and top_level_id.startswith("ch_"):
        return top_level_id

    raise ValueError("Stripe tool result missing charge_id")


def _resolve_cost_cents(record: dict[str, Any]) -> int:
    cost = _read_number(record, "cost_cents", "costCents", "amount_cents", "amountCents")
    if cost is None:
        cost = _read_number(record, "amount_received", "amountReceived")
    if cost is None:
        raise ValueError("Stripe tool result missing cost_cents")
    if not isinstance(cost, int) or cost < 0:
        raise ValueError("Stripe tool result cost_cents must be a non-negative integer")
    return cost


def _normalize_completion_status(status: str) -> str:
    normalized = status.strip().lower()
    if normalized in {"succeeded", "requires_capture"}:
        return "completed"
    return normalized


def _resolve_http_status(record: dict[str, Any], status: str) -> int:
    explicit = _read_number(record, "http_status", "httpStatus")
    if explicit is not None:
        return int(explicit)
    normalized = status.strip().lower()
    if normalized in {"succeeded", "requires_capture"}:
        return 200
    return 402


def _stripe_response_digest_hex(charge_id: str, cost_cents: int) -> str:
    digest_hex = json_value_digest({"charge_id": charge_id, "cost_cents": cost_cents}).hex()
    return f"blake3:{digest_hex}"


def _map_stripe_charge_evidence(record: dict[str, Any]) -> StripeChargeVendorEvidence:
    charge_id = _resolve_charge_id(record)
    status = _read_string(record, "status") or "succeeded"
    cost_cents = _resolve_cost_cents(record)
    return {
        "charge_id": charge_id,
        "http_status": _resolve_http_status(record, status),
        "response_digest": _stripe_response_digest_hex(charge_id, cost_cents),
    }


def _map_cost_and_completion_evidence(record: dict[str, Any]) -> CostAndCompletionEvidence:
    status = _read_string(record, "status")
    if not status:
        raise ValueError("Stripe tool result missing status")
    return {
        "status": _normalize_completion_status(status),
        "cost_cents": _resolve_cost_cents(record),
    }


def map_stripe_tool_result_to_evidence(
    tool_result: dict[str, Any],
    options: MapStripeToolResultToEvidenceOptions,
) -> StripeChargeVendorEvidence | CostAndCompletionEvidence:
    """Normalize Stripe SDK tool results into completion-catalog evidence fields."""
    assert_not_stripe_funding_webhook(tool_result)

    preset: StripeCommerceEvidencePreset = options["preset"]
    if preset == "stripe_charge":
        return _map_stripe_charge_evidence(tool_result)
    if preset == "cost_and_completion":
        return _map_cost_and_completion_evidence(tool_result)
    raise ValueError(f"map_stripe_tool_result_to_evidence: unsupported preset {preset}")
