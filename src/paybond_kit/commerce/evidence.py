"""Evidence mapping for multi-provider commerce.checkout results."""

from __future__ import annotations

from typing import Any

from paybond_kit.commerce.types import (
    CommerceCheckoutEvidencePreset,
    MapCommerceCheckoutResultToEvidenceOptions,
)

COMMERCE_CHECKOUT_MAPPER_VERSION = "commerce_checkout_v1"

_KNOWN_PROVIDERS: frozenset[str] = frozenset({"shopify", "stripe", "zinc"})


def _read_string(record: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _read_number(record: dict[str, Any], *keys: str) -> float | int | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int | float) and value == value:  # not NaN
            return value
    return None


def _resolve_cost_cents(record: dict[str, Any]) -> int:
    # Fail closed: never invent cost_cents from amount_cents / amountCents.
    if "cost_cents" not in record and "costCents" not in record:
        raise ValueError("commerce.checkout tool result missing cost_cents")
    raw = record["cost_cents"] if "cost_cents" in record else record["costCents"]
    if raw is None:
        raise ValueError("commerce.checkout tool result missing cost_cents")
    cost = _read_number({"cost_cents": raw}, "cost_cents")
    if cost is None:
        raise ValueError(
            "commerce.checkout tool result cost_cents must be a non-negative integer"
        )
    if not isinstance(cost, int) or isinstance(cost, bool) or cost < 0:
        raise ValueError(
            "commerce.checkout tool result cost_cents must be a non-negative integer"
        )
    return cost


def map_commerce_checkout_result_to_evidence(
    tool_result: object,
    options: MapCommerceCheckoutResultToEvidenceOptions,
) -> dict[str, Any]:
    """Normalize multi-provider commerce.checkout results into completion evidence.

    Status + ``cost_cents`` are required. Optional ``provider`` and ``order_id``
    are preserved when present. Other provider-specific fields (``shop``,
    ``payment_intent_id``, ``zinc_request_id``) are ignored for the
    ``cost_and_completion`` preset.
    """

    if not isinstance(tool_result, dict):
        raise ValueError("commerce.checkout tool result must be an object")

    preset: CommerceCheckoutEvidencePreset = options["preset"]
    if preset != "cost_and_completion":
        raise ValueError(f"map_commerce_checkout_result_to_evidence: unsupported preset {preset}")

    status = _read_string(tool_result, "status")
    if not status:
        raise ValueError("commerce.checkout tool result missing status")

    evidence: dict[str, Any] = {
        "status": status,
        "cost_cents": _resolve_cost_cents(tool_result),
    }

    provider = _read_string(tool_result, "provider")
    if provider in _KNOWN_PROVIDERS:
        evidence["provider"] = provider

    order_id = _read_string(tool_result, "order_id", "orderId")
    if order_id:
        evidence["order_id"] = order_id

    return evidence
