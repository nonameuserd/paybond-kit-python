"""Shopify commerce evidence mapping."""

from __future__ import annotations

from typing import Any

from paybond_kit.shopify.types import MapShopifyToolResultToEvidenceOptions

SHOPIFY_COMMERCE_MAPPER_VERSION = "shopify_commerce_v1"

_SHOPIFY_FUNDING_TOPICS = {
    "orders/create",
    "orders/paid",
    "orders/updated",
    "orders/cancelled",
    "orders/fulfilled",
    "refunds/create",
}


def _read_string(record: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _read_number(record: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, int):
            return value
    return None


def assert_not_shopify_funding_webhook(input_payload: dict[str, Any]) -> None:
    """Reject Shopify order webhook envelopes used as tool-completion evidence."""
    topic = _read_string(input_payload, "topic", "X-Shopify-Topic")
    if topic and topic in _SHOPIFY_FUNDING_TOPICS:
        raise ValueError(f"{topic} webhooks are funding signals, not tool-completion evidence")

    if _read_string(input_payload, "X-Shopify-Shop-Domain") and _read_string(
        input_payload, "X-Shopify-Webhook-Id"
    ):
        raise ValueError(
            "Shopify webhook envelopes are funding signals, not tool-completion evidence"
        )

    admin_graphql_id = _read_string(input_payload, "admin_graphql_api_id")
    order_number = _read_string(input_payload, "order_number")
    if admin_graphql_id and "gid://shopify/Order/" in admin_graphql_id and order_number and "status" not in input_payload:
        raise ValueError(
            "Shopify order webhook payloads are funding signals, not tool-completion evidence"
        )


def map_shopify_tool_result_to_evidence(
    tool_result: dict[str, Any],
    options: MapShopifyToolResultToEvidenceOptions,
) -> dict[str, Any]:
    """Normalize Shopify checkout tool results into completion-catalog evidence."""
    assert_not_shopify_funding_webhook(tool_result)
    preset = options["preset"]
    if preset != "cost_and_completion":
        raise ValueError(f"map_shopify_tool_result_to_evidence: unsupported preset {preset}")

    status = _read_string(tool_result, "status")
    if not status:
        raise ValueError("Shopify tool result missing status")
    cost_cents = _read_number(tool_result, "cost_cents", "costCents", "amount_cents", "amountCents")
    if cost_cents is None:
        raise ValueError("Shopify tool result missing cost_cents")
    if cost_cents < 0:
        raise ValueError("Shopify tool result cost_cents must be a non-negative integer")
    return {"status": status, "cost_cents": cost_cents}
