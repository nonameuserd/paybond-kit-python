"""Shopify UCP checkout payload helpers with binding injection."""

from __future__ import annotations

from typing import cast

from paybond_kit.commerce_binding import encode_commerce_binding_to_shopify_note_attributes
from paybond_kit.shopify.types import (
    CreateCheckoutWithBindingParams,
    ShopifyCheckoutCreatePayload,
    ShopifyCheckoutLineItemInput,
    ShopifyNoteAttribute,
)

PAYBOND_UCP_AGENT_PROFILE_URL = "https://paybond.ai/.well-known/ucp/profile.json"
PAYBOND_SHOPIFY_UCP_VERSION = "2026-04-08"


def _require_non_empty(value: str, label: str) -> str:
    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"shopify checkout: {label} is required")
    return trimmed


def _normalize_variant_gid(variant_id: str) -> str:
    trimmed = variant_id.strip()
    if not trimmed:
        raise ValueError("shopify checkout: line item variant_id is required")
    if trimmed.startswith("gid://shopify/ProductVariant/"):
        return trimmed
    if trimmed.isdigit():
        return f"gid://shopify/ProductVariant/{trimmed}"
    return trimmed


def to_ucp_checkout_line_items(
    line_items: list[ShopifyCheckoutLineItemInput],
) -> list[dict[str, object]]:
    if not line_items:
        raise ValueError("shopify checkout: at least one line item is required")
    normalized: list[dict[str, object]] = []
    for entry in line_items:
        quantity = entry["quantity"]
        if not isinstance(quantity, int) or quantity <= 0:
            raise ValueError("shopify checkout: line item quantity must be a positive integer")
        normalized.append(
            {
                "item": {"id": _normalize_variant_gid(entry["variant_id"])},
                "quantity": quantity,
            }
        )
    return normalized


def create_checkout_with_binding(
    params: CreateCheckoutWithBindingParams,
) -> ShopifyCheckoutCreatePayload:
    """Build a UCP checkout payload with canonical Paybond binding metadata."""
    tenant_id = _require_non_empty(params["tenant_id"], "tenant_id")
    intent_id = _require_non_empty(params["intent_id"], "intent_id")
    note_attributes = encode_commerce_binding_to_shopify_note_attributes(
        {"tenant_id": tenant_id, "intent_id": intent_id},
        params.get("existing_note_attributes"),
    )
    payload: ShopifyCheckoutCreatePayload = {
        "line_items": to_ucp_checkout_line_items(params["line_items"]),
        "note_attributes": note_attributes,
        "meta": {
            "profile_url": (params.get("agent_profile_url") or PAYBOND_UCP_AGENT_PROFILE_URL).strip(),
        },
    }
    cart_id_raw = params.get("cart_id")
    cart_id = cart_id_raw.strip() if isinstance(cart_id_raw, str) else ""
    if cart_id:
        payload["cart_id"] = cart_id
    return payload


def merge_binding_into_checkout_payload(
    *,
    tenant_id: str,
    intent_id: str,
    checkout_payload: dict[str, object],
    agent_profile_url: str = PAYBOND_UCP_AGENT_PROFILE_URL,
) -> dict[str, object]:
    """Merge binding metadata into an existing checkout mutation payload."""
    existing_attrs = checkout_payload.get("note_attributes")
    attrs: list[ShopifyNoteAttribute] | None = (
        [cast(ShopifyNoteAttribute, dict(item)) for item in existing_attrs]
        if isinstance(existing_attrs, list)
        else None
    )
    note_attributes = encode_commerce_binding_to_shopify_note_attributes(
        {"tenant_id": tenant_id, "intent_id": intent_id},
        attrs,
    )
    meta = checkout_payload.get("meta")
    profile_url = agent_profile_url.strip()
    if isinstance(meta, dict) and isinstance(meta.get("profile_url"), str):
        profile_url = meta["profile_url"].strip() or profile_url
    return {
        **checkout_payload,
        "note_attributes": note_attributes,
        "meta": {"profile_url": profile_url},
    }
