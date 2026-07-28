"""Shopify UCP order reconciliation helper."""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from paybond_kit.commerce_binding import decode_commerce_binding_from_shopify_note_attributes
from paybond_kit.shopify.checkout import PAYBOND_SHOPIFY_UCP_VERSION, PAYBOND_UCP_AGENT_PROFILE_URL
from paybond_kit.shopify.types import (
    GetShopifyOrderParams,
    ShopifyNoteAttribute,
    ShopifyOrderBinding,
    ShopifyOrderSummary,
)

UcpFetch = Callable[[str, dict[str, Any]], Awaitable[Any]]


def _require_shop_domain(shop_domain: str) -> str:
    trimmed = shop_domain.strip()
    if not trimmed:
        raise ValueError("shopify order: shop_domain is required")
    return trimmed.replace("https://", "").replace("http://", "").rstrip("/")


def _normalize_order_gid(order_id: str) -> str:
    trimmed = order_id.strip()
    if not trimmed:
        raise ValueError("shopify order: order_id is required")
    if trimmed.startswith("gid://shopify/Order/"):
        return trimmed
    if trimmed.isdigit():
        return f"gid://shopify/Order/{trimmed}"
    return trimmed


def _shop_origin(shop_domain: str) -> str:
    host = _require_shop_domain(shop_domain)
    if "." in host:
        return f"https://{host}"
    return f"https://{host}.myshopify.com"


def _read_note_attributes(value: object) -> list[ShopifyNoteAttribute]:
    if not isinstance(value, list):
        return []
    attrs: list[ShopifyNoteAttribute] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        attr_value = entry.get("value")
        if isinstance(name, str) and isinstance(attr_value, str):
            attrs.append({"name": name, "value": attr_value})
    return attrs


async def get_order(
    params: GetShopifyOrderParams,
    *,
    fetch_ucp: UcpFetch | None = None,
) -> ShopifyOrderSummary:
    """Fetch an order via Shopify UCP Order MCP for reconciliation."""
    shop = _require_shop_domain(params["shop_domain"])
    order_id = _normalize_order_gid(params["order_id"])
    profile_url = (params.get("agent_profile_url") or PAYBOND_UCP_AGENT_PROFILE_URL).strip()

    request_body = {
        "jsonrpc": "2.0",
        "id": "paybond-kit-get-order",
        "method": "order/get",
        "params": {
            "order_id": order_id,
            "meta": {
                "profile_url": profile_url,
                "ucp_version": PAYBOND_SHOPIFY_UCP_VERSION,
            },
        },
    }

    if fetch_ucp is None:
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{_shop_origin(shop)}/api/ucp/mcp",
                headers={
                    "content-type": "application/json",
                    "UCP-Agent": profile_url,
                },
                content=json.dumps(request_body),
            )
            body = response.json()
            if response.status_code >= 400:
                message = body.get("message") or body.get("error") or f"UCP order/get failed ({response.status_code})"
                raise ValueError(str(message))
    else:
        body = await fetch_ucp(
            f"{_shop_origin(shop)}/api/ucp/mcp",
            {
                "method": "POST",
                "headers": {
                    "content-type": "application/json",
                    "UCP-Agent": profile_url,
                },
                "body": json.dumps(request_body),
            },
        )

    if not isinstance(body, dict):
        raise ValueError("shopify order: UCP response must be an object")
    result = body.get("result")
    if not isinstance(result, dict):
        raise ValueError("shopify order: UCP response missing result")

    note_attributes = _read_note_attributes(result.get("note_attributes"))
    binding = decode_commerce_binding_from_shopify_note_attributes(note_attributes)
    order_value = result.get("id") or result.get("order_id") or result.get("admin_graphql_api_id")
    financial_status = result.get("financial_status")
    order_binding: ShopifyOrderBinding = {
        "tenant_id": binding["tenant_id"] if binding else None,
        "paybond_intent_id": binding["intent_id"] if binding else None,
    }
    summary: ShopifyOrderSummary = {
        "order_id": str(order_value) if order_value is not None else order_id,
        "shop": shop,
        "financial_status": str(financial_status) if isinstance(financial_status, str) else None,
        "note_attributes": note_attributes,
        "binding": order_binding,
    }
    return summary
