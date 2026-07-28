"""Tests for Shopify checkout binding helpers."""

from __future__ import annotations

import pytest

from paybond_kit.shopify import (
    PAYBOND_UCP_AGENT_PROFILE_URL,
    ShopifyCheckoutToolResult,
    create_checkout_with_binding,
    create_guarded_shopify_checkout_handler,
    map_shopify_tool_result_to_evidence,
)


def test_create_checkout_with_binding_injects_note_attributes() -> None:
    payload = create_checkout_with_binding(
        {
            "tenant_id": "tenant-a",
            "intent_id": "00000000-0000-0000-0000-000000000111",
            "line_items": [{"variant_id": "12345", "quantity": 1}],
        }
    )
    assert payload["note_attributes"] == [
        {"name": "tenant_id", "value": "tenant-a"},
        {"name": "paybond_intent_id", "value": "00000000-0000-0000-0000-000000000111"},
    ]
    assert payload["meta"]["profile_url"] == PAYBOND_UCP_AGENT_PROFILE_URL


def test_map_shopify_tool_result_to_evidence() -> None:
    evidence = map_shopify_tool_result_to_evidence(
        {
            "status": "completed",
            "cost_cents": 4500,
            "order_id": "gid://shopify/Order/123",
            "shop": "paybond-agent-commerce-dev.myshopify.com",
        },
        {"preset": "cost_and_completion"},
    )
    assert evidence == {"status": "completed", "cost_cents": 4500}


@pytest.mark.asyncio
async def test_guarded_shopify_checkout_injects_binding() -> None:
    binding = {"tenant_id": "tenant-a", "intent_id": "00000000-0000-0000-0000-000000000111"}

    async def execute_checkout(input_payload) -> ShopifyCheckoutToolResult:
        assert input_payload["checkout_payload"]["note_attributes"][-2:] == [
            {"name": "tenant_id", "value": "tenant-a"},
            {"name": "paybond_intent_id", "value": "00000000-0000-0000-0000-000000000111"},
        ]
        return {
            "status": "completed",
            "cost_cents": input_payload["amount_cents"],
            "shop": input_payload["shop_domain"],
        }

    handler = create_guarded_shopify_checkout_handler(
        binding=lambda: binding,
        execute_checkout=execute_checkout,
    )
    result = await handler(
        {
            "shop_domain": "paybond-agent-commerce-dev.myshopify.com",
            "line_items": [{"variant_id": "123", "quantity": 1}],
            "amount_cents": 4500,
        }
    )
    assert result["status"] == "completed"
