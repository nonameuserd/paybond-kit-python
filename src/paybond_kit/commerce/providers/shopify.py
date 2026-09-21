"""Shopify adapter for multi-provider commerce.checkout."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from paybond_kit.commerce.provider import (
    require_amount_cents,
    require_commerce_session_binding,
)
from paybond_kit.commerce.types import (
    CommerceCheckoutSessionBinding,
    CommerceCheckoutToolArgs,
    CommerceCheckoutToolResult,
    CommerceProviderId,
)
from paybond_kit.shopify.checkout import PAYBOND_UCP_AGENT_PROFILE_URL, create_checkout_with_binding
from paybond_kit.shopify.types import ShopifyCheckoutExecuteInput, ShopifyCheckoutToolResult

ShopifyCommerceCheckoutExecutor = Callable[
    [ShopifyCheckoutExecuteInput], Awaitable[ShopifyCheckoutToolResult]
]


@dataclass(slots=True)
class _ShopifyCommerceProvider:
    execute_checkout: ShopifyCommerceCheckoutExecutor
    agent_profile_url: str

    @property
    def id(self) -> CommerceProviderId:
        return "shopify"

    async def checkout(
        self,
        args: CommerceCheckoutToolArgs,
        binding: CommerceCheckoutSessionBinding,
    ) -> CommerceCheckoutToolResult:
        session = require_commerce_session_binding(binding)
        amount_cents = require_amount_cents(args.get("amount_cents"))
        shopify_args = args.get("shopify")
        if not shopify_args:
            raise ValueError('commerce.checkout: shopify payload is required when provider is "shopify"')

        shop_domain = str(shopify_args.get("shop_domain", "")).strip()
        if not shop_domain:
            raise ValueError("commerce.checkout: shopify.shop_domain is required")

        line_items = shopify_args.get("line_items")
        if not isinstance(line_items, list) or len(line_items) == 0:
            raise ValueError("commerce.checkout: shopify.line_items must include at least one item")

        profile_url = self.agent_profile_url
        checkout_payload = create_checkout_with_binding(
            {
                "tenant_id": session["tenant_id"],
                "intent_id": session["intent_id"],
                "line_items": line_items,
                "existing_note_attributes": shopify_args.get("note_attributes"),
                "cart_id": shopify_args.get("cart_id"),
                "agent_profile_url": profile_url,
            }
        )

        execute_input: ShopifyCheckoutExecuteInput = {
            "shop_domain": shop_domain,
            "line_items": line_items,
            "amount_cents": amount_cents,
            "tenant_id": session["tenant_id"],
            "intent_id": session["intent_id"],
            "checkout_payload": checkout_payload,
            "agent_profile_url": profile_url,
            # Bound attributes only — never forward unbound client note_attributes.
            "note_attributes": checkout_payload["note_attributes"],
        }
        cart_id = shopify_args.get("cart_id")
        if cart_id:
            execute_input["cart_id"] = cart_id

        result = await self.execute_checkout(execute_input)
        cost_raw = result.get("cost_cents")
        if cost_raw is None:
            raise ValueError("commerce.checkout: shopify executor result missing cost_cents")
        if not isinstance(cost_raw, int) or isinstance(cost_raw, bool) or cost_raw < 0:
            raise ValueError(
                "commerce.checkout: shopify executor result cost_cents must be a non-negative integer"
            )
        out: CommerceCheckoutToolResult = {
            "status": result["status"],
            "cost_cents": cost_raw,
            "provider": "shopify",
        }
        order_id = result.get("order_id")
        if order_id:
            out["order_id"] = order_id
        shop = result.get("shop")
        if shop:
            out["shop"] = shop
        elif shop_domain:
            out["shop"] = shop_domain
        continue_url = result.get("continue_url")
        if continue_url:
            out["continue_url"] = continue_url
        return out


def create_shopify_commerce_provider(
    *,
    execute_checkout: ShopifyCommerceCheckoutExecutor,
    agent_profile_url: str = PAYBOND_UCP_AGENT_PROFILE_URL,
) -> _ShopifyCommerceProvider:
    """Create a Shopify adapter for the multi-provider commerce checkout router.

    Reuses :func:`create_checkout_with_binding` so ``tenant_id`` /
    ``paybond_intent_id`` note attributes always come from session binding —
    never from tool args.
    """

    return _ShopifyCommerceProvider(
        execute_checkout=execute_checkout,
        agent_profile_url=agent_profile_url.strip() or PAYBOND_UCP_AGENT_PROFILE_URL,
    )
