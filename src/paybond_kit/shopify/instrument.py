"""Instrument Shopify checkout tools with Paybond middleware."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from paybond_kit.shopify.checkout import PAYBOND_UCP_AGENT_PROFILE_URL, create_checkout_with_binding
from paybond_kit.shopify.types import (
    ShopifyCheckoutExecuteInput,
    ShopifyCheckoutToolArgs,
    ShopifyCheckoutToolResult,
)

ShopifyCheckoutExecutor = Callable[
    [ShopifyCheckoutExecuteInput], Awaitable[ShopifyCheckoutToolResult]
]


def create_guarded_shopify_checkout_handler(
    *,
    binding: Callable[[], dict[str, str]],
    execute_checkout: ShopifyCheckoutExecutor,
    agent_profile_url: str = PAYBOND_UCP_AGENT_PROFILE_URL,
) -> Callable[[ShopifyCheckoutToolArgs], Awaitable[ShopifyCheckoutToolResult]]:
    """Wrap a checkout executor so binding metadata is injected on every call."""

    profile_url = agent_profile_url.strip()

    async def handler(args: ShopifyCheckoutToolArgs) -> ShopifyCheckoutToolResult:
        session = binding()
        tenant_id = str(session.get("tenant_id", "")).strip()
        intent_id = str(session.get("intent_id", "")).strip()
        if not tenant_id or not intent_id:
            raise ValueError("Paybond session binding is required before commerce.checkout")

        checkout_payload = create_checkout_with_binding(
            {
                "tenant_id": tenant_id,
                "intent_id": intent_id,
                "line_items": args["line_items"],
                "existing_note_attributes": args.get("note_attributes"),
                "cart_id": args.get("cart_id"),
                "agent_profile_url": profile_url,
            }
        )

        execute_input: ShopifyCheckoutExecuteInput = {
            **args,
            "tenant_id": tenant_id,
            "intent_id": intent_id,
            "checkout_payload": checkout_payload,
            "agent_profile_url": profile_url,
        }
        return await execute_checkout(execute_input)

    return handler


async def instrument_shopify_checkout(
    paybond: Any,
    *,
    policy: str,
    execute_checkout: ShopifyCheckoutExecutor,
    binding_ref: dict[str, str] | None = None,
    agent_profile_url: str = PAYBOND_UCP_AGENT_PROFILE_URL,
    **instrument_kwargs: Any,
) -> Any:
    """Instrument commerce.checkout with Paybond middleware and binding injection."""
    session_binding = binding_ref if binding_ref is not None else {"tenant_id": "", "intent_id": ""}
    checkout_handler = create_guarded_shopify_checkout_handler(
        binding=lambda: session_binding,
        execute_checkout=execute_checkout,
        agent_profile_url=agent_profile_url,
    )
    instrumented = await paybond.instrument(
        policy=policy,
        tools={"commerce.checkout": checkout_handler},
        **instrument_kwargs,
    )
    return instrumented, session_binding
