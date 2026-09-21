"""Instrument multi-provider commerce.checkout with Paybond middleware."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from paybond_kit.commerce.router import (
    CommerceCheckoutHandler,
    CommerceCheckoutProviderMap,
    create_commerce_checkout_router,
)
from paybond_kit.commerce.types import (
    CommerceCheckoutSessionBinding,
    CommerceProviderId,
)


def create_guarded_commerce_checkout_handler(
    *,
    providers: CommerceCheckoutProviderMap,
    default_provider: CommerceProviderId,
    binding: Callable[[], CommerceCheckoutSessionBinding],
) -> CommerceCheckoutHandler:
    """Wrap registered commerce providers so session binding is injected on every call.

    Equivalent to :func:`create_commerce_checkout_router` — kept for symmetry with
    :func:`paybond_kit.shopify.create_guarded_shopify_checkout_handler`.
    """

    return create_commerce_checkout_router(
        providers=providers,
        default_provider=default_provider,
        binding=binding,
    )


async def instrument_commerce_checkout(
    paybond: Any,
    *,
    policy: str,
    providers: CommerceCheckoutProviderMap,
    default_provider: CommerceProviderId,
    binding_ref: CommerceCheckoutSessionBinding | None = None,
    **instrument_kwargs: Any,
) -> tuple[Any, CommerceCheckoutSessionBinding]:
    """Instrument ``commerce.checkout`` with Paybond middleware and multi-provider routing.

    Prefer this over wiring Shopify-only ``instrument_shopify_checkout`` when the
    agent may check out via Shopify, Stripe, or Zinc under one tool name.

    Returns:
        ``(instrumented, binding_ref)`` — populate ``binding_ref`` after sandbox
        bind / production attach (tenant and intent from session, never client input).
    """

    session_binding: CommerceCheckoutSessionBinding = (
        binding_ref if binding_ref is not None else {"tenant_id": "", "intent_id": ""}
    )
    checkout_handler = create_commerce_checkout_router(
        providers=providers,
        default_provider=default_provider,
        binding=lambda: session_binding,
    )
    instrumented = await paybond.instrument(
        policy=policy,
        tools={"commerce.checkout": checkout_handler},
        **instrument_kwargs,
    )
    return instrumented, session_binding
