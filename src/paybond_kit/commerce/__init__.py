"""Multi-provider commerce.checkout router for Paybond Kit.

Route one ``commerce.checkout`` tool across Shopify, Stripe, and Zinc adapters
while Paybond remains the authorize → prove → release → receipt control layer.

This is a Kit product surface — not a Gateway HTTP buy-proxy.
"""

from paybond_kit.commerce.evidence import (
    COMMERCE_CHECKOUT_MAPPER_VERSION,
    map_commerce_checkout_result_to_evidence,
)
from paybond_kit.commerce.instrument import (
    create_guarded_commerce_checkout_handler,
    instrument_commerce_checkout,
)
from paybond_kit.commerce.provider import (
    CommerceCheckoutProvider,
    require_amount_cents,
    require_commerce_session_binding,
)
from paybond_kit.commerce.providers import (
    ShopifyCommerceCheckoutExecutor,
    StripeCommerceCheckoutExecuteInput,
    StripeCommerceCheckoutExecutor,
    ZincCheckoutRequest,
    ZincHttpClient,
    create_shopify_commerce_provider,
    create_stripe_commerce_provider,
    create_zinc_commerce_provider,
    derive_zinc_products_cost_cents,
)
from paybond_kit.commerce.router import (
    CommerceCheckoutHandler,
    CommerceCheckoutProviderMap,
    create_commerce_checkout_router,
    resolve_commerce_checkout_provider,
)
from paybond_kit.commerce.types import (
    CommerceCheckoutEvidencePreset,
    CommerceCheckoutSessionBinding,
    CommerceCheckoutToolArgs,
    CommerceCheckoutToolResult,
    CommerceProviderId,
    CommerceShopifyCheckoutArgs,
    CommerceStripeCheckoutArgs,
    CommerceZincCheckoutArgs,
    CommerceZincProductInput,
    MapCommerceCheckoutResultToEvidenceOptions,
)

__all__ = [
    "COMMERCE_CHECKOUT_MAPPER_VERSION",
    "CommerceCheckoutEvidencePreset",
    "CommerceCheckoutHandler",
    "CommerceCheckoutProvider",
    "CommerceCheckoutProviderMap",
    "CommerceCheckoutSessionBinding",
    "CommerceCheckoutToolArgs",
    "CommerceCheckoutToolResult",
    "CommerceProviderId",
    "CommerceShopifyCheckoutArgs",
    "CommerceStripeCheckoutArgs",
    "CommerceZincCheckoutArgs",
    "CommerceZincProductInput",
    "MapCommerceCheckoutResultToEvidenceOptions",
    "ShopifyCommerceCheckoutExecutor",
    "StripeCommerceCheckoutExecuteInput",
    "StripeCommerceCheckoutExecutor",
    "ZincCheckoutRequest",
    "ZincHttpClient",
    "create_commerce_checkout_router",
    "create_guarded_commerce_checkout_handler",
    "create_shopify_commerce_provider",
    "create_stripe_commerce_provider",
    "create_zinc_commerce_provider",
    "derive_zinc_products_cost_cents",
    "instrument_commerce_checkout",
    "map_commerce_checkout_result_to_evidence",
    "require_amount_cents",
    "require_commerce_session_binding",
    "resolve_commerce_checkout_provider",
]
