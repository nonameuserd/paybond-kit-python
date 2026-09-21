"""Types for multi-provider commerce.checkout."""

from __future__ import annotations

from typing import Literal, TypedDict

from paybond_kit.commerce_binding import ShopifyNoteAttribute
from paybond_kit.shopify.types import ShopifyCheckoutLineItemInput
from paybond_kit.stripe_commerce.types import PaybondStripeSettlementRail

CommerceProviderId = Literal["shopify", "stripe", "zinc"]
CommerceCheckoutEvidencePreset = Literal["cost_and_completion"]
CommerceCheckoutStatus = Literal["completed", "requires_escalation", "failed"]


class CommerceCheckoutSessionBinding(TypedDict):
    """Paybond session binding — never sourced from unauthenticated tool args."""

    tenant_id: str
    intent_id: str


class _CommerceShopifyCheckoutArgsRequired(TypedDict):
    shop_domain: str
    line_items: list[ShopifyCheckoutLineItemInput]


class CommerceShopifyCheckoutArgs(_CommerceShopifyCheckoutArgsRequired, total=False):
    """Shopify payload for ``commerce.checkout``.

    Optional keys use ``total=False`` inheritance so they stay optional under
    ``from __future__ import annotations`` (``NotRequired`` is ignored by
    TypedDict on Python 3.11 with postponed annotations).
    """

    cart_id: str
    note_attributes: list[ShopifyNoteAttribute]


class CommerceStripeCheckoutArgs(TypedDict, total=False):
    currency: str
    description: str
    existing_metadata: dict[str, str]
    rail: PaybondStripeSettlementRail
    payment_intent_id: str


class _CommerceZincProductInputRequired(TypedDict):
    product_id: str
    quantity: int


class CommerceZincProductInput(_CommerceZincProductInputRequired, total=False):
    """Zinc product line for ``commerce.checkout``.

    ``price_cents`` (unit price) is required in sandbox so ``cost_cents`` is
    product-derived — never trusted from agent ``amount_cents`` alone.
    Optional keys use ``total=False`` inheritance under postponed annotations.
    """

    price_cents: int


class _CommerceZincCheckoutArgsRequired(TypedDict):
    retailer: str
    products: list[CommerceZincProductInput]


class CommerceZincCheckoutArgs(_CommerceZincCheckoutArgsRequired, total=False):
    """Zinc payload for ``commerce.checkout``.

    Optional keys use ``total=False`` inheritance so they stay optional under
    ``from __future__ import annotations``.
    """

    shipping_address: dict[str, str]
    max_price_cents: int


class _CommerceCheckoutToolArgsRequired(TypedDict):
    amount_cents: int


class CommerceCheckoutToolArgs(_CommerceCheckoutToolArgsRequired, total=False):
    """Arguments for the shared ``commerce.checkout`` tool handler.

    ``provider`` selects the adapter; when omitted the router's default is used.
    Never pass ``tenant_id`` or ``intent_id`` here — those come from session binding.

    Optional keys use ``total=False`` inheritance so they stay optional under
    ``from __future__ import annotations`` (``NotRequired`` is ignored by
    TypedDict on Python 3.11 with postponed annotations).
    """

    provider: CommerceProviderId
    shopify: CommerceShopifyCheckoutArgs
    stripe: CommerceStripeCheckoutArgs
    zinc: CommerceZincCheckoutArgs


class _CommerceCheckoutToolResultRequired(TypedDict):
    status: CommerceCheckoutStatus
    cost_cents: int
    provider: CommerceProviderId


class CommerceCheckoutToolResult(_CommerceCheckoutToolResultRequired, total=False):
    """Canonical completion envelope — matches TS ``{ status, cost_cents, provider, ... }``.

    Optional keys use ``total=False`` inheritance so they stay optional under
    ``from __future__ import annotations`` (``NotRequired`` is ignored by
    TypedDict on Python 3.11 with postponed annotations).
    """

    order_id: str
    continue_url: str
    shop: str
    payment_intent_id: str
    zinc_request_id: str


class MapCommerceCheckoutResultToEvidenceOptions(TypedDict):
    preset: CommerceCheckoutEvidencePreset
