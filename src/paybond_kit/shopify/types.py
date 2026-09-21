"""Types for Shopify UCP checkout helpers."""

from __future__ import annotations

from typing import Literal, TypedDict

ShopifyCommerceEvidencePreset = Literal["cost_and_completion"]


class ShopifyCheckoutLineItemInput(TypedDict):
    variant_id: str
    quantity: int


class ShopifyNoteAttribute(TypedDict):
    name: str
    value: str


class _CreateCheckoutWithBindingParamsRequired(TypedDict):
    tenant_id: str
    intent_id: str
    line_items: list[ShopifyCheckoutLineItemInput]


class CreateCheckoutWithBindingParams(_CreateCheckoutWithBindingParamsRequired, total=False):
    """Inputs for ``create_checkout_with_binding``.

    Optional keys use ``total=False`` inheritance so they stay optional under
    ``from __future__ import annotations`` (``NotRequired`` is ignored by
    TypedDict on Python 3.11 with postponed annotations).
    """

    existing_note_attributes: list[ShopifyNoteAttribute] | None
    cart_id: str | None
    agent_profile_url: str | None


class _ShopifyCheckoutCreatePayloadRequired(TypedDict):
    line_items: list[dict[str, object]]
    note_attributes: list[ShopifyNoteAttribute]
    meta: dict[str, str]


class ShopifyCheckoutCreatePayload(_ShopifyCheckoutCreatePayloadRequired, total=False):
    """UCP create_checkout payload with binding metadata injected.

    Optional keys use ``total=False`` inheritance under postponed annotations.
    """

    cart_id: str


class _ShopifyCheckoutToolResultRequired(TypedDict):
    status: Literal["completed", "requires_escalation", "failed"]
    cost_cents: int
    shop: str


class ShopifyCheckoutToolResult(_ShopifyCheckoutToolResultRequired, total=False):
    """Checkout tool completion envelope for commerce.checkout evidence mapping.

    ``cost_cents`` and ``shop`` are required (TS parity). Optional keys use
    ``total=False`` inheritance so they stay optional under
    ``from __future__ import annotations`` (``NotRequired`` is ignored by
    TypedDict on Python 3.11 with postponed annotations).
    """

    order_id: str
    continue_url: str


class _ShopifyCheckoutToolArgsRequired(TypedDict):
    line_items: list[ShopifyCheckoutLineItemInput]


class ShopifyCheckoutToolArgs(_ShopifyCheckoutToolArgsRequired, total=False):
    """Arguments accepted by guarded commerce.checkout Shopify handlers.

    Optional keys use ``total=False`` inheritance under postponed annotations.
    """

    shop_domain: str
    amount_cents: int
    cart_id: str
    note_attributes: list[ShopifyNoteAttribute]


class ShopifyCheckoutExecuteInput(ShopifyCheckoutToolArgs, total=False):
    """Arguments passed to the checkout executor after binding injection.

    Keys declared here are optional; inherited ``line_items`` stays required.
    """

    tenant_id: str
    intent_id: str
    checkout_payload: ShopifyCheckoutCreatePayload
    agent_profile_url: str


class _GetShopifyOrderParamsRequired(TypedDict):
    shop_domain: str
    order_id: str


class GetShopifyOrderParams(_GetShopifyOrderParamsRequired, total=False):
    """Inputs for ``get_order``.

    Optional keys use ``total=False`` inheritance under postponed annotations.
    """

    agent_profile_url: str


class ShopifyOrderBinding(TypedDict):
    tenant_id: str | None
    paybond_intent_id: str | None


class ShopifyOrderSummary(TypedDict, total=False):
    order_id: str
    shop: str
    financial_status: str | None
    note_attributes: list[ShopifyNoteAttribute]
    binding: ShopifyOrderBinding


class MapShopifyToolResultToEvidenceOptions(TypedDict):
    preset: ShopifyCommerceEvidencePreset
