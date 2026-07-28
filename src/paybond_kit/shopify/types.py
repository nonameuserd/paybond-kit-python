"""Types for Shopify UCP checkout helpers."""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict

ShopifyCommerceEvidencePreset = Literal["cost_and_completion"]


class ShopifyCheckoutLineItemInput(TypedDict):
    variant_id: str
    quantity: int


class ShopifyNoteAttribute(TypedDict):
    name: str
    value: str


class CreateCheckoutWithBindingParams(TypedDict):
    tenant_id: str
    intent_id: str
    line_items: list[ShopifyCheckoutLineItemInput]
    existing_note_attributes: NotRequired[list[ShopifyNoteAttribute] | None]
    cart_id: NotRequired[str | None]
    agent_profile_url: NotRequired[str | None]


class ShopifyCheckoutCreatePayload(TypedDict):
    line_items: list[dict[str, object]]
    note_attributes: list[ShopifyNoteAttribute]
    meta: dict[str, str]
    cart_id: NotRequired[str]


class ShopifyCheckoutToolResult(TypedDict):
    status: Literal["completed", "requires_escalation", "failed"]
    cost_cents: NotRequired[int]
    order_id: NotRequired[str]
    shop: NotRequired[str]
    continue_url: NotRequired[str]


class ShopifyCheckoutToolArgs(TypedDict):
    line_items: list[ShopifyCheckoutLineItemInput]
    shop_domain: NotRequired[str]
    amount_cents: NotRequired[int]
    cart_id: NotRequired[str]
    note_attributes: NotRequired[list[ShopifyNoteAttribute]]


class ShopifyCheckoutExecuteInput(ShopifyCheckoutToolArgs):
    tenant_id: NotRequired[str]
    intent_id: NotRequired[str]
    checkout_payload: NotRequired[ShopifyCheckoutCreatePayload]
    agent_profile_url: NotRequired[str]


class GetShopifyOrderParams(TypedDict):
    shop_domain: str
    order_id: str
    agent_profile_url: NotRequired[str]


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
