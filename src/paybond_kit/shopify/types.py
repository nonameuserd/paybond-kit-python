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


class CreateCheckoutWithBindingParams(TypedDict, total=False):
    tenant_id: str
    intent_id: str
    line_items: list[ShopifyCheckoutLineItemInput]
    existing_note_attributes: list[ShopifyNoteAttribute]
    cart_id: str
    agent_profile_url: str


class ShopifyCheckoutCreatePayload(TypedDict, total=False):
    line_items: list[dict[str, object]]
    note_attributes: list[ShopifyNoteAttribute]
    cart_id: str
    meta: dict[str, str]


class ShopifyCheckoutToolResult(TypedDict, total=False):
    status: Literal["completed", "requires_escalation", "failed"]
    cost_cents: int
    order_id: str
    shop: str
    continue_url: str


class ShopifyCheckoutToolArgs(TypedDict, total=False):
    shop_domain: str
    line_items: list[ShopifyCheckoutLineItemInput]
    amount_cents: int
    cart_id: str
    note_attributes: list[ShopifyNoteAttribute]


class ShopifyCheckoutExecuteInput(ShopifyCheckoutToolArgs, total=False):
    tenant_id: str
    intent_id: str
    checkout_payload: ShopifyCheckoutCreatePayload
    agent_profile_url: str


class GetShopifyOrderParams(TypedDict, total=False):
    shop_domain: str
    order_id: str
    agent_profile_url: str


class ShopifyOrderBinding(TypedDict):
    tenant_id: str | None
    paybond_intent_id: str | None


class ShopifyOrderSummary(TypedDict, total=False):
    order_id: str
    shop: str
    financial_status: str
    note_attributes: list[ShopifyNoteAttribute]
    binding: ShopifyOrderBinding


class MapShopifyToolResultToEvidenceOptions(TypedDict):
    preset: ShopifyCommerceEvidencePreset
