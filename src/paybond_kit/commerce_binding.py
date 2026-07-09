"""Shared commerce binding helpers (Stripe metadata + Shopify note_attributes).

The binding is a tenant-isolation primitive:
- Stripe webhook preflight uses metadata keys.
- Shopify webhook preflight uses note_attributes keys.

All values must be sourced from authenticated Paybond session context.
"""

from __future__ import annotations

from typing import Mapping, Sequence, TypedDict

PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY = "tenant_id"
PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY = "paybond_intent_id"


class CommerceBinding(TypedDict):
    """Canonical Paybond commerce binding."""

    tenant_id: str
    intent_id: str


class ShopifyNoteAttribute(TypedDict):
    name: str
    value: str


def _require_non_empty_trimmed(value: str, label: str) -> str:
    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"commerce_binding: {label} is required")
    return trimmed


def normalize_commerce_binding(binding: CommerceBinding) -> CommerceBinding:
    """Validate and normalize a canonical Paybond commerce binding."""

    return {
        "tenant_id": _require_non_empty_trimmed(binding["tenant_id"], "tenant_id"),
        "intent_id": _require_non_empty_trimmed(binding["intent_id"], "intent_id"),
    }


def _assert_no_collision(existing_value: str | None, next_value: str, label: str) -> None:
    if existing_value is None:
        return
    if existing_value == next_value:
        return
    raise ValueError(
        f"commerce_binding: {label} collision ({existing_value!r} != {next_value!r})"
    )


def encode_commerce_binding_to_stripe_metadata(
    binding: CommerceBinding,
    existing_metadata: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Encode a commerce binding into Stripe `metadata` (string -> string).

    Preserves unknown keys and rejects collisions when a binding key disagrees.
    """

    normalized = normalize_commerce_binding(binding)
    merged: dict[str, str] = dict(existing_metadata or {})

    _assert_no_collision(
        merged.get(PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY),
        normalized["tenant_id"],
        PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY,
    )
    _assert_no_collision(
        merged.get(PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY),
        normalized["intent_id"],
        PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY,
    )

    merged[PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY] = normalized["tenant_id"]
    merged[PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY] = normalized["intent_id"]
    return merged


def decode_commerce_binding_from_stripe_metadata(
    metadata: Mapping[str, object] | None,
) -> CommerceBinding | None:
    """Decode a commerce binding from Stripe `metadata`.

    Returns None when binding keys are absent. Raises on empty values.
    """

    if not metadata:
        return None
    tenant_id = metadata.get(PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY)
    intent_id = metadata.get(PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY)
    if not isinstance(tenant_id, str) or not isinstance(intent_id, str):
        return None
    return normalize_commerce_binding({"tenant_id": tenant_id, "intent_id": intent_id})


def encode_commerce_binding_to_shopify_note_attributes(
    binding: CommerceBinding,
    existing_attributes: Sequence[ShopifyNoteAttribute] | None = None,
) -> list[ShopifyNoteAttribute]:
    """Encode a commerce binding into Shopify `note_attributes`.

    Preserves unknown attributes, rejects collisions, and appends canonical keys
    in stable order.
    """

    normalized = normalize_commerce_binding(binding)
    out: list[ShopifyNoteAttribute] = []

    for attr in existing_attributes or []:
        name = attr.get("name")
        value = attr.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            continue

        if name == PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY:
            _assert_no_collision(value, normalized["tenant_id"], name)
            continue
        if name == PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY:
            _assert_no_collision(value, normalized["intent_id"], name)
            continue

        out.append({"name": name, "value": value})

    out.append(
        {"name": PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY, "value": normalized["tenant_id"]}
    )
    out.append(
        {
            "name": PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY,
            "value": normalized["intent_id"],
        }
    )
    return out


def decode_commerce_binding_from_shopify_note_attributes(
    note_attributes: object,
) -> CommerceBinding | None:
    """Decode a commerce binding from Shopify `note_attributes`.

    Returns None when binding keys are absent. Raises on:
    - empty binding values
    - multiple conflicting values for the same key
    """

    if not isinstance(note_attributes, list):
        return None

    tenant_id: str | None = None
    intent_id: str | None = None

    for entry in note_attributes:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        value = entry.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            continue

        if name == PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY:
            if tenant_id is not None and tenant_id != value:
                raise ValueError(
                    f"commerce_binding: {name} collision ({tenant_id!r} != {value!r})"
                )
            tenant_id = value

        if name == PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY:
            if intent_id is not None and intent_id != value:
                raise ValueError(
                    f"commerce_binding: {name} collision ({intent_id!r} != {value!r})"
                )
            intent_id = value

    if tenant_id is None or intent_id is None:
        return None
    return normalize_commerce_binding({"tenant_id": tenant_id, "intent_id": intent_id})

