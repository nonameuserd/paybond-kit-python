import pytest

from paybond_kit.commerce_binding import (
    PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY,
    PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY,
    decode_commerce_binding_from_shopify_note_attributes,
    decode_commerce_binding_from_stripe_metadata,
    encode_commerce_binding_to_shopify_note_attributes,
    encode_commerce_binding_to_stripe_metadata,
)


def test_encode_stripe_metadata_canonical_keys() -> None:
    metadata = encode_commerce_binding_to_stripe_metadata(
        {"tenant_id": "tenant-a", "intent_id": "intent-a"}
    )
    assert metadata == {
        PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY: "tenant-a",
        PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY: "intent-a",
    }


def test_encode_stripe_metadata_merges_unknown_keys() -> None:
    metadata = encode_commerce_binding_to_stripe_metadata(
        {"tenant_id": "tenant-a", "intent_id": "intent-a"}, {"foo": "bar"}
    )
    assert metadata["foo"] == "bar"
    assert metadata["tenant_id"] == "tenant-a"


def test_encode_stripe_metadata_rejects_collision() -> None:
    with pytest.raises(ValueError, match="tenant_id collision"):
        encode_commerce_binding_to_stripe_metadata(
            {"tenant_id": "tenant-a", "intent_id": "intent-a"}, {"tenant_id": "tenant-b"}
        )


def test_decode_stripe_metadata() -> None:
    binding = decode_commerce_binding_from_stripe_metadata(
        {"tenant_id": "tenant-a", "paybond_intent_id": "intent-a"}
    )
    assert binding == {"tenant_id": "tenant-a", "intent_id": "intent-a"}


def test_decode_stripe_metadata_missing_is_none() -> None:
    assert decode_commerce_binding_from_stripe_metadata({}) is None
    assert decode_commerce_binding_from_stripe_metadata({"tenant_id": "tenant-a"}) is None


def test_encode_shopify_note_attributes_preserves_unknown() -> None:
    attrs = encode_commerce_binding_to_shopify_note_attributes(
        {"tenant_id": "tenant-a", "intent_id": "intent-a"},
        [{"name": "foo", "value": "bar"}],
    )
    assert attrs == [
        {"name": "foo", "value": "bar"},
        {"name": "tenant_id", "value": "tenant-a"},
        {"name": "paybond_intent_id", "value": "intent-a"},
    ]


def test_encode_shopify_note_attributes_rejects_collision() -> None:
    with pytest.raises(ValueError, match="tenant_id collision"):
        encode_commerce_binding_to_shopify_note_attributes(
            {"tenant_id": "tenant-a", "intent_id": "intent-a"},
            [{"name": "tenant_id", "value": "tenant-b"}],
        )


def test_decode_shopify_note_attributes() -> None:
    binding = decode_commerce_binding_from_shopify_note_attributes(
        [
            {"name": "foo", "value": "bar"},
            {"name": "tenant_id", "value": "tenant-a"},
            {"name": "paybond_intent_id", "value": "intent-a"},
        ]
    )
    assert binding == {"tenant_id": "tenant-a", "intent_id": "intent-a"}


def test_decode_shopify_note_attributes_missing_is_none() -> None:
    assert decode_commerce_binding_from_shopify_note_attributes([]) is None
    assert (
        decode_commerce_binding_from_shopify_note_attributes(
            [{"name": "tenant_id", "value": "tenant-a"}]
        )
        is None
    )


def test_decode_shopify_note_attributes_rejects_conflicting_duplicates() -> None:
    with pytest.raises(ValueError, match="tenant_id collision"):
        decode_commerce_binding_from_shopify_note_attributes(
            [
                {"name": "tenant_id", "value": "tenant-a"},
                {"name": "tenant_id", "value": "tenant-b"},
                {"name": "paybond_intent_id", "value": "intent-a"},
            ]
        )

