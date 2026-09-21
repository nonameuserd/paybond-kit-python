"""Tests for multi-provider commerce.checkout (Python parity with @paybond/kit/commerce)."""

from __future__ import annotations

from typing import cast

import pytest

from paybond_kit.commerce import (
    COMMERCE_CHECKOUT_MAPPER_VERSION,
    CommerceCheckoutSessionBinding,
    CommerceCheckoutToolArgs,
    StripeCommerceCheckoutExecuteInput,
    ZincCheckoutRequest,
    create_commerce_checkout_router,
    create_guarded_commerce_checkout_handler,
    create_shopify_commerce_provider,
    create_stripe_commerce_provider,
    create_zinc_commerce_provider,
    derive_zinc_products_cost_cents,
    map_commerce_checkout_result_to_evidence,
    resolve_commerce_checkout_provider,
)
from paybond_kit.commerce.providers.stripe import StripeCommerceCheckoutExecutorResult
from paybond_kit.commerce.providers.zinc import ZincHttpClientResult
from paybond_kit.shopify.types import ShopifyCheckoutExecuteInput, ShopifyCheckoutToolResult


def test_map_commerce_checkout_result_to_evidence() -> None:
    evidence = map_commerce_checkout_result_to_evidence(
        {
            "status": "completed",
            "cost_cents": 2500,
            "provider": "zinc",
            "order_id": "zinc_sandbox_ord_amazon_B00TEST",
            "zinc_request_id": "req_ignored",
        },
        {"preset": "cost_and_completion"},
    )
    assert evidence == {
        "status": "completed",
        "cost_cents": 2500,
        "provider": "zinc",
        "order_id": "zinc_sandbox_ord_amazon_B00TEST",
    }
    assert COMMERCE_CHECKOUT_MAPPER_VERSION == "commerce_checkout_v1"


def test_map_commerce_checkout_rejects_missing_cost() -> None:
    with pytest.raises(ValueError, match="missing cost_cents"):
        _ = map_commerce_checkout_result_to_evidence(
            cast(
                dict[str, object],
                {"status": "completed", "provider": "stripe"},
            ),
            {"preset": "cost_and_completion"},
        )


def test_map_commerce_checkout_rejects_none_cost_without_amount_fallback() -> None:
    with pytest.raises(ValueError, match="missing cost_cents"):
        _ = map_commerce_checkout_result_to_evidence(
            {"status": "completed", "cost_cents": None, "amount_cents": 9999},
            {"preset": "cost_and_completion"},
        )


def test_map_commerce_checkout_does_not_invent_cost_from_amount() -> None:
    with pytest.raises(ValueError, match="missing cost_cents"):
        _ = map_commerce_checkout_result_to_evidence(
            {"status": "completed", "amount_cents": 4500},
            {"preset": "cost_and_completion"},
        )


def test_commerce_typeddicts_optional_keys_under_future_annotations() -> None:
    """Python 3.11 + postponed annotations: optional keys must use total=False inheritance."""
    from paybond_kit.commerce.types import (
        CommerceCheckoutToolArgs,
        CommerceShopifyCheckoutArgs,
        CommerceZincCheckoutArgs,
        CommerceZincProductInput,
    )

    assert CommerceCheckoutToolArgs.__required_keys__ == frozenset({"amount_cents"})
    assert CommerceCheckoutToolArgs.__optional_keys__ == frozenset(
        {"provider", "shopify", "stripe", "zinc"}
    )
    assert CommerceShopifyCheckoutArgs.__required_keys__ == frozenset(
        {"shop_domain", "line_items"}
    )
    assert CommerceShopifyCheckoutArgs.__optional_keys__ == frozenset(
        {"cart_id", "note_attributes"}
    )
    assert CommerceZincCheckoutArgs.__required_keys__ == frozenset({"retailer", "products"})
    assert CommerceZincCheckoutArgs.__optional_keys__ == frozenset(
        {"shipping_address", "max_price_cents"}
    )
    assert CommerceZincProductInput.__required_keys__ == frozenset({"product_id", "quantity"})
    assert CommerceZincProductInput.__optional_keys__ == frozenset({"price_cents"})


@pytest.mark.asyncio
async def test_router_default_provider_injects_shopify_binding() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }
    calls: list[ShopifyCheckoutExecuteInput] = []

    async def execute_checkout(
        input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        calls.append(input_payload)
        assert input_payload.get("tenant_id") == "tenant-a"
        assert input_payload.get("intent_id") == "00000000-0000-0000-0000-000000000111"
        checkout_payload = input_payload.get("checkout_payload")
        assert checkout_payload is not None
        expected_attrs = [
            {"name": "buyer_note", "value": "leave at door"},
            {"name": "tenant_id", "value": "tenant-a"},
            {
                "name": "paybond_intent_id",
                "value": "00000000-0000-0000-0000-000000000111",
            },
        ]
        assert checkout_payload["note_attributes"] == expected_attrs
        # Executor top-level note_attributes must be the bound set, not unbound client attrs.
        assert input_payload.get("note_attributes") == expected_attrs
        return {
            "status": "completed",
            "cost_cents": input_payload.get("amount_cents", 0),
            "order_id": "gid://shopify/Order/123",
            "shop": input_payload.get("shop_domain", ""),
        }

    shopify = create_shopify_commerce_provider(execute_checkout=execute_checkout)
    checkout = create_commerce_checkout_router(
        providers={"shopify": shopify},
        default_provider="shopify",
        binding=lambda: binding,
    )

    result = await checkout(
        {
            "amount_cents": 4500,
            "shopify": {
                "shop_domain": "paybond-agent-commerce-dev.myshopify.com",
                "line_items": [{"variant_id": "123", "quantity": 1}],
                "note_attributes": [{"name": "buyer_note", "value": "leave at door"}],
            },
        }
    )

    assert result["status"] == "completed"
    assert result["cost_cents"] == 4500
    assert result["provider"] == "shopify"
    assert result.get("order_id") == "gid://shopify/Order/123"
    assert result.get("shop") == "paybond-agent-commerce-dev.myshopify.com"
    assert len(calls) == 1
    assert calls[0].get("note_attributes") == [
        {"name": "buyer_note", "value": "leave at door"},
        {"name": "tenant_id", "value": "tenant-a"},
        {
            "name": "paybond_intent_id",
            "value": "00000000-0000-0000-0000-000000000111",
        },
    ]


@pytest.mark.asyncio
async def test_shopify_missing_executor_cost_cents_fails_closed() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }

    async def execute_checkout(
        _input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        # Intentionally incomplete executor result for fail-closed coverage.
        return cast(
            ShopifyCheckoutToolResult,
            cast(object, {"status": "completed", "shop": "demo.myshopify.com"}),
        )

    shopify = create_shopify_commerce_provider(execute_checkout=execute_checkout)
    checkout = create_commerce_checkout_router(
        providers={"shopify": shopify},
        default_provider="shopify",
        binding=lambda: binding,
    )

    with pytest.raises(ValueError, match="missing cost_cents"):
        _ = await checkout(
            {
                "amount_cents": 4500,
                "shopify": {
                    "shop_domain": "demo.myshopify.com",
                    "line_items": [{"variant_id": "123", "quantity": 1}],
                },
            }
        )


@pytest.mark.asyncio
async def test_shopify_none_executor_cost_cents_fails_closed() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }

    async def execute_checkout(
        _input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        # Intentionally invalid executor result for fail-closed coverage.
        return cast(
            ShopifyCheckoutToolResult,
            cast(
                object,
                {
                    "status": "completed",
                    "cost_cents": None,
                    "shop": "demo.myshopify.com",
                },
            ),
        )

    shopify = create_shopify_commerce_provider(execute_checkout=execute_checkout)
    checkout = create_commerce_checkout_router(
        providers={"shopify": shopify},
        default_provider="shopify",
        binding=lambda: binding,
    )

    with pytest.raises(ValueError, match="missing cost_cents"):
        _ = await checkout(
            {
                "amount_cents": 4500,
                "shopify": {
                    "shop_domain": "demo.myshopify.com",
                    "line_items": [{"variant_id": "123", "quantity": 1}],
                },
            }
        )


@pytest.mark.asyncio
async def test_router_routes_stripe_and_stamps_metadata() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }

    async def execute_stripe(
        input_payload: StripeCommerceCheckoutExecuteInput,
    ) -> StripeCommerceCheckoutExecutorResult:
        assert input_payload["metadata"]["tenant_id"] == "tenant-a"
        assert input_payload["metadata"]["paybond_intent_id"] == (
            "00000000-0000-0000-0000-000000000111"
        )
        assert input_payload["metadata"]["paybond_settlement_rail"] == "stripe_connect"
        return {
            "status": "completed",
            "cost_cents": input_payload["amount_cents"],
            "payment_intent_id": "pi_test_123",
        }

    async def execute_shopify(
        _input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        raise AssertionError("shopify should not run")

    stripe = create_stripe_commerce_provider(execute_checkout=execute_stripe)
    shopify = create_shopify_commerce_provider(execute_checkout=execute_shopify)
    checkout = create_commerce_checkout_router(
        providers={"shopify": shopify, "stripe": stripe},
        default_provider="shopify",
        binding=lambda: binding,
    )

    result = await checkout(
        {
            "provider": "stripe",
            "amount_cents": 1999,
            "stripe": {
                "rail": "stripe_connect",
                "description": "agent cart",
            },
        }
    )

    assert result["status"] == "completed"
    assert result["cost_cents"] == 1999
    assert result["provider"] == "stripe"
    assert result.get("payment_intent_id") == "pi_test_123"
    assert result.get("order_id") == "pi_test_123"


@pytest.mark.asyncio
async def test_zinc_sandbox_product_derived_cost() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }
    zinc = create_zinc_commerce_provider(
        mode="sandbox",
        sandbox_order_id_prefix="zinc_test_",
    )
    checkout = create_commerce_checkout_router(
        providers={"zinc": zinc},
        default_provider="zinc",
        binding=lambda: binding,
    )

    result = await checkout(
        {
            "amount_cents": 3200,
            "zinc": {
                "retailer": "amazon",
                "products": [{"product_id": "B00TEST", "quantity": 1, "price_cents": 3200}],
                "max_price_cents": 5000,
            },
        }
    )

    assert result["status"] == "completed"
    assert result["cost_cents"] == 3200
    assert result["provider"] == "zinc"
    assert result.get("order_id") == "zinc_test_ord_amazon_B00TEST"
    assert str(result.get("zinc_request_id", "")).startswith("zinc_test_")


@pytest.mark.asyncio
async def test_zinc_sandbox_fails_over_max_price() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }
    zinc = create_zinc_commerce_provider(mode="sandbox")
    checkout = create_commerce_checkout_router(
        providers={"zinc": zinc},
        default_provider="zinc",
        binding=lambda: binding,
    )

    result = await checkout(
        {
            "amount_cents": 9000,
            "zinc": {
                "retailer": "amazon",
                "products": [{"product_id": "B00TEST", "quantity": 1, "price_cents": 9000}],
                "max_price_cents": 5000,
            },
        }
    )

    assert result["status"] == "failed"
    assert result["cost_cents"] == 0


@pytest.mark.asyncio
async def test_zinc_sandbox_rejects_under_reported_amount() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }
    zinc = create_zinc_commerce_provider(mode="sandbox")
    checkout = create_commerce_checkout_router(
        providers={"zinc": zinc},
        default_provider="zinc",
        binding=lambda: binding,
    )

    with pytest.raises(ValueError, match=r"must equal product-derived cost_cents \(3000\)"):
        _ = await checkout(
            {
                "amount_cents": 1000,
                "zinc": {
                    "retailer": "amazon",
                    "products": [{"product_id": "B00TEST", "quantity": 2, "price_cents": 1500}],
                },
            }
        )


@pytest.mark.asyncio
async def test_zinc_sandbox_rejects_over_reported_amount() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }
    zinc = create_zinc_commerce_provider(mode="sandbox")
    checkout = create_commerce_checkout_router(
        providers={"zinc": zinc},
        default_provider="zinc",
        binding=lambda: binding,
    )

    with pytest.raises(ValueError, match=r"must equal product-derived cost_cents \(3200\)"):
        _ = await checkout(
            {
                "amount_cents": 5000,
                "zinc": {
                    "retailer": "amazon",
                    "products": [{"product_id": "B00TEST", "quantity": 1, "price_cents": 3200}],
                },
            }
        )


@pytest.mark.asyncio
async def test_zinc_rejects_invalid_max_price_cents() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }
    zinc = create_zinc_commerce_provider(mode="sandbox")
    checkout = create_commerce_checkout_router(
        providers={"zinc": zinc},
        default_provider="zinc",
        binding=lambda: binding,
    )

    with pytest.raises(ValueError, match="max_price_cents"):
        _ = await checkout(
            {
                "amount_cents": 100,
                "zinc": {
                    "retailer": "amazon",
                    "products": [{"product_id": "B00", "quantity": 1, "price_cents": 100}],
                    "max_price_cents": -1,
                },
            }
        )


def test_derive_zinc_products_cost_cents() -> None:
    assert (
        derive_zinc_products_cost_cents(
            [
                {"product_id": "A", "quantity": 2, "price_cents": 1500},
                {"product_id": "B", "quantity": 1, "price_cents": 200},
            ]
        )
        == 3200
    )


@pytest.mark.asyncio
async def test_rejects_unknown_provider() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }

    async def execute_checkout(
        _input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        return {"status": "completed", "cost_cents": 1, "shop": "demo.myshopify.com"}

    shopify = create_shopify_commerce_provider(execute_checkout=execute_checkout)
    checkout = create_commerce_checkout_router(
        providers={"shopify": shopify},
        default_provider="shopify",
        binding=lambda: binding,
    )

    with pytest.raises(ValueError, match="unknown provider"):
        _ = await checkout(
            cast(
                CommerceCheckoutToolArgs,
                cast(object, {"provider": "ebay", "amount_cents": 100}),
            )
        )


@pytest.mark.asyncio
async def test_rejects_blank_provider() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }

    async def execute_checkout(
        _input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        return {"status": "completed", "cost_cents": 1, "shop": "demo.myshopify.com"}

    shopify = create_shopify_commerce_provider(execute_checkout=execute_checkout)
    checkout = create_commerce_checkout_router(
        providers={"shopify": shopify},
        default_provider="shopify",
        binding=lambda: binding,
    )

    with pytest.raises(ValueError, match="unknown provider"):
        _ = await checkout(
            cast(
                CommerceCheckoutToolArgs,
                cast(
                    object,
                    {
                        "provider": "",
                        "amount_cents": 100,
                        "shopify": {
                            "shop_domain": "demo.myshopify.com",
                            "line_items": [{"variant_id": "1", "quantity": 1}],
                        },
                    },
                ),
            )
        )


@pytest.mark.asyncio
async def test_rejects_missing_adapter() -> None:
    binding: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-a",
        "intent_id": "00000000-0000-0000-0000-000000000111",
    }

    async def execute_checkout(
        _input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        return {"status": "completed", "cost_cents": 1, "shop": "demo.myshopify.com"}

    shopify = create_shopify_commerce_provider(execute_checkout=execute_checkout)
    checkout = create_commerce_checkout_router(
        providers={"shopify": shopify},
        default_provider="shopify",
        binding=lambda: binding,
    )

    with pytest.raises(ValueError, match="no adapter registered"):
        _ = await checkout(
            {
                "provider": "zinc",
                "amount_cents": 100,
                "zinc": {
                    "retailer": "amazon",
                    "products": [{"product_id": "B00", "quantity": 1, "price_cents": 100}],
                },
            }
        )


@pytest.mark.asyncio
async def test_fails_closed_without_binding() -> None:
    zinc = create_zinc_commerce_provider(mode="sandbox")
    checkout = create_commerce_checkout_router(
        providers={"zinc": zinc},
        default_provider="zinc",
        binding=lambda: {"tenant_id": "", "intent_id": ""},
    )

    with pytest.raises(ValueError, match="Paybond session binding is required"):
        _ = await checkout(
            {
                "amount_cents": 100,
                "zinc": {
                    "retailer": "amazon",
                    "products": [{"product_id": "B00", "quantity": 1, "price_cents": 100}],
                },
            }
        )


def test_requires_default_provider_adapter() -> None:
    with pytest.raises(ValueError, match="default_provider"):
        _ = create_commerce_checkout_router(
            providers={},
            default_provider="shopify",
            binding=lambda: {
                "tenant_id": "t",
                "intent_id": "00000000-0000-0000-0000-000000000111",
            },
        )


def test_resolve_commerce_checkout_provider_explicit() -> None:
    async def execute_checkout(
        _input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        return {"status": "completed", "cost_cents": 1, "shop": "demo.myshopify.com"}

    shopify = create_shopify_commerce_provider(execute_checkout=execute_checkout)
    zinc = create_zinc_commerce_provider(mode="sandbox")
    provider_id, _provider = resolve_commerce_checkout_provider(
        {"provider": "zinc", "amount_cents": 1},
        providers={"shopify": shopify, "zinc": zinc},
        default_provider="shopify",
    )
    assert provider_id == "zinc"


def test_zinc_live_requires_http_client() -> None:
    with pytest.raises(ValueError, match="http_client"):
        _ = create_zinc_commerce_provider(mode="live")


def test_zinc_rejects_invalid_mode_casing() -> None:
    with pytest.raises(ValueError, match='mode must be "sandbox" or "live"'):
        _ = create_zinc_commerce_provider(mode="Live")
    with pytest.raises(ValueError, match='mode must be "sandbox" or "live"'):
        _ = create_zinc_commerce_provider(mode="production")


@pytest.mark.asyncio
async def test_zinc_live_delegates_to_http_client() -> None:
    calls: list[ZincCheckoutRequest] = []

    async def http_client(request: ZincCheckoutRequest) -> ZincHttpClientResult:
        calls.append(request)
        assert request["tenant_id"] == "tenant-a"
        assert request["intent_id"] == "00000000-0000-0000-0000-000000000111"
        return {
            "status": "completed",
            "cost_cents": 2200,
            "order_id": "live_ord_1",
            "zinc_request_id": "req_live_1",
        }

    zinc = create_zinc_commerce_provider(mode="live", http_client=http_client)
    result = await zinc.checkout(
        {
            "amount_cents": 1100,
            "zinc": {
                "retailer": "amazon",
                "products": [{"product_id": "B00LIVE", "quantity": 2}],
            },
        },
        {
            "tenant_id": "tenant-a",
            "intent_id": "00000000-0000-0000-0000-000000000111",
        },
    )

    assert result["status"] == "completed"
    assert result["cost_cents"] == 2200
    assert result["provider"] == "zinc"
    assert result.get("order_id") == "live_ord_1"
    assert result.get("zinc_request_id") == "req_live_1"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_guarded_handler_instrument_smoke() -> None:
    binding_ref: CommerceCheckoutSessionBinding = {
        "tenant_id": "tenant-smoke",
        "intent_id": "00000000-0000-0000-0000-000000000222",
    }

    async def execute_checkout(
        input_payload: ShopifyCheckoutExecuteInput,
    ) -> ShopifyCheckoutToolResult:
        return {
            "status": "completed",
            "cost_cents": input_payload.get("amount_cents", 0),
            "order_id": "gid://shopify/Order/999",
            "shop": input_payload.get("shop_domain", ""),
        }

    shopify = create_shopify_commerce_provider(execute_checkout=execute_checkout)
    zinc = create_zinc_commerce_provider(
        mode="sandbox",
        sandbox_order_id_prefix="smoke_",
    )
    checkout = create_guarded_commerce_checkout_handler(
        providers={"shopify": shopify, "zinc": zinc},
        default_provider="shopify",
        binding=lambda: binding_ref,
    )

    shopify_result = await checkout(
        {
            "amount_cents": 4500,
            "shopify": {
                "shop_domain": "paybond-agent-commerce-dev.myshopify.com",
                "line_items": [
                    {"variant_id": "gid://shopify/ProductVariant/1", "quantity": 1}
                ],
            },
        }
    )
    assert shopify_result["provider"] == "shopify"
    assert shopify_result["cost_cents"] == 4500

    zinc_result = await checkout(
        {
            "provider": "zinc",
            "amount_cents": 1800,
            "zinc": {
                "retailer": "amazon",
                "products": [{"product_id": "B00SMOKE", "quantity": 1, "price_cents": 1800}],
            },
        }
    )
    assert zinc_result["status"] == "completed"
    assert zinc_result["cost_cents"] == 1800
    assert zinc_result["provider"] == "zinc"
    assert zinc_result.get("order_id") == "smoke_ord_amazon_B00SMOKE"
