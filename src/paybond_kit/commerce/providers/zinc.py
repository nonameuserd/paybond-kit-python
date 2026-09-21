"""Zinc adapter for multi-provider commerce.checkout (sandbox + optional live HTTP)."""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TypedDict

from paybond_kit.commerce.provider import (
    require_amount_cents,
    require_commerce_session_binding,
)
from paybond_kit.commerce.types import (
    CommerceCheckoutSessionBinding,
    CommerceCheckoutStatus,
    CommerceCheckoutToolArgs,
    CommerceCheckoutToolResult,
    CommerceProviderId,
    CommerceZincCheckoutArgs,
    CommerceZincProductInput,
)


class _ZincCheckoutRequestRequired(TypedDict):
    tenant_id: str
    intent_id: str
    amount_cents: int
    retailer: str
    products: list[CommerceZincProductInput]


class ZincCheckoutRequest(_ZincCheckoutRequestRequired, total=False):
    """Binding-injected Zinc order request used by sandbox and optional live clients.

    Optional keys use ``total=False`` inheritance so they stay optional under
    ``from __future__ import annotations`` (``NotRequired`` is ignored by
    TypedDict on Python 3.11 with postponed annotations).
    """

    shipping_address: dict[str, str]
    max_price_cents: int


class _ZincHttpClientResultRequired(TypedDict):
    status: CommerceCheckoutStatus
    cost_cents: int


class ZincHttpClientResult(_ZincHttpClientResultRequired, total=False):
    """Live HTTP client envelope — matches TS ``{ status, cost_cents, ... }``."""

    order_id: str
    zinc_request_id: str


ZincHttpClient = Callable[[ZincCheckoutRequest], Awaitable[ZincHttpClientResult]]


def _require_non_negative_cents(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"commerce.checkout: {label} must be a non-negative integer")
    return value


def derive_zinc_products_cost_cents(products: Sequence[CommerceZincProductInput]) -> int:
    """Sum unit ``price_cents * quantity`` across Zinc products.

    Raises:
        ValueError: when any product lacks a valid non-negative integer ``price_cents``.
    """

    total = 0
    for product in products:
        unit = _require_non_negative_cents(product.get("price_cents"), "zinc product price_cents")
        quantity = product.get("quantity")
        if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0:
            raise ValueError("commerce.checkout: zinc product quantity must be a positive integer")
        total += unit * quantity
    return total


def _require_zinc_args(args: CommerceCheckoutToolArgs) -> CommerceZincCheckoutArgs:
    zinc = args.get("zinc")
    if not zinc:
        raise ValueError('commerce.checkout: zinc payload is required when provider is "zinc"')
    if not str(zinc.get("retailer", "")).strip():
        raise ValueError("commerce.checkout: zinc.retailer is required")
    products = zinc.get("products")
    if not isinstance(products, list) or len(products) == 0:
        raise ValueError("commerce.checkout: zinc.products must include at least one item")
    for product in products:
        if not str(product.get("product_id", "")).strip():
            raise ValueError("commerce.checkout: zinc product_id is required")
        quantity = product.get("quantity")
        if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0:
            raise ValueError("commerce.checkout: zinc product quantity must be a positive integer")
    if "max_price_cents" in zinc:
        _require_non_negative_cents(zinc.get("max_price_cents"), "zinc.max_price_cents")
    return zinc


def _sandbox_checkout(
    request: ZincCheckoutRequest,
    order_id_prefix: str,
) -> CommerceCheckoutToolResult:
    derived_cost_cents = derive_zinc_products_cost_cents(request["products"])

    max_price = request.get("max_price_cents")
    if max_price is not None and derived_cost_cents > max_price:
        return {
            "status": "failed",
            "cost_cents": 0,
            "provider": "zinc",
            "zinc_request_id": f"{order_id_prefix}req_over_max",
        }

    if request["amount_cents"] != derived_cost_cents:
        raise ValueError(
            f"commerce.checkout: zinc amount_cents ({request['amount_cents']}) must equal "
            f"product-derived cost_cents ({derived_cost_cents})"
        )

    request_id = f"{order_id_prefix}{secrets.token_hex(6)}"
    first_product = request["products"][0]["product_id"] if request["products"] else "item"
    return {
        "status": "completed",
        # Product-derived — never invent from agent amount_cents alone.
        "cost_cents": derived_cost_cents,
        "order_id": f"{order_id_prefix}ord_{request['retailer']}_{first_product}",
        "provider": "zinc",
        "zinc_request_id": request_id,
    }


@dataclass(slots=True)
class _ZincCommerceProvider:
    mode: str
    http_client: ZincHttpClient | None
    sandbox_order_id_prefix: str

    @property
    def id(self) -> CommerceProviderId:
        return "zinc"

    async def checkout(
        self,
        args: CommerceCheckoutToolArgs,
        binding: CommerceCheckoutSessionBinding,
    ) -> CommerceCheckoutToolResult:
        session = require_commerce_session_binding(binding)
        amount_cents = require_amount_cents(args.get("amount_cents"))
        zinc_args = _require_zinc_args(args)

        request: ZincCheckoutRequest = {
            "tenant_id": session["tenant_id"],
            "intent_id": session["intent_id"],
            "amount_cents": amount_cents,
            "retailer": zinc_args["retailer"].strip(),
            "products": zinc_args["products"],
        }
        shipping_address = zinc_args.get("shipping_address")
        if shipping_address is not None:
            request["shipping_address"] = shipping_address
        max_price_cents = zinc_args.get("max_price_cents")
        if max_price_cents is not None:
            request["max_price_cents"] = max_price_cents

        if self.mode == "sandbox":
            return _sandbox_checkout(request, self.sandbox_order_id_prefix)

        assert self.http_client is not None
        result = await self.http_client(request)
        cost_raw = result.get("cost_cents")
        if cost_raw is None:
            raise ValueError("commerce.checkout: zinc http_client result missing cost_cents")
        cost_cents = _require_non_negative_cents(cost_raw, "zinc http_client result cost_cents")
        out: CommerceCheckoutToolResult = {
            "status": result["status"],
            "cost_cents": cost_cents,
            "provider": "zinc",
        }
        order_id = result.get("order_id")
        if order_id:
            out["order_id"] = order_id
        zinc_request_id = result.get("zinc_request_id")
        if zinc_request_id:
            out["zinc_request_id"] = zinc_request_id
        return out


def create_zinc_commerce_provider(
    *,
    mode: str = "sandbox",
    http_client: ZincHttpClient | None = None,
    sandbox_order_id_prefix: str = "zinc_sandbox_",
) -> _ZincCommerceProvider:
    """Create a Zinc adapter for the multi-provider commerce checkout router.

    Default ``sandbox`` mode is fully offline for e2e / instrument smoke tests.
    Live HTTP is optional via a pluggable ``http_client`` — Kit does not ship a
    hard-coded Zinc API dependency or Gateway buy-proxy.

    ``mode`` must be exactly ``\"sandbox\"`` or ``\"live\"`` after trim
    (``\"Live\"`` / ``\"production\"`` are rejected).
    """

    normalized_mode = mode.strip()
    if normalized_mode not in {"sandbox", "live"}:
        raise ValueError('create_zinc_commerce_provider: mode must be "sandbox" or "live"')
    if normalized_mode == "live" and http_client is None:
        raise ValueError('create_zinc_commerce_provider: http_client is required when mode is "live"')

    return _ZincCommerceProvider(
        mode=normalized_mode,
        http_client=http_client,
        sandbox_order_id_prefix=sandbox_order_id_prefix,
    )
