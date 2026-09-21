"""Stripe adapter for multi-provider commerce.checkout."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
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
)
from paybond_kit.commerce_binding import encode_commerce_binding_to_stripe_metadata
from paybond_kit.stripe_commerce.metadata import build_paybond_stripe_metadata
from paybond_kit.stripe_commerce.types import PaybondStripeSettlementRail


class _StripeCommerceCheckoutExecuteInputRequired(TypedDict):
    tenant_id: str
    intent_id: str
    amount_cents: int
    currency: str
    metadata: dict[str, str]


class StripeCommerceCheckoutExecuteInput(_StripeCommerceCheckoutExecuteInputRequired, total=False):
    """Binding-injected input passed to a Stripe checkout executor.

    Optional keys use ``total=False`` inheritance so they stay optional under
    ``from __future__ import annotations`` (``NotRequired`` is ignored by
    TypedDict on Python 3.11 with postponed annotations).
    """

    description: str
    rail: PaybondStripeSettlementRail
    payment_intent_id: str


class _StripeCommerceCheckoutExecutorResultRequired(TypedDict):
    status: CommerceCheckoutStatus
    cost_cents: int


class StripeCommerceCheckoutExecutorResult(_StripeCommerceCheckoutExecutorResultRequired, total=False):
    """Canonical executor envelope — matches TS ``{ status, cost_cents, ... }``."""

    order_id: str
    payment_intent_id: str


StripeCommerceCheckoutExecutor = Callable[
    [StripeCommerceCheckoutExecuteInput], Awaitable[StripeCommerceCheckoutExecutorResult]
]


@dataclass(slots=True)
class _StripeCommerceProvider:
    execute_checkout: StripeCommerceCheckoutExecutor
    default_currency: str

    @property
    def id(self) -> CommerceProviderId:
        return "stripe"

    async def checkout(
        self,
        args: CommerceCheckoutToolArgs,
        binding: CommerceCheckoutSessionBinding,
    ) -> CommerceCheckoutToolResult:
        session = require_commerce_session_binding(binding)
        amount_cents = require_amount_cents(args.get("amount_cents"))
        stripe_args = args.get("stripe") or {}

        metadata = encode_commerce_binding_to_stripe_metadata(
            {"tenant_id": session["tenant_id"], "intent_id": session["intent_id"]},
            stripe_args.get("existing_metadata"),
        )

        rail = stripe_args.get("rail")
        if rail is not None:
            with_rail = build_paybond_stripe_metadata(
                {
                    "tenant_id": session["tenant_id"],
                    "intent_id": session["intent_id"],
                    "rail": rail,
                }
            )
            metadata.update(with_rail)

        currency = str(stripe_args.get("currency") or self.default_currency).strip().lower() or self.default_currency

        execute_input: StripeCommerceCheckoutExecuteInput = {
            "tenant_id": session["tenant_id"],
            "intent_id": session["intent_id"],
            "amount_cents": amount_cents,
            "currency": currency,
            "metadata": metadata,
        }
        description = stripe_args.get("description")
        if description is not None:
            execute_input["description"] = description
        if rail is not None:
            execute_input["rail"] = rail
        payment_intent_id_arg = stripe_args.get("payment_intent_id")
        if payment_intent_id_arg:
            execute_input["payment_intent_id"] = payment_intent_id_arg

        result = await self.execute_checkout(execute_input)
        cost_raw = result.get("cost_cents")
        if cost_raw is None:
            raise ValueError("commerce.checkout: stripe executor result missing cost_cents")
        if not isinstance(cost_raw, int) or isinstance(cost_raw, bool) or cost_raw < 0:
            raise ValueError(
                "commerce.checkout: stripe executor result cost_cents must be a non-negative integer"
            )
        payment_intent_id = result.get("payment_intent_id")
        out: CommerceCheckoutToolResult = {
            "status": result["status"],
            "cost_cents": cost_raw,
            "provider": "stripe",
        }
        order_id = result.get("order_id") or payment_intent_id
        if order_id:
            out["order_id"] = order_id
        if payment_intent_id:
            out["payment_intent_id"] = payment_intent_id
        return out


def create_stripe_commerce_provider(
    *,
    execute_checkout: StripeCommerceCheckoutExecutor,
    default_currency: str = "usd",
) -> _StripeCommerceProvider:
    """Create a Stripe adapter for the multi-provider commerce checkout router.

    Stamps PaymentIntent metadata with session-sourced ``tenant_id`` /
    ``paybond_intent_id`` via :func:`encode_commerce_binding_to_stripe_metadata`.
    """

    currency = (default_currency or "usd").strip().lower() or "usd"
    return _StripeCommerceProvider(
        execute_checkout=execute_checkout,
        default_currency=currency,
    )
