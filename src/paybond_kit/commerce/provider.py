"""Provider contract and binding helpers for multi-provider commerce.checkout."""

from __future__ import annotations

from typing import Protocol

from paybond_kit.commerce.types import (
    CommerceCheckoutSessionBinding,
    CommerceCheckoutToolArgs,
    CommerceCheckoutToolResult,
    CommerceProviderId,
)


class CommerceCheckoutProvider(Protocol):
    """Thin adapter contract for a commerce.checkout provider.

    Adapters receive session-sourced binding and tool args; they must never trust
    client-supplied tenant or intent identifiers.
    """

    @property
    def id(self) -> CommerceProviderId: ...

    async def checkout(
        self,
        args: CommerceCheckoutToolArgs,
        binding: CommerceCheckoutSessionBinding,
    ) -> CommerceCheckoutToolResult: ...


def require_commerce_session_binding(
    binding: CommerceCheckoutSessionBinding,
) -> CommerceCheckoutSessionBinding:
    """Validate and normalize a Paybond session binding for commerce checkout.

    Raises:
        ValueError: when tenant_id or intent_id are missing/blank.
    """

    tenant_id = str(binding.get("tenant_id", "")).strip()
    intent_id = str(binding.get("intent_id", "")).strip()
    if not tenant_id or not intent_id:
        raise ValueError("Paybond session binding is required before commerce.checkout")
    return {"tenant_id": tenant_id, "intent_id": intent_id}


def require_amount_cents(amount_cents: object) -> int:
    """Assert amount_cents is a non-negative integer."""

    if not isinstance(amount_cents, int) or isinstance(amount_cents, bool) or amount_cents < 0:
        raise ValueError("commerce.checkout: amount_cents must be a non-negative integer")
    return amount_cents
