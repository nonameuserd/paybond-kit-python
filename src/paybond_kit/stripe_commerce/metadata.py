"""Build Stripe PaymentIntent metadata bound to Harbor intents."""

from __future__ import annotations

from paybond_kit.stripe_commerce.types import (
    BuildPaybondStripeMetadataParams,
    PaybondStripeSettlementRail,
)

PAYBOND_STRIPE_METADATA_TENANT_ID_KEY = "tenant_id"
PAYBOND_STRIPE_METADATA_INTENT_ID_KEY = "paybond_intent_id"
PAYBOND_STRIPE_METADATA_RAIL_KEY = "paybond_settlement_rail"

_STRIPE_METADATA_RAILS: frozenset[PaybondStripeSettlementRail] = frozenset(
    {"stripe_connect", "stripe_ach_debit"}
)


def build_paybond_stripe_metadata(params: BuildPaybondStripeMetadataParams) -> dict[str, str]:
    """Build Stripe metadata using authenticated Paybond tenant and intent identifiers."""
    tenant_id = str(params.get("tenant_id", "")).strip()
    intent_id = str(params.get("intent_id", "")).strip()
    if not tenant_id:
        raise ValueError("build_paybond_stripe_metadata: tenant_id is required")
    if not intent_id:
        raise ValueError("build_paybond_stripe_metadata: intent_id is required")

    metadata: dict[str, str] = {
        PAYBOND_STRIPE_METADATA_TENANT_ID_KEY: tenant_id,
        PAYBOND_STRIPE_METADATA_INTENT_ID_KEY: intent_id,
    }

    rail = params.get("rail")
    if rail is not None:
        if rail not in _STRIPE_METADATA_RAILS:
            raise ValueError(
                "build_paybond_stripe_metadata: rail must be stripe_connect or stripe_ach_debit"
            )
        metadata[PAYBOND_STRIPE_METADATA_RAIL_KEY] = rail

    return metadata
