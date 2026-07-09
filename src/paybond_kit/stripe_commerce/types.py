"""Types for Stripe commerce metadata and evidence mapping."""

from __future__ import annotations

from typing import Literal, TypedDict

PaybondStripeSettlementRail = Literal["stripe_connect", "stripe_ach_debit"]
StripeCommerceEvidencePreset = Literal["stripe_charge", "cost_and_completion"]


class PaybondStripeMetadata(TypedDict, total=False):
    tenant_id: str
    paybond_intent_id: str
    paybond_settlement_rail: PaybondStripeSettlementRail


class BuildPaybondStripeMetadataParams(TypedDict, total=False):
    tenant_id: str
    intent_id: str
    rail: PaybondStripeSettlementRail


class MapStripeToolResultToEvidenceOptions(TypedDict):
    preset: StripeCommerceEvidencePreset


class StripeChargeVendorEvidence(TypedDict):
    charge_id: str
    http_status: int
    response_digest: str


class CostAndCompletionEvidence(TypedDict):
    status: str
    cost_cents: int
