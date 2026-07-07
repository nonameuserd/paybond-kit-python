"""MPP commercial denomination helpers for Paybond MVP."""

from __future__ import annotations

from typing import Final

from paybond_kit.harbor import SettlementRail

USDC_BASE_UNITS_PER_USD_CENT: Final[int] = 10_000

USD_DENOMINATED_SETTLEMENT_RAILS: Final[frozenset[SettlementRail]] = frozenset(
    {"x402_usdc_base", "stripe_ach_debit", "stripe_mpp"}
)


def validate_usd_denominated_settlement(settlement_rail: SettlementRail, currency: str) -> None:
    """Reject non-USD intents on rails that remain USD-denominated for MVP."""
    if settlement_rail not in USD_DENOMINATED_SETTLEMENT_RAILS:
        return
    if currency.strip().lower() != "usd":
        raise ValueError(
            f"currency must be usd when settlement_rail is {settlement_rail} "
            "until multi-currency policy is defined"
        )


def usd_cents_to_usdc_base_units(amount_cents: int) -> int:
    """Convert Paybond USD cents to Tempo USDC base units."""
    if amount_cents < 0:
        raise ValueError("amount_cents must be non-negative")
    return amount_cents * USDC_BASE_UNITS_PER_USD_CENT
