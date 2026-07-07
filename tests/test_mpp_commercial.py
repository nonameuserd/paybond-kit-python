from paybond_kit.mpp_commercial import (
    USDC_BASE_UNITS_PER_USD_CENT,
    usd_cents_to_usdc_base_units,
    validate_usd_denominated_settlement,
)


def test_usd_cents_to_usdc_base_units_scales_by_ten_thousand() -> None:
    assert USDC_BASE_UNITS_PER_USD_CENT == 10_000
    assert usd_cents_to_usdc_base_units(0) == 0
    assert usd_cents_to_usdc_base_units(1) == 10_000
    assert usd_cents_to_usdc_base_units(100) == 1_000_000
    assert usd_cents_to_usdc_base_units(12_345) == 123_450_000


def test_validate_usd_denominated_settlement_rejects_non_usd_for_stripe_mpp() -> None:
    try:
        validate_usd_denominated_settlement("stripe_mpp", "eur")
    except ValueError as exc:
        assert "currency must be usd when settlement_rail is stripe_mpp" in str(exc)
    else:
        raise AssertionError("expected ValueError for non-USD stripe_mpp currency")


def test_validate_usd_denominated_settlement_accepts_usd_for_stripe_mpp() -> None:
    validate_usd_denominated_settlement("stripe_mpp", "USD")
