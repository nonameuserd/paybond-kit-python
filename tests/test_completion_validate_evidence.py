from __future__ import annotations

from paybond_kit.completion_catalog import get_completion_preset
from paybond_kit.completion_validate_evidence import validate_completion_evidence


def test_validate_stripe_charge_vendor_payload() -> None:
    preset = get_completion_preset("stripe_charge")
    report = validate_completion_evidence(
        preset_id="stripe_charge",
        vendor_payload=preset.get("vendor_sample_evidence"),
    )
    assert report["vendor_schema_ok"] is True
    assert report["canonical_schema_ok"] is True
    assert report["drift_kinds"] == []


def test_validate_pack_stale_frozen_api_version() -> None:
    preset = get_completion_preset("stripe_charge")
    report = validate_completion_evidence(
        preset_id="stripe_charge",
        vendor_payload=preset.get("vendor_sample_evidence"),
        frozen_vendor_api_version="legacy_epoch",
    )
    assert report["pack_stale"] is True
    assert "pack_stale" in report["drift_kinds"]


def test_validate_missing_quality_fields() -> None:
    report = validate_completion_evidence(
        preset_id="ach_travel_booking",
        vendor_payload={
            "confirmation_number": "AA-123",
            "http_status": 200,
            "response_digest": "blake3:abc",
            "status": "confirmed",
            "total_cents": 12000,
        },
    )
    assert "fare_class" in report["quality_fields_missing"]
    assert "quality_field_missing" in report["drift_kinds"]


def test_validate_rejects_forbidden_evidence_fields() -> None:
    report = validate_completion_evidence(
        preset_id="x402_paid_api_ok",
        vendor_payload={
            "http_status": 200,
            "response_digest": "blake3:abc",
            "payment_session_id": "sess_123",
        },
    )
    assert "payment_session_id" in report["forbidden_fields_present"]
    assert "forbidden_field_present" in report["drift_kinds"]
    assert report["vendor_schema_ok"] is False
