from __future__ import annotations

import pytest

from paybond_kit.completion_catalog import load_completion_catalog
from paybond_kit.completion_resolve import (
    completion_preset_deprecation_warning,
    map_vendor_evidence_to_canonical,
    resolve_completion_preset,
)
from paybond_kit.mcp_sep2828_evidence import map_sep2828_receipts_to_artifact_attested_evidence
from paybond_kit.x402_receipt_evidence import (
    assert_not_x402_funding_artifact,
    build_x402_receipt_digest_payload,
    map_x402_receipt_to_artifact_attested_evidence,
    x402_receipt_payload_digest_hex,
)
from tests.helpers.evidence_fixtures import signed_jws_x402_receipt, signed_sep2828_pair


def test_stripe_charge_resolves_to_api_response_archetype() -> None:
    resolved = resolve_completion_preset("stripe_charge")
    assert resolved["kind"] == "vendor_pack"
    assert resolved["archetype"]["preset_id"] == "api_response_ok"
    assert resolved["harbor_template_id"] == "api_response_v1"


def test_vendor_webhook_confirmed_uses_neutral_event_type() -> None:
    resolved = resolve_completion_preset("vendor_webhook_confirmed")
    assert resolved["parameters"]["expected_event_type"] == "job.completed"


def test_stripe_webhook_payment_deprecation_warning() -> None:
    warning = completion_preset_deprecation_warning("stripe_webhook_payment")
    assert warning is not None
    assert "vendor_webhook_confirmed" in warning


def test_vendor_evidence_field_map() -> None:
    resolved = resolve_completion_preset("stripe_charge")
    canonical = map_vendor_evidence_to_canonical(
        resolved["preset"],
        {
            "charge_id": "ch_123",
            "http_status": 200,
            "response_digest": "blake3:abc",
        },
    )
    assert canonical == {
        "vendor_ref_id": "ch_123",
        "http_status": 200,
        "response_digest": "blake3:abc",
    }


def test_ach_paid_api_ok_maps_confirmation_number() -> None:
    resolved = resolve_completion_preset("ach_paid_api_ok")
    canonical = map_vendor_evidence_to_canonical(
        resolved["preset"],
        {
            "confirmation_number": "AA-8JZ3QK",
            "http_status": 200,
            "response_digest": "blake3:abc",
        },
    )
    assert canonical["vendor_ref_id"] == "AA-8JZ3QK"


def test_x402_delivery_receipt_wraps_receipt_digest() -> None:
    resolved = resolve_completion_preset("x402_delivery_receipt")
    canonical = map_vendor_evidence_to_canonical(
        resolved["preset"],
        {
            "receipt_digest": "deadbeef",
            "resource_url": "https://api.vendor.example/job/123",
            "operation": "attested",
        },
    )
    assert canonical == {
        "artifact_blake3_hex": ["deadbeef"],
        "vendor_ref_id": "https://api.vendor.example/job/123",
        "operation": "attested",
    }


def test_ach_travel_booking_uses_custom_evidence_schema() -> None:
    resolved = resolve_completion_preset("ach_travel_booking")
    required = resolved["evidence_schema"].get("required", [])
    assert "confirmation_number" in required
    assert "total_cents" in required
    assert resolved["parameters"]["cost_path"] == ["total_cents"]


def test_phase52_vendor_packs_declare_rail_hints_and_forbidden_fields() -> None:
    catalog = load_completion_catalog()
    ach = next(preset for preset in catalog["presets"] if preset["preset_id"] == "ach_vendor_webhook")
    x402 = next(preset for preset in catalog["presets"] if preset["preset_id"] == "x402_paid_api_ok")
    assert ach.get("rail_hints") == ["stripe_ach_debit"]
    assert "payment_intent_id" in (ach.get("forbidden_evidence_fields") or [])
    assert x402.get("rail_hints") == ["x402_usdc_base"]
    assert "payment_session_id" in (x402.get("forbidden_evidence_fields") or [])


def test_vertical_completion_presets_in_catalog() -> None:
    catalog = load_completion_catalog()
    for preset_id in ("x402_saas_api_purchase", "x402_travel_booking", "invoice_payment_confirmed"):
        preset = next(entry for entry in catalog["presets"] if entry["preset_id"] == preset_id)
        assert preset.get("kind") == "vendor_pack"
        assert preset.get("vendor_contract", {}).get("api_version")


def test_x402_saas_api_purchase_maps_subscription_id() -> None:
    resolved = resolve_completion_preset("x402_saas_api_purchase")
    canonical = map_vendor_evidence_to_canonical(
        resolved["preset"],
        {
            "subscription_id": "sub_abc",
            "seat_count": 2,
            "http_status": 200,
            "response_digest": "blake3:abc",
        },
    )
    assert canonical["vendor_ref_id"] == "sub_abc"


def test_invoice_payment_confirmed_uses_invoice_paid_event() -> None:
    resolved = resolve_completion_preset("invoice_payment_confirmed")
    assert resolved["parameters"]["expected_event_type"] == "invoice.paid"
    required = resolved["evidence_schema"].get("required", [])
    assert "invoice_number" in required
    assert "payment_reference" in required


def test_sep2828_receipt_import_maps_to_artifact_attested() -> None:
    decision, outcome = signed_sep2828_pair()
    evidence = map_sep2828_receipts_to_artifact_attested_evidence(decision, outcome)
    assert evidence["operation"] == "attested"
    assert evidence["vendor_ref_id"] == "sha256:deadbeef"
    assert "22222222" in evidence["artifact_blake3_hex"][1]


def test_sep2828_receipt_import_rejects_unsigned_records() -> None:
    with pytest.raises(ValueError, match="missing ed25519 signature"):
        map_sep2828_receipts_to_artifact_attested_evidence(
            {"backLink": {"attestationDigest": "sha256:deadbeef"}},
            {"backLink": {"attestationDigest": "sha256:deadbeef"}},
        )


SAMPLE_X402_RECEIPT = {
    "resourceUrl": "https://api.vendor.example/job/123",
    "payer": "0xabc123",
    "network": "eip155:84532",
    "issuedAt": 1710000000,
}


def test_x402_receipt_import_maps_to_artifact_attested() -> None:
    payload = build_x402_receipt_digest_payload(SAMPLE_X402_RECEIPT)
    digest = x402_receipt_payload_digest_hex(payload)
    assert len(digest) == 64

    evidence = map_x402_receipt_to_artifact_attested_evidence(signed_jws_x402_receipt(SAMPLE_X402_RECEIPT))
    assert evidence == {
        "artifact_blake3_hex": [digest],
        "operation": "attested",
        "vendor_ref_id": "https://api.vendor.example/job/123",
    }


def test_x402_receipt_import_rejects_unsigned_payload() -> None:
    with pytest.raises(ValueError, match="signed offer-receipt artifact"):
        map_x402_receipt_to_artifact_attested_evidence(SAMPLE_X402_RECEIPT)


def test_x402_receipt_import_rejects_funding_webhook() -> None:
    with pytest.raises(ValueError, match="funding signals"):
        assert_not_x402_funding_artifact(
            {"event_type": "authorization_succeeded", "payment_session_id": "sess_123"}
        )
