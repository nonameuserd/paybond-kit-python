from __future__ import annotations

import pytest

from paybond_kit.x402_receipt_evidence import (
    assert_not_x402_funding_artifact,
    build_x402_receipt_digest_payload,
    map_x402_receipt_to_artifact_attested_evidence,
    x402_receipt_payload_digest_hex,
)
from tests.helpers.evidence_fixtures import signed_jws_x402_receipt


def test_maps_signed_receipt_payload_to_artifact_attested_evidence() -> None:
    receipt = {
        "resourceUrl": "https://api.vendor.example/job/123",
        "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
        "network": "eip155:8453",
        "issuedAt": 1_700_000_000,
        "transaction": "0xabc123",
    }
    evidence = map_x402_receipt_to_artifact_attested_evidence(signed_jws_x402_receipt(receipt))
    assert evidence["operation"] == "attested"
    assert evidence["vendor_ref_id"] == "https://api.vendor.example/job/123"
    assert len(evidence["artifact_blake3_hex"]) == 1
    assert evidence["artifact_blake3_hex"][0] == x402_receipt_payload_digest_hex(
        build_x402_receipt_digest_payload(receipt)
    )


def test_unwraps_offer_receipt_extension_envelope() -> None:
    payload = {
        "resourceUrl": "https://api.vendor.example/job/456",
        "payer": "0xabc",
        "network": "eip155:8453",
        "issuedAt": 1_700_000_001,
    }
    evidence = map_x402_receipt_to_artifact_attested_evidence(signed_jws_x402_receipt(payload))
    assert evidence["vendor_ref_id"] == "https://api.vendor.example/job/456"


def test_rejects_unsigned_receipt_payload() -> None:
    with pytest.raises(ValueError, match="signed offer-receipt artifact"):
        map_x402_receipt_to_artifact_attested_evidence(
            {
                "resourceUrl": "https://api.vendor.example/job/123",
                "payer": "0xabc",
                "network": "eip155:8453",
                "issuedAt": 1,
            }
        )


def test_rejects_coinbase_authorization_funding_webhook_shape() -> None:
    with pytest.raises(ValueError, match="authorization_succeeded"):
        assert_not_x402_funding_artifact({"eventType": "authorization_succeeded"})


def test_rejects_payment_session_id_in_receipt_input() -> None:
    with pytest.raises(ValueError, match="payment_session_id"):
        map_x402_receipt_to_artifact_attested_evidence(
            {
                "payment_session_id": "paymentSession_123",
                "resourceUrl": "https://api.vendor.example/job/123",
                "payer": "0xabc",
                "network": "eip155:8453",
                "issuedAt": 1,
            }
        )
