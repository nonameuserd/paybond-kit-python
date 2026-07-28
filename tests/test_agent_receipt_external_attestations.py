"""Tests for AP2 external attestation mappers."""

from __future__ import annotations

import pytest

from paybond_kit.agent_receipt import AgentReceiptExternalAttestationV1
from paybond_kit.agent_mandate import agent_mandate_digest_sha256_hex, normalize_agent_mandate_v1
from paybond_kit.agent_receipt_external_attestations import (
    AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
    AGENT_RECEIPT_EXTERNAL_SOURCE_X402,
    partner_record_digest_sha256_hex,
    protocol_authorization_receipt_to_external_attestations,
    protocol_settlement_receipt_to_external_attestations,
    resolve_external_attestations,
    signed_mandate_to_external_attestations,
    x402_receipt_to_external_attestations,
)
from tests.helpers.evidence_fixtures import (
    AP2_TEST_INTENT_ID,
    X402_FIXTURE_EXPECTED_SIGNER,
    signed_ap2_mandate,
    signed_jws_x402_receipt,
    signed_protocol_authorization_receipt,
    signed_protocol_settlement_receipt,
)

_X402_SAMPLE_RECEIPT = {
    "resourceUrl": "https://api.vendor.example/job/999",
    "payer": "0xabc123",
    "network": "eip155:84532",
    "issuedAt": 1710000000,
}


def test_partner_record_digest_sha256_hex_is_stable() -> None:
    first = partner_record_digest_sha256_hex({"b": 2, "a": 1})
    second = partner_record_digest_sha256_hex({"a": 1, "b": 2})
    assert first == second
    assert len(first) == 64


def test_resolve_external_attestations_accepts_prebuilt_entries() -> None:
    built = resolve_external_attestations(
        [
            {
                "source": AGENT_RECEIPT_EXTERNAL_SOURCE_X402,
                "kind": "delivery_receipt_v1",
                "digest_sha256_hex": "a" * 64,
                "reference_id": "https://api.example/resource",
            }
        ]
    )
    assert len(built) == 1
    assert built[0].get("reference_id") == "https://api.example/resource"


def test_resolve_external_attestations_accepts_prebuilt_ap2_entries() -> None:
    prebuilt: AgentReceiptExternalAttestationV1 = {
        "source": AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
        "kind": "agent_mandate_v1",
        "digest_sha256_hex": "b" * 64,
        "reference_id": "authz-prebuilt",
    }
    built = resolve_external_attestations([prebuilt])
    assert built == [prebuilt]


def test_x402_receipt_to_external_attestations_maps_when_pin_matches() -> None:
    attestations = x402_receipt_to_external_attestations(
        signed_jws_x402_receipt(_X402_SAMPLE_RECEIPT),
        expected_signer=X402_FIXTURE_EXPECTED_SIGNER,
    )
    assert len(attestations) == 1
    assert attestations[0]["source"] == AGENT_RECEIPT_EXTERNAL_SOURCE_X402
    assert attestations[0].get("reference_id") == _X402_SAMPLE_RECEIPT["resourceUrl"]


def test_x402_receipt_to_external_attestations_fails_closed_without_pin() -> None:
    with pytest.raises(ValueError, match="requires a non-empty expected_signer"):
        x402_receipt_to_external_attestations(
            signed_jws_x402_receipt(_X402_SAMPLE_RECEIPT), expected_signer=""
        )


def test_resolve_external_attestations_enforces_x402_pin() -> None:
    built = resolve_external_attestations(
        [
            {
                "kind": "x402",
                "receipt": signed_jws_x402_receipt(_X402_SAMPLE_RECEIPT),
                "expected_signer": X402_FIXTURE_EXPECTED_SIGNER,
            }
        ]
    )
    assert len(built) == 1
    assert built[0]["source"] == AGENT_RECEIPT_EXTERNAL_SOURCE_X402

    with pytest.raises(ValueError, match="does not match expected signer"):
        resolve_external_attestations(
            [
                {
                    "kind": "x402",
                    "receipt": signed_jws_x402_receipt(_X402_SAMPLE_RECEIPT),
                    "expected_signer": "not-the-real-signer",
                }
            ]
        )


def test_resolve_external_attestations_throws_when_sep2828_verification_fails() -> None:
    with pytest.raises(ValueError):
        resolve_external_attestations(
            [
                {
                    "kind": "sep2828",
                    "decision": {"note": "decision"},
                    "outcome": {"note": "outcome"},
                }
            ]
        )


def test_signed_mandate_to_external_attestations() -> None:
    signed = signed_ap2_mandate()
    attestations = signed_mandate_to_external_attestations(
        signed,
        {"external_authorization_id": "authz-123"},
    )

    assert len(attestations) == 1
    assert attestations[0] == {
        "source": AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
        "kind": "agent_mandate_v1",
        "digest_sha256_hex": signed["message_digest_sha256_hex"],
        "reference_id": "authz-123",
    }


def test_signed_mandate_falls_back_to_nonce() -> None:
    signed = signed_ap2_mandate()
    attestations = signed_mandate_to_external_attestations(signed)
    assert attestations[0].get("reference_id") == "nonce-123"


def test_resolve_external_attestations_ap2_mandate_kind() -> None:
    signed = signed_ap2_mandate()
    attestations = resolve_external_attestations(
        [
            {
                "kind": "ap2_mandate",
                "signed_mandate": signed,
                "transport_binding": {"external_authorization_id": "authz-123"},
            }
        ]
    )

    assert len(attestations) == 1
    assert attestations[0]["source"] == AGENT_RECEIPT_EXTERNAL_SOURCE_AP2
    assert attestations[0]["kind"] == "agent_mandate_v1"
    assert attestations[0]["digest_sha256_hex"] == signed["message_digest_sha256_hex"]
    assert attestations[0].get("reference_id") == "authz-123"


def test_mandate_digest_cross_check() -> None:
    signed = signed_ap2_mandate()
    normalized_digest = agent_mandate_digest_sha256_hex(normalize_agent_mandate_v1(signed))
    attestations = signed_mandate_to_external_attestations(signed)

    assert attestations[0]["digest_sha256_hex"] == signed["message_digest_sha256_hex"]
    assert attestations[0]["digest_sha256_hex"] == normalized_digest


def test_signed_mandate_throws_on_verify_failure() -> None:
    signed = signed_ap2_mandate()
    tampered = dict(signed)
    tampered["allowed_tools"] = ["travel.cancel"]

    with pytest.raises(ValueError):
        signed_mandate_to_external_attestations(tampered)
    with pytest.raises(ValueError):
        resolve_external_attestations([{"kind": "ap2_mandate", "signed_mandate": tampered}])


def test_protocol_authorization_receipt_to_external_attestations() -> None:
    receipt = signed_protocol_authorization_receipt()
    attestations = protocol_authorization_receipt_to_external_attestations(receipt)

    assert len(attestations) == 1
    assert attestations[0] == {
        "source": AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
        "kind": "protocol_authorization_receipt_v1",
        "digest_sha256_hex": receipt["message_digest_sha256_hex"],
        "reference_id": AP2_TEST_INTENT_ID,
    }


def test_resolve_external_attestations_ap2_authorization_receipt_kind() -> None:
    receipt = signed_protocol_authorization_receipt()
    attestations = resolve_external_attestations([{"kind": "ap2_authorization_receipt", "receipt": receipt}])

    assert len(attestations) == 1
    assert attestations[0]["source"] == AGENT_RECEIPT_EXTERNAL_SOURCE_AP2
    assert attestations[0]["kind"] == "protocol_authorization_receipt_v1"
    assert attestations[0]["digest_sha256_hex"] == receipt["message_digest_sha256_hex"]
    assert attestations[0].get("reference_id") == AP2_TEST_INTENT_ID


def test_authorization_receipt_throws_on_verify_failure() -> None:
    receipt = signed_protocol_authorization_receipt()
    tampered = dict(receipt)
    tampered["intent_id"] = "00000000-0000-4000-8000-000000000001"

    with pytest.raises(ValueError):
        protocol_authorization_receipt_to_external_attestations(tampered)
    with pytest.raises(ValueError):
        resolve_external_attestations([{"kind": "ap2_authorization_receipt", "receipt": tampered}])


def test_protocol_settlement_receipt_to_external_attestations() -> None:
    receipt = signed_protocol_settlement_receipt()
    attestations = protocol_settlement_receipt_to_external_attestations(receipt)

    assert len(attestations) == 1
    assert attestations[0] == {
        "source": AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
        "kind": "protocol_settlement_receipt_v1",
        "digest_sha256_hex": receipt["message_digest_sha256_hex"],
        "reference_id": AP2_TEST_INTENT_ID,
    }


def test_resolve_external_attestations_ap2_settlement_receipt_kind() -> None:
    receipt = signed_protocol_settlement_receipt()
    attestations = resolve_external_attestations([{"kind": "ap2_settlement_receipt", "receipt": receipt}])

    assert len(attestations) == 1
    assert attestations[0]["source"] == AGENT_RECEIPT_EXTERNAL_SOURCE_AP2
    assert attestations[0]["kind"] == "protocol_settlement_receipt_v1"
    assert attestations[0]["digest_sha256_hex"] == receipt["message_digest_sha256_hex"]
    assert attestations[0].get("reference_id") == AP2_TEST_INTENT_ID


def test_settlement_receipt_throws_on_verify_failure() -> None:
    receipt = signed_protocol_settlement_receipt()
    tampered = dict(receipt)
    tampered["harbor_state"] = "funded"

    with pytest.raises(ValueError):
        protocol_settlement_receipt_to_external_attestations(tampered)
    with pytest.raises(ValueError):
        resolve_external_attestations([{"kind": "ap2_settlement_receipt", "receipt": tampered}])
