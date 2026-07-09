"""Tests for protocol authorization and settlement receipt verification."""

from __future__ import annotations

import hashlib

import pytest

from paybond_kit.agent_mandate import sign_agent_mandate_v1
from paybond_kit.protocol_receipt import (
    PROTOCOL_RECEIPT_STATUS_AUTHORIZED,
    PROTOCOL_SOURCE_AP2,
    sign_protocol_authorization_receipt_v1,
    sign_protocol_settlement_receipt_v1,
    verify_protocol_authorization_receipt_v1,
    verify_protocol_settlement_receipt_v1,
)


def _ed25519_seed(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _test_agent_mandate(expires_at: str) -> dict:
    return {
        "authorization": {
            "kind": " principal ",
            "tenant_id": " acme-pilot ",
            "principal_subject": " user-123 ",
            "principal_type": " User ",
        },
        "agent": {
            "subject": " did:paybond:travel-booker ",
            "issuer": " urn:orchestrator:example ",
            "key_id": " kid-1 ",
            "display_name": " Travel Booker ",
        },
        "allowed_actions": [" tool.use ", "intent.create"],
        "allowed_tools": [" Stripe/Capture ", "travel.book", "travel.book"],
        "spend_ceiling": {
            "amount_minor": 250000,
            "currency": " USD ",
        },
        "settlement": {
            "default_rail": " STRIPE_CONNECT ",
            "allowed_rails": ["x402_usdc_base", "stripe_connect", "stripe_connect"],
        },
        "constraint": {
            "kind": " policy ",
            "id": " travel_hold ",
            "version": " v3 ",
        },
        "expires_at": expires_at,
        "nonce": " nonce-123 ",
        "human_presence_mode": " HUMAN_PRESENT ",
    }


def _signed_test_agent_mandate(expires_at: str) -> dict:
    return sign_agent_mandate_v1(_ed25519_seed("protocol-signed-agent-mandate"), _test_agent_mandate(expires_at))


def _authorization_receipt_input(signed: dict, transport: dict) -> dict:
    return {
        "receipt_id": "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
        "issued_at": "2026-05-17T18:00:00.000Z",
        "status": PROTOCOL_RECEIPT_STATUS_AUTHORIZED,
        "intent_id": "550e8400-e29b-41d4-a716-446655440000",
        "tenant_id": signed["authorization"]["tenant_id"],
        "verifier_id": "paybond-gateway",
        "transport_binding": transport,
        "mandate_digest_sha256_hex": signed["message_digest_sha256_hex"],
        "imported_mandate_signing_public_key_ed25519_hex": signed["signing_public_key_ed25519_hex"],
        "authorization": signed["authorization"],
        "agent": signed["agent"],
        "allowed_actions": signed["allowed_actions"],
        "allowed_tools": signed["allowed_tools"],
        "spend_ceiling": signed["spend_ceiling"],
        "settlement": signed["settlement"],
        "constraint": signed["constraint"],
        "expires_at": signed["expires_at"],
        "nonce": signed["nonce"],
        "human_presence_mode": signed["human_presence_mode"],
    }


def test_authorization_receipt_sign_and_verify_round_trip() -> None:
    seed = _ed25519_seed("protocol-authorization-receipt")
    signed_mandate = _signed_test_agent_mandate("2026-05-18T00:00:00.000Z")
    receipt = sign_protocol_authorization_receipt_v1(
        seed,
        _authorization_receipt_input(
            signed_mandate,
            {
                "source_protocol": "AP2",
                "partner_platform": "Partner Travel Hub",
                "external_authorization_id": "authz-123",
                "request_id": "req-123",
            },
        ),
    )

    verified = verify_protocol_authorization_receipt_v1(receipt)

    assert verified["status"] == PROTOCOL_RECEIPT_STATUS_AUTHORIZED
    assert verified["transport_binding"]["source_protocol"] == PROTOCOL_SOURCE_AP2
    assert verified["intent_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert len(verified["message_digest_sha256_hex"]) == 64


def test_authorization_receipt_rejects_tampering_after_signing() -> None:
    seed = _ed25519_seed("protocol-authorization-receipt-tamper")
    signed_mandate = _signed_test_agent_mandate("2026-05-18T00:00:00.000Z")
    receipt = sign_protocol_authorization_receipt_v1(
        seed,
        _authorization_receipt_input(signed_mandate, {"source_protocol": PROTOCOL_SOURCE_AP2}),
    )

    tampered = dict(receipt)
    tampered["transport_binding"] = {
        **receipt["transport_binding"],
        "partner_platform": "other",
    }

    with pytest.raises(ValueError, match="message digest mismatch"):
        verify_protocol_authorization_receipt_v1(tampered)


def test_settlement_receipt_sign_and_verify_round_trip() -> None:
    seed = _ed25519_seed("protocol-settlement-receipt")
    receipt = sign_protocol_settlement_receipt_v1(
        seed,
        {
            "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
            "issued_at": "2026-05-17T18:05:00.000Z",
            "intent_id": "550e8400-e29b-41d4-a716-446655440000",
            "tenant_id": "acme-pilot",
            "verifier_id": "paybond-gateway",
            "transport_binding": {
                "source_protocol": PROTOCOL_SOURCE_AP2,
                "partner_platform": "Partner Travel Hub",
            },
            "authorization_receipt_id": "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
            "mandate_digest_sha256_hex": "ab" * 32,
            "harbor_state": "released",
            "predicate_passed": True,
            "settlement_rail": "stripe_connect",
            "settlement_mode": "managed",
            "principal_did": "did:principal:alice",
            "payee_did": "did:payee:hotel",
            "currency": "usd",
            "amount_cents": 250000,
            "terminal_observed_at": "2026-05-17T18:04:00.000Z",
        },
    )

    verified = verify_protocol_settlement_receipt_v1(receipt)

    assert verified["harbor_state"] == "released"
    assert verified["authorization_receipt_id"] == "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7"
    assert verified.get("predicate_passed") is True
    assert len(verified["message_digest_sha256_hex"]) == 64


def test_settlement_receipt_rejects_non_terminal_harbor_state() -> None:
    seed = _ed25519_seed("protocol-settlement-receipt-invalid")
    with pytest.raises(
        ValueError,
        match="harbor_state must be released, refunded, resolved_split, or escalated_external",
    ):
        sign_protocol_settlement_receipt_v1(
            seed,
            {
                "receipt_id": "550e8400-e29b-41d4-a716-446655440000",
                "issued_at": "2026-05-17T18:05:00.000Z",
                "intent_id": "550e8400-e29b-41d4-a716-446655440000",
                "tenant_id": "acme-pilot",
                "verifier_id": "paybond-gateway",
                "transport_binding": {"source_protocol": PROTOCOL_SOURCE_AP2},
                "authorization_receipt_id": "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
                "mandate_digest_sha256_hex": "ab" * 32,
                "harbor_state": "funded",
                "settlement_rail": "stripe_connect",
                "settlement_mode": "managed",
                "principal_did": "did:principal:alice",
                "payee_did": "did:payee:hotel",
                "currency": "usd",
                "amount_cents": 250000,
                "terminal_observed_at": "2026-05-17T18:04:00.000Z",
            },
        )
