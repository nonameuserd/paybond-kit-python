"""Test helpers for signed completion evidence fixtures."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paybond_kit.agent_mandate import sign_agent_mandate_v1
from paybond_kit.json_digest import normalize_json
from paybond_kit.protocol_receipt import (
    PROTOCOL_RECEIPT_STATUS_AUTHORIZED,
    PROTOCOL_SOURCE_AP2,
    sign_protocol_authorization_receipt_v1,
    sign_protocol_settlement_receipt_v1,
)

SIGNATURE_KEYS = frozenset(
    {
        "signature",
        "ed25519_signature_hex",
        "message_digest_sha256_hex",
        "signing_public_key_ed25519_hex",
    }
)
ASSERTED_BLOCKS = ("issuerAsserted", "receiptAsserted")


def _strip_signature_fields(record: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in record.items():
        if key in SIGNATURE_KEYS:
            continue
        if key in ASSERTED_BLOCKS and isinstance(value, dict):
            stripped = {
                inner_key: inner_value
                for inner_key, inner_value in value.items()
                if inner_key not in SIGNATURE_KEYS
            }
            if stripped:
                out[key] = stripped
            continue
        out[key] = value
    return out


def _canonical_json_bytes(value: Any) -> bytes:
    normalized = normalize_json(value)
    return json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_sep2828_record(record: dict[str, Any], *, block: str) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    signed = dict(record)
    signed[block] = {
        "iss": "did:example:mcp-server",
        "signing_public_key_ed25519_hex": public_bytes.hex(),
    }
    digest = hashlib.sha256(_canonical_json_bytes(_strip_signature_fields(signed))).digest()
    signed[block]["ed25519_signature_hex"] = private_key.sign(digest).hex()
    return signed


def signed_sep2828_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    decision_body = {
        "backLink": {
            "attestationDigest": "sha256:deadbeef",
            "attestationNonce": "nonce-1",
        },
        "decisionDerived": {"decision": "allow"},
    }
    decision = sign_sep2828_record(decision_body, block="issuerAsserted")
    decision_digest = hashlib.sha256(_canonical_json_bytes(_strip_signature_fields(decision))).hexdigest()
    outcome_body = {
        "backLink": {
            "attestationDigest": "sha256:deadbeef",
            "attestationNonce": "nonce-1",
        },
        "outcomeDerived": {
            "status": "executed",
            "decisionDigest": f"sha256:{decision_digest}",
            "resultCommitment": "blake3:22222222",
        },
    }
    outcome = sign_sep2828_record(outcome_body, block="receiptAsserted")
    return decision, outcome


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def signed_jws_x402_receipt(payload: dict[str, Any]) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    header = {"alg": "EdDSA", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _base64url(public_bytes)}}
    header_b64 = _base64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _base64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature_b64 = _base64url(private_key.sign(signing_input))
    return {
        "extensions": {
            "offer-receipt": {
                "info": {
                    "receipt": {
                        "format": "jws",
                        "signature": f"{header_b64}.{payload_b64}.{signature_b64}",
                    }
                }
            }
        }
    }


AP2_MANDATE_SEED = hashlib.sha256(b"evidence-fixtures-ap2-mandate").digest()
AP2_AUTHORIZATION_RECEIPT_SEED = hashlib.sha256(b"evidence-fixtures-ap2-authorization-receipt").digest()
AP2_SETTLEMENT_RECEIPT_SEED = hashlib.sha256(b"evidence-fixtures-ap2-settlement-receipt").digest()

AP2_TEST_INTENT_ID = "550e8400-e29b-41d4-a716-446655440000"
AP2_TEST_AUTHORIZATION_RECEIPT_ID = "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7"


def _test_ap2_agent_mandate(expires_at: str) -> dict[str, Any]:
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


def _authorization_receipt_input(
    signed: dict[str, Any],
    transport: dict[str, Any],
) -> dict[str, Any]:
    return {
        "receipt_id": AP2_TEST_AUTHORIZATION_RECEIPT_ID,
        "issued_at": "2026-05-17T18:00:00.000Z",
        "status": PROTOCOL_RECEIPT_STATUS_AUTHORIZED,
        "intent_id": AP2_TEST_INTENT_ID,
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


def signed_ap2_mandate() -> dict[str, Any]:
    """Far-future signed AP2 agent mandate for external attestation tests."""
    return sign_agent_mandate_v1(AP2_MANDATE_SEED, _test_ap2_agent_mandate("2030-01-02T03:04:05Z"))


def signed_protocol_authorization_receipt() -> dict[str, Any]:
    """Signed AP2 protocol authorization receipt derived from signed_ap2_mandate."""
    signed_mandate = signed_ap2_mandate()
    return sign_protocol_authorization_receipt_v1(
        AP2_AUTHORIZATION_RECEIPT_SEED,
        _authorization_receipt_input(
            signed_mandate,
            {
                "source_protocol": PROTOCOL_SOURCE_AP2,
                "partner_platform": "Partner Travel Hub",
                "external_authorization_id": "authz-123",
                "request_id": "req-123",
            },
        ),
    )


def signed_protocol_settlement_receipt() -> dict[str, Any]:
    """Signed AP2 protocol settlement receipt for external attestation tests."""
    signed_mandate = signed_ap2_mandate()
    return sign_protocol_settlement_receipt_v1(
        AP2_SETTLEMENT_RECEIPT_SEED,
        {
            "receipt_id": AP2_TEST_INTENT_ID,
            "issued_at": "2026-05-17T18:05:00.000Z",
            "intent_id": AP2_TEST_INTENT_ID,
            "tenant_id": signed_mandate["authorization"]["tenant_id"],
            "verifier_id": "paybond-gateway",
            "transport_binding": {
                "source_protocol": PROTOCOL_SOURCE_AP2,
                "partner_platform": "Partner Travel Hub",
            },
            "authorization_receipt_id": AP2_TEST_AUTHORIZATION_RECEIPT_ID,
            "mandate_digest_sha256_hex": signed_mandate["message_digest_sha256_hex"],
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
