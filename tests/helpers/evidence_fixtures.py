"""Test helpers for signed completion evidence fixtures."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paybond_kit.json_digest import normalize_json

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
