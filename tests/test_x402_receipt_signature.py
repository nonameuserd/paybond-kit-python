from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

from paybond_kit.x402_receipt_signature import (
    SignedX402Receipt,
    _eip712_receipt_digest,
    _keccak256,
    verify_signed_x402_receipt,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _signed_jws_receipt(payload: dict[str, Any]) -> tuple[SignedX402Receipt, str, str]:
    private_key = Ed25519PrivateKey.generate()
    raw_pub = private_key.public_key().public_bytes_raw()
    x_b64 = _b64url(raw_pub)
    header = {"alg": "EdDSA", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": x_b64}}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_b64 = _b64url(private_key.sign(signing_input))
    canonical = json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": x_b64}, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    thumbprint = _b64url(hashlib.sha256(canonical).digest())
    signed: SignedX402Receipt = {
        "format": "jws",
        "signature": f"{header_b64}.{payload_b64}.{sig_b64}",
    }
    return signed, x_b64, thumbprint


_JWS_PAYLOAD = {
    "version": 1,
    "network": "eip155:84532",
    "resourceUrl": "https://api.vendor.example/job/123",
    "payer": "0xabc123",
    "issuedAt": 1_710_000_000,
}


def test_jws_receipt_fails_closed_without_expected_signer() -> None:
    signed, _x, _tp = _signed_jws_receipt(_JWS_PAYLOAD)
    # A self-consistent JWS proves nothing about the issuer without a pin.
    with pytest.raises(ValueError, match="requires a non-empty expected_signer"):
        verify_signed_x402_receipt(signed, expected_signer="")


def test_jws_receipt_accepts_matching_expected_signer_by_x() -> None:
    signed, x_b64, _tp = _signed_jws_receipt(_JWS_PAYLOAD)
    assert verify_signed_x402_receipt(signed, expected_signer=x_b64) == _JWS_PAYLOAD


def test_jws_receipt_accepts_matching_expected_signer_by_thumbprint() -> None:
    signed, _x, thumbprint = _signed_jws_receipt(_JWS_PAYLOAD)
    assert verify_signed_x402_receipt(signed, expected_signer=thumbprint) == _JWS_PAYLOAD


def test_jws_receipt_rejects_mismatched_expected_signer() -> None:
    # Attacker forges a self-consistent receipt with their own embedded key.
    signed, _x, _tp = _signed_jws_receipt(_JWS_PAYLOAD)
    with pytest.raises(ValueError, match="does not match expected signer"):
        verify_signed_x402_receipt(signed, expected_signer="not-the-real-signer")


def _expected_signer_address(signing_key: SigningKey) -> str:
    verifying_key = signing_key.get_verifying_key()
    assert verifying_key is not None
    pub_bytes = verifying_key.to_string("uncompressed")
    address = _keccak256(pub_bytes[1:])[-20:]
    return "0x" + address.hex()


def _signed_eip712_receipt(payload: dict[str, Any], signing_key: SigningKey) -> SignedX402Receipt:
    digest = _eip712_receipt_digest(payload)
    sig_bytes = signing_key.sign_digest(digest, sigencode=sigencode_string)
    verifying_keys = VerifyingKey.from_public_key_recovery_with_digest(
        sig_bytes,
        digest,
        SECP256k1,
        sigdecode=sigdecode_string,
    )
    actual = signing_key.get_verifying_key()
    assert actual is not None
    recovery = next(
        index
        for index, verifying_key in enumerate(verifying_keys)
        if verifying_key.to_string() == actual.to_string()
    )
    signature = "0x" + (sig_bytes + bytes([recovery + 27])).hex()
    return {
        "format": "eip712",
        "payload": payload,
        "signature": signature,
    }


def test_eip712_receipt_recovers_signer() -> None:
    signing_key = SigningKey.generate(curve=SECP256k1)
    payload = {
        "version": 1,
        "network": "eip155:8453",
        "resourceUrl": "https://api.vendor.example/job/123",
        "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
        "issuedAt": 1_700_000_000,
        "transaction": "0xabc123",
    }
    signed = _signed_eip712_receipt(payload, signing_key)
    expected_signer = _expected_signer_address(signing_key)

    verified = verify_signed_x402_receipt(signed, expected_signer=expected_signer)

    assert verified == payload
