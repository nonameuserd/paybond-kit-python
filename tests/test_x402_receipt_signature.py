from __future__ import annotations

from typing import Any

from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

from paybond_kit.x402_receipt_signature import (
    SignedX402Receipt,
    _eip712_receipt_digest,
    _keccak256,
    verify_signed_x402_receipt,
)


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
