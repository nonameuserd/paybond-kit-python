"""Owner disclosure HPKE package + optional TEE/ZK digest slots."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from paybond_kit.agent_receipt import verify_agent_receipt_v1
from paybond_kit.agent_receipt_owner_disclosure import (
    AGENT_RECEIPT_OWNER_DISCLOSURE_INFO,
    AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1,
    decrypt_owner_disclosure_package,
    derive_owner_disclosure_plaintext,
    encrypt_owner_disclosure_package,
    generate_x25519_keypair_hex,
    open_hpke_base_x25519_aes128_gcm,
    seal_hpke_base_x25519_aes128_gcm,
)

_CONFORMANCE = (
    Path(__file__).resolve().parents[2] / "agent-receipt" / "conformance"
)


def test_hpke_base_round_trip() -> None:
    priv, pub = generate_x25519_keypair_hex()
    info = AGENT_RECEIPT_OWNER_DISCLOSURE_INFO.encode()
    enc, ct = seal_hpke_base_x25519_aes128_gcm(
        bytes.fromhex(pub), info, b"aad", b"hello"
    )
    opened = open_hpke_base_x25519_aes128_gcm(
        bytes.fromhex(priv), enc, info, b"aad", ct
    )
    assert opened == b"hello"


def test_owner_disclosure_encrypt_decrypt_round_trip() -> None:
    receipt = json.loads(
        (_CONFORMANCE / "signed-action-receipt-v1.json").read_text(encoding="utf-8")
    )
    plaintext = derive_owner_disclosure_plaintext(
        receipt,
        derived_at=datetime(2026, 7, 12, 18, 0, 0, tzinfo=timezone.utc),
    )
    priv, pub = generate_x25519_keypair_hex()
    package = encrypt_owner_disclosure_package(plaintext, pub)
    assert package["kind"] == AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1
    opened = decrypt_owner_disclosure_package(package, priv)
    assert opened["receipt_id"] == plaintext["receipt_id"]


def test_optional_tee_zk_digest_slots() -> None:
    receipt = json.loads(
        (_CONFORMANCE / "signed-action-receipt-v1.json").read_text(encoding="utf-8")
    )
    tee = "ab" * 32
    zk = "cd" * 32
    receipt["execution"]["tee_attestation_digest_sha256_hex"] = tee
    receipt["authorization"]["zk_policy_proof_digest_sha256_hex"] = zk
    plaintext = derive_owner_disclosure_plaintext(receipt)
    assert plaintext["execution"]["tee_attestation_digest_sha256_hex"] == tee
    assert plaintext["authorization"]["zk_policy_proof_digest_sha256_hex"] == zk
    receipt["execution"]["tee_attestation_digest_sha256_hex"] = "nope"
    with pytest.raises(ValueError, match="tee_attestation_digest_sha256_hex"):
        verify_agent_receipt_v1(receipt)
