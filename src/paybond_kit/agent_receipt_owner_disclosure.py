"""Confidential HPKE owner disclosure package for Agent Receipt Standard.

Separate artifact from the public ``paybond.agent_receipt_v1`` body. Encrypt /
decrypt helpers are always available library exports; this is not part of the
signed public ARS body.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.hmac import HMAC

AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1 = "paybond.agent_receipt_owner_disclosure_v1"
AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1 = (
    "paybond.agent_receipt_owner_disclosure_plaintext_v1"
)
AGENT_RECEIPT_OWNER_DISCLOSURE_SCHEMA_VERSION = 1
AGENT_RECEIPT_OWNER_DISCLOSURE_HPKE_SUITE = (
    "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM"
)
AGENT_RECEIPT_OWNER_DISCLOSURE_INFO = "paybond.agent_receipt_owner_disclosure_v1"

_HPKE_KEM_ID = 0x0020
_HPKE_KDF_ID = 0x0001
_HPKE_AEAD_ID = 0x0001
_HPKE_MODE_BASE = 0x00
_HPKE_NH = 32
_HPKE_NK = 16
_HPKE_NN = 12
_HPKE_NSECRET = 32


def _i2osp(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def _suite_id_kem() -> bytes:
    return b"KEM" + _i2osp(_HPKE_KEM_ID, 2)


def _suite_id_hpke() -> bytes:
    return (
        b"HPKE"
        + _i2osp(_HPKE_KEM_ID, 2)
        + _i2osp(_HPKE_KDF_ID, 2)
        + _i2osp(_HPKE_AEAD_ID, 2)
    )


def _labeled_extract(suite_id: bytes, salt: bytes | None, label: bytes, ikm: bytes) -> bytes:
    labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
    if not salt:
        salt = bytes(_HPKE_NH)
    # HKDF-Extract(salt, IKM) via HMAC
    mac = HMAC(salt, SHA256())
    mac.update(labeled_ikm)
    return mac.finalize()


def _labeled_expand(
    suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    labeled_info = _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info
    return HKDFExpand(algorithm=SHA256(), length=length, info=labeled_info).derive(prk)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    suite_id = _suite_id_kem()
    eae_prk = _labeled_extract(suite_id, None, b"eae_prk", dh)
    return _labeled_expand(suite_id, eae_prk, b"shared_secret", kem_context, _HPKE_NSECRET)


def _encap(pk_r: X25519PublicKey) -> tuple[bytes, bytes]:
    sk_e = X25519PrivateKey.generate()
    dh = sk_e.exchange(pk_r)
    enc = sk_e.public_key().public_bytes_raw()
    kem_context = enc + pk_r.public_bytes_raw()
    return _extract_and_expand(dh, kem_context), enc


def _decap(sk_r: X25519PrivateKey, enc: bytes) -> bytes:
    if len(enc) != 32:
        raise ValueError("owner disclosure: encapsulated key must be 32 bytes")
    pk_e = X25519PublicKey.from_public_bytes(enc)
    dh = sk_r.exchange(pk_e)
    kem_context = enc + sk_r.public_key().public_bytes_raw()
    return _extract_and_expand(dh, kem_context)


def _key_schedule_base(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    suite_id = _suite_id_hpke()
    psk_id_hash = _labeled_extract(suite_id, None, b"psk_id_hash", b"")
    info_hash = _labeled_extract(suite_id, None, b"info_hash", info)
    key_schedule_context = bytes([_HPKE_MODE_BASE]) + psk_id_hash + info_hash
    secret = _labeled_extract(suite_id, shared_secret, b"secret", b"")
    key = _labeled_expand(suite_id, secret, b"key", key_schedule_context, _HPKE_NK)
    base_nonce = _labeled_expand(
        suite_id, secret, b"base_nonce", key_schedule_context, _HPKE_NN
    )
    return key, base_nonce


def _nonce(base_nonce: bytes, seq: int = 0) -> bytes:
    nonce = bytearray(base_nonce)
    for i in range(8):
        nonce[len(nonce) - 1 - i] ^= (seq >> (8 * i)) & 0xFF
    return bytes(nonce)


def seal_hpke_base_x25519_aes128_gcm(
    recipient_public_key: bytes, info: bytes, aad: bytes, plaintext: bytes
) -> tuple[bytes, bytes]:
    """Seal plaintext to a 32-byte X25519 public key. Returns (enc, ciphertext)."""
    if len(recipient_public_key) != 32:
        raise ValueError("owner disclosure: recipient public key must be 32 bytes")
    pk_r = X25519PublicKey.from_public_bytes(recipient_public_key)
    shared_secret, enc = _encap(pk_r)
    key, base_nonce = _key_schedule_base(shared_secret, info)
    ciphertext = AESGCM(key).encrypt(_nonce(base_nonce), plaintext, aad)
    return enc, ciphertext


def open_hpke_base_x25519_aes128_gcm(
    recipient_private_key: bytes,
    enc: bytes,
    info: bytes,
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    """Open HPKE ciphertext for a 32-byte X25519 private key."""
    if len(recipient_private_key) != 32:
        raise ValueError("owner disclosure: recipient private key must be 32 bytes")
    sk_r = X25519PrivateKey.from_private_bytes(recipient_private_key)
    shared_secret = _decap(sk_r, enc)
    key, base_nonce = _key_schedule_base(shared_secret, info)
    return AESGCM(key).decrypt(_nonce(base_nonce), ciphertext, aad)


def generate_x25519_keypair_hex() -> tuple[str, str]:
    """Return ``(private_key_hex, public_key_hex)`` lowercase."""
    sk = X25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


def _aad(receipt_id: str, message_digest: str) -> bytes:
    material = f"{receipt_id.strip()}\x00{message_digest.strip().lower()}".encode("utf-8")
    return hashlib.sha256(material).digest()


def derive_owner_disclosure_plaintext(
    receipt: Mapping[str, Any],
    *,
    derived_at: datetime | None = None,
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive a hash-only disclosure plaintext from a public ARS receipt."""
    from paybond_kit.agent_receipt import _normalize_receipt

    normalized = _normalize_receipt(dict(receipt))
    when = derived_at or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    out: dict[str, Any] = {
        "kind": AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1,
        "schema_version": AGENT_RECEIPT_OWNER_DISCLOSURE_SCHEMA_VERSION,
        "receipt_id": normalized["receipt_id"],
        "message_digest_sha256_hex": str(normalized["message_digest_sha256_hex"]).lower(),
        "tenant_id": normalized["tenant_id"],
        "scope": normalized["scope"],
        "derived_at": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "authorization": normalized["authorization"],
        "outcome": normalized["outcome"],
        "references": normalized["references"],
    }
    if normalized.get("execution"):
        out["execution"] = normalized["execution"]
    if normalized.get("evidence"):
        out["evidence"] = normalized["evidence"]
    if extensions:
        out["extensions"] = dict(extensions)
    return out


def encrypt_owner_disclosure_package(
    plaintext: Mapping[str, Any],
    recipient_public_key_x25519_hex: str,
) -> dict[str, Any]:
    """HPKE-encrypt a derived disclosure plaintext to an owner X25519 public key."""
    if plaintext.get("kind") != AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1:
        raise ValueError(
            "owner disclosure: plaintext kind must be "
            f"{AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1}"
        )
    pub_hex = recipient_public_key_x25519_hex.strip().lower()
    if len(pub_hex) != 64:
        raise ValueError("owner disclosure: recipient_public_key_x25519_hex must be 32-byte hex")
    pub = bytes.fromhex(pub_hex)
    body = json.dumps(plaintext, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    # Stable JSON: use canonical key order via json.dumps default insertion order from dict
    aad = _aad(str(plaintext["receipt_id"]), str(plaintext["message_digest_sha256_hex"]))
    enc, ciphertext = seal_hpke_base_x25519_aes128_gcm(
        pub,
        AGENT_RECEIPT_OWNER_DISCLOSURE_INFO.encode("utf-8"),
        aad,
        body,
    )
    return {
        "kind": AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1,
        "schema_version": AGENT_RECEIPT_OWNER_DISCLOSURE_SCHEMA_VERSION,
        "hpke_suite": AGENT_RECEIPT_OWNER_DISCLOSURE_HPKE_SUITE,
        "info": AGENT_RECEIPT_OWNER_DISCLOSURE_INFO,
        "recipient_public_key_x25519_hex": pub_hex,
        "encapsulated_key_hex": enc.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "aad_sha256_hex": aad.hex(),
        "receipt_id": plaintext["receipt_id"],
        "message_digest_sha256_hex": str(plaintext["message_digest_sha256_hex"]).lower(),
        "plaintext_content_type": (
            "application/json; charset=utf-8; profile="
            + AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1
        ),
    }


def decrypt_owner_disclosure_package(
    package: Mapping[str, Any],
    recipient_private_key_x25519_hex: str,
) -> dict[str, Any]:
    """Decrypt an HPKE owner disclosure package."""
    if package.get("kind") != AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1:
        raise ValueError(
            f"owner disclosure: kind must be {AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1}"
        )
    if package.get("hpke_suite") != AGENT_RECEIPT_OWNER_DISCLOSURE_HPKE_SUITE:
        raise ValueError(f"owner disclosure: unsupported hpke_suite {package.get('hpke_suite')!r}")
    if package.get("info") != AGENT_RECEIPT_OWNER_DISCLOSURE_INFO:
        raise ValueError("owner disclosure: info mismatch")
    priv_hex = recipient_private_key_x25519_hex.strip().lower()
    priv = bytes.fromhex(priv_hex)
    if len(priv) != 32:
        raise ValueError("owner disclosure: recipient private key must be 32-byte hex")
    enc = bytes.fromhex(str(package["encapsulated_key_hex"]).strip().lower())
    ciphertext = bytes.fromhex(str(package["ciphertext_hex"]).strip().lower())
    aad = _aad(str(package["receipt_id"]), str(package["message_digest_sha256_hex"]))
    if aad.hex() != str(package["aad_sha256_hex"]).strip().lower():
        raise ValueError("owner disclosure: aad_sha256_hex mismatch")
    plaintext_bytes = open_hpke_base_x25519_aes128_gcm(
        priv,
        enc,
        AGENT_RECEIPT_OWNER_DISCLOSURE_INFO.encode("utf-8"),
        aad,
        ciphertext,
    )
    plaintext = json.loads(plaintext_bytes.decode("utf-8"))
    if plaintext.get("kind") != AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1:
        raise ValueError("owner disclosure: decrypted kind mismatch")
    if plaintext.get("receipt_id") != package.get("receipt_id"):
        raise ValueError("owner disclosure: decrypted receipt binding mismatch")
    return plaintext
