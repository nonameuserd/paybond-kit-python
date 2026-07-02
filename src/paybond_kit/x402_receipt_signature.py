"""x402 Signed Offer & Receipt extension signature verification."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, TypedDict

from Crypto.Hash import keccak
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers, SECP256R1
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_string


class SignedX402Receipt(TypedDict, total=False):
    format: str
    payload: dict[str, Any]
    signature: str


def _read_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _read_string(record: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _base64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _encode_type(type_name: str, fields: list[tuple[str, str]]) -> str:
    return f"{type_name}({','.join(f'{field_type} {field_name}' for field_name, field_type in fields)})"


def _keccak256(data: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def _encode_value(field_type: str, value: Any) -> bytes:
    if field_type == "string":
        return _keccak256(str(value if value is not None else "").encode("utf-8"))
    if field_type == "uint256":
        bigint = int(value)
        return bigint.to_bytes(32, byteorder="big")
    raise ValueError(f"unsupported EIP-712 type {field_type}")


def _hash_struct(type_name: str, fields: list[tuple[str, str]], data: dict[str, Any]) -> bytes:
    encoded = [_keccak256(_encode_type(type_name, fields).encode("utf-8"))]
    encoded.extend(_encode_value(field_type, data.get(field_name)) for field_name, field_type in fields)
    return _keccak256(b"".join(encoded))


_RECEIPT_FIELDS = [
    ("version", "uint256"),
    ("network", "string"),
    ("resourceUrl", "string"),
    ("payer", "string"),
    ("issuedAt", "uint256"),
    ("transaction", "string"),
]


def _normalize_receipt_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    transaction = normalized.get("transaction")
    normalized["transaction"] = transaction if isinstance(transaction, str) else ""
    return normalized


def _eip712_receipt_digest(payload: dict[str, Any]) -> bytes:
    domain_fields = [("name", "string"), ("version", "string"), ("chainId", "uint256")]
    domain = {"name": "x402 receipt", "version": "1", "chainId": 1}
    normalized = _normalize_receipt_payload(payload)
    domain_separator = _hash_struct("EIP712Domain", domain_fields, domain)
    struct_hash = _hash_struct("Receipt", _RECEIPT_FIELDS, normalized)
    return _keccak256(b"\x19\x01" + domain_separator + struct_hash)


def _recover_eip712_signer(digest: bytes, signature: str) -> str:
    trimmed = signature.strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{130}", trimmed):
        raise ValueError("x402 EIP-712 signature must be 0x-prefixed 65-byte hex")
    raw = bytes.fromhex(trimmed[2:])
    if len(raw) != 65:
        raise ValueError("x402 EIP-712 signature must decode to 65 bytes")
    recovery = raw[64]
    if recovery >= 27:
        recovery -= 27
    if recovery not in (0, 1):
        raise ValueError("x402 EIP-712 signature recovery id must be 0 or 1")
    sig_bytes = raw[:64]
    try:
        verifying_keys = VerifyingKey.from_public_key_recovery_with_digest(
            sig_bytes,
            digest,
            SECP256k1,
            sigdecode=sigdecode_string,
        )
    except Exception as exc:
        raise ValueError("x402 EIP-712 signature verification failed") from exc
    for candidate in (recovery, recovery ^ 1):
        if candidate >= len(verifying_keys):
            continue
        verifying_key = verifying_keys[candidate]
        pub_bytes = verifying_key.to_string("uncompressed")
        address = _keccak256(pub_bytes[1:])[-20:]
        return "0x" + address.hex()
    raise ValueError("x402 EIP-712 signature verification failed")


def _verify_jws_compact_signature(signature: str) -> dict[str, Any]:
    parts = signature.split(".")
    if len(parts) != 3:
        raise ValueError("x402 JWS signature must use compact serialization")
    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(_base64url_decode(header_b64).decode("utf-8"))
    payload = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature_bytes = _base64url_decode(sig_b64)
    alg = header.get("alg")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise ValueError("x402 JWS verification requires embedded jwk")

    if alg in ("EdDSA", "Ed25519"):
        x = jwk.get("x")
        if not isinstance(x, str):
            raise ValueError("x402 JWS Ed25519 verification requires embedded jwk.x")
        public_key = Ed25519PublicKey.from_public_bytes(_base64url_decode(x))
        try:
            public_key.verify(signature_bytes, signing_input)
        except InvalidSignature as exc:
            raise ValueError("x402 JWS Ed25519 signature verification failed") from exc
        return payload

    if alg == "ES256":
        x = jwk.get("x")
        y = jwk.get("y")
        if not isinstance(x, str) or not isinstance(y, str):
            raise ValueError("x402 JWS ES256 verification requires embedded jwk x/y")
        public_numbers = EllipticCurvePublicNumbers(
            int.from_bytes(_base64url_decode(x), "big"),
            int.from_bytes(_base64url_decode(y), "big"),
            SECP256R1(),
        )
        public_key = public_numbers.public_key()
        try:
            public_key.verify(signature_bytes, signing_input, ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise ValueError("x402 JWS ES256 signature verification failed") from exc
        return payload

    raise ValueError(f"unsupported x402 JWS alg {alg}")


def extract_signed_x402_receipt(input_record: dict[str, Any]) -> SignedX402Receipt:
    extensions = _read_object(input_record.get("extensions"))
    if extensions is not None:
        offer_receipt = _read_object(extensions.get("offer-receipt")) or _read_object(
            extensions.get("offerReceipt")
        )
        info = _read_object(offer_receipt.get("info")) if offer_receipt else None
        receipt = _read_object(info.get("receipt")) if info else None
        if receipt and isinstance(receipt.get("format"), str) and isinstance(receipt.get("signature"), str):
            return {
                "format": "jws" if receipt["format"] == "jws" else "eip712",
                "payload": _read_object(receipt.get("payload")) or {},
                "signature": receipt["signature"],
            }
        if offer_receipt is not None:
            nested = _read_object(offer_receipt.get("receipt")) or offer_receipt
            if nested and isinstance(nested.get("format"), str) and isinstance(nested.get("signature"), str):
                return {
                    "format": "jws" if nested["format"] == "jws" else "eip712",
                    "payload": _read_object(nested.get("payload")) or {},
                    "signature": nested["signature"],
                }

    receipt = _read_object(input_record.get("receipt"))
    if receipt and isinstance(receipt.get("format"), str) and isinstance(receipt.get("signature"), str):
        return {
            "format": "jws" if receipt["format"] == "jws" else "eip712",
            "payload": _read_object(receipt.get("payload")) or {},
            "signature": receipt["signature"],
        }

    if isinstance(input_record.get("format"), str) and isinstance(input_record.get("signature"), str):
        return {
            "format": "jws" if input_record["format"] == "jws" else "eip712",
            "payload": _read_object(input_record.get("payload")) or {},
            "signature": str(input_record["signature"]),
        }

    raise ValueError(
        "x402 receipt input missing signed offer-receipt artifact (format and signature required)"
    )


def verify_signed_x402_receipt(
    signed: SignedX402Receipt,
    *,
    expected_signer: str | None = None,
) -> dict[str, Any]:
    receipt_format = signed.get("format")
    signature = signed.get("signature")
    if not isinstance(signature, str) or not signature:
        raise ValueError("x402 signed receipt missing signature")

    if receipt_format == "jws":
        return _verify_jws_compact_signature(signature)

    payload = signed.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("x402 EIP-712 receipt requires payload alongside signature")

    digest = _eip712_receipt_digest(payload)
    recovered = _recover_eip712_signer(digest, signature)
    if expected_signer and recovered.lower() != expected_signer.strip().lower():
        raise ValueError("x402 EIP-712 recovered signer does not match expected signer")
    return payload
