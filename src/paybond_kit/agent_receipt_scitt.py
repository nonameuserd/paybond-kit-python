"""SCITT COSE_Sign1 export adapter for verified ARS digests."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

AGENT_RECEIPT_SCITT_EXPORT_KIND_V1 = "paybond.agent_receipt_scitt_export_v1"
AGENT_RECEIPT_SCITT_STATEMENT_KIND_V1 = "paybond.agent_receipt_scitt_statement_v1"
COSE_ALG_EDDSA = -8

_COSE_HEADER_ALG = 1
_COSE_HEADER_KID = 4
_COSE_HEADER_CWT_CLAIMS = 15
_CWT_CLAIM_ISS = 1
_CWT_CLAIM_SUB = 2
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _canonicalize_json(value: Any) -> Any:
    if isinstance(value, list):
        return [_canonicalize_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonicalize_json(value[key]) for key in sorted(value)}
    return value


def _jcs_bytes(value: Any) -> bytes:
    return json.dumps(
        _canonicalize_json(value),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _require_hex64(value: object, field: str) -> str:
    normalized = str(value).strip().lower()
    if not _HEX64.match(normalized):
        raise ValueError(f"scitt export: {field} must be a lowercase 64-char hex digest")
    return normalized


def _encode_cbor_uint(value: int) -> bytes:
    if value < 0 or not isinstance(value, int):
        raise ValueError("scitt export: CBOR uint must be a non-negative integer")
    if value < 24:
        return bytes([value])
    if value < 0x100:
        return bytes([24, value])
    if value < 0x10000:
        return bytes([25, (value >> 8) & 0xFF, value & 0xFF])
    if value < 0x100000000:
        return bytes(
            [
                26,
                (value >> 24) & 0xFF,
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            ]
        )
    raise ValueError("scitt export: CBOR uint too large")


def _encode_cbor_nint(value: int) -> bytes:
    n = -1 - value
    if n < 24:
        return bytes([0x20 | n])
    if n < 0x100:
        return bytes([0x38, n])
    if n < 0x10000:
        return bytes([0x39, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError("scitt export: CBOR nint too large")


def _encode_cbor_int(value: int) -> bytes:
    return _encode_cbor_uint(value) if value >= 0 else _encode_cbor_nint(value)


def _encode_cbor_bstr(data: bytes) -> bytes:
    length = len(data)
    if length < 24:
        header = bytes([0x40 | length])
    elif length < 0x100:
        header = bytes([0x58, length])
    elif length < 0x10000:
        header = bytes([0x59, (length >> 8) & 0xFF, length & 0xFF])
    else:
        raise ValueError("scitt export: CBOR bstr too large")
    return header + data


def _encode_cbor_tstr(value: str) -> bytes:
    data = value.encode("utf-8")
    length = len(data)
    if length < 24:
        header = bytes([0x60 | length])
    elif length < 0x100:
        header = bytes([0x78, length])
    elif length < 0x10000:
        header = bytes([0x79, (length >> 8) & 0xFF, length & 0xFF])
    else:
        raise ValueError("scitt export: CBOR tstr too large")
    return header + data


def _encode_cbor_array(items: list[bytes]) -> bytes:
    length = len(items)
    header = bytes([0x80 | length]) if length < 24 else bytes([0x98, length])
    return header + b"".join(items)


def _encode_cbor_map(entries: list[tuple[int | str, bytes]]) -> bytes:
    encoded: list[tuple[bytes, bytes]] = []
    for key, value in entries:
        key_bytes = _encode_cbor_int(key) if isinstance(key, int) else _encode_cbor_tstr(key)
        encoded.append((key_bytes, value))
    encoded.sort(key=lambda item: item[0])
    length = len(encoded)
    header = bytes([0xA0 | length]) if length < 24 else bytes([0xB8, length])
    body = b"".join(key + value for key, value in encoded)
    return header + body


def _encode_cbor_tag(tag: int, item: bytes) -> bytes:
    if tag < 24:
        header = bytes([0xC0 | tag])
    elif tag < 0x100:
        header = bytes([0xD8, tag])
    else:
        raise ValueError("scitt export: CBOR tag too large")
    return header + item


def _build_protected_header(issuer: str, subject: str, kid: str | None) -> bytes:
    cwt_claims = _encode_cbor_map(
        [
            (_CWT_CLAIM_ISS, _encode_cbor_tstr(issuer)),
            (_CWT_CLAIM_SUB, _encode_cbor_tstr(subject)),
        ]
    )
    entries: list[tuple[int | str, bytes]] = [
        (_COSE_HEADER_ALG, _encode_cbor_int(COSE_ALG_EDDSA)),
        (_COSE_HEADER_CWT_CLAIMS, cwt_claims),
    ]
    if kid and kid.strip():
        entries.append((_COSE_HEADER_KID, _encode_cbor_tstr(kid.strip())))
    return _encode_cbor_map(entries)


def build_agent_receipt_scitt_export(
    *,
    receipt_id: str,
    message_digest_sha256_hex: str,
    signing_private_key_seed_hex: str,
    issuer: str,
    kid: str | None = None,
) -> dict[str, Any]:
    """
    Build a SCITT-oriented COSE_Sign1 export for a verified ARS message digest.

    Payload is JCS(statement); signature is EdDSA COSE_Sign1 (tag 18).
    """
    trimmed_id = receipt_id.strip()
    if not trimmed_id:
        raise ValueError("scitt export: receipt_id is required")
    trimmed_issuer = issuer.strip()
    if not trimmed_issuer:
        raise ValueError("scitt export: issuer is required")
    digest = _require_hex64(message_digest_sha256_hex, "message_digest_sha256_hex")
    seed = bytes.fromhex(_require_hex64(signing_private_key_seed_hex, "signing_private_key_seed_hex"))
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key_hex = private_key.public_key().public_bytes_raw().hex()

    statement = {
        "kind": AGENT_RECEIPT_SCITT_STATEMENT_KIND_V1,
        "receipt_id": trimmed_id,
        "message_digest_sha256_hex": digest,
    }
    payload = _jcs_bytes(statement)
    protected_header = _build_protected_header(trimmed_issuer, trimmed_id, kid)
    sig_structure = _encode_cbor_array(
        [
            _encode_cbor_tstr("Signature1"),
            _encode_cbor_bstr(protected_header),
            _encode_cbor_bstr(b""),
            _encode_cbor_bstr(payload),
        ]
    )
    signature = private_key.sign(sig_structure)
    cose_sign1 = _encode_cbor_array(
        [
            _encode_cbor_bstr(protected_header),
            _encode_cbor_map([]),
            _encode_cbor_bstr(payload),
            _encode_cbor_bstr(signature),
        ]
    )
    tagged = _encode_cbor_tag(18, cose_sign1)
    export_doc: dict[str, Any] = {
        "kind": AGENT_RECEIPT_SCITT_EXPORT_KIND_V1,
        "receipt_id": trimmed_id,
        "message_digest_sha256_hex": digest,
        "signing_public_key_ed25519_hex": public_key_hex,
        "issuer": trimmed_issuer,
        "cose_sign1_tag18_hex": tagged.hex(),
        "statement": statement,
    }
    if kid and kid.strip():
        export_doc["kid"] = kid.strip()
    return export_doc


def _read_cbor_length(data: bytes, offset: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, offset
    if additional == 24:
        return data[offset], offset + 1
    if additional == 25:
        return (data[offset] << 8) | data[offset + 1], offset + 2
    raise ValueError("scitt export: unsupported CBOR length")


def _decode_cbor_item(data: bytes, offset: int) -> tuple[Any, int]:
    initial = data[offset]
    major = initial >> 5
    additional = initial & 0x1F
    cursor = offset + 1
    if major == 0:
        length, next_offset = _read_cbor_length(data, cursor, additional)
        return length, next_offset
    if major == 1:
        length, next_offset = _read_cbor_length(data, cursor, additional)
        return -1 - length, next_offset
    if major in {2, 3}:
        length, next_offset = _read_cbor_length(data, cursor, additional)
        end = next_offset + length
        slice_bytes = data[next_offset:end]
        if major == 2:
            return slice_bytes, end
        return slice_bytes.decode("utf-8"), end
    if major == 4:
        length, next_offset = _read_cbor_length(data, cursor, additional)
        cursor = next_offset
        items: list[Any] = []
        for _ in range(length):
            item, cursor = _decode_cbor_item(data, cursor)
            items.append(item)
        return items, cursor
    if major == 5:
        length, next_offset = _read_cbor_length(data, cursor, additional)
        cursor = next_offset
        mapping: dict[Any, Any] = {}
        for _ in range(length):
            key, cursor = _decode_cbor_item(data, cursor)
            value, cursor = _decode_cbor_item(data, cursor)
            mapping[key] = value
        return mapping, cursor
    if major == 6:
        tag, next_offset = _read_cbor_length(data, cursor, additional)
        value, end = _decode_cbor_item(data, next_offset)
        return {"tag": tag, "value": value}, end
    raise ValueError(f"scitt export: unsupported CBOR major type {major}")


def verify_agent_receipt_scitt_export(export_doc: Mapping[str, Any]) -> None:
    """Verify COSE_Sign1 EdDSA over the statement payload."""
    if export_doc.get("kind") != AGENT_RECEIPT_SCITT_EXPORT_KIND_V1:
        raise ValueError("scitt export: unexpected kind")
    digest = _require_hex64(
        export_doc.get("message_digest_sha256_hex"), "message_digest_sha256_hex"
    )
    statement = export_doc.get("statement")
    if not isinstance(statement, Mapping):
        raise ValueError("scitt export: statement must be an object")
    if statement.get("message_digest_sha256_hex") != digest:
        raise ValueError("scitt export: statement digest mismatch")
    if statement.get("receipt_id") != export_doc.get("receipt_id"):
        raise ValueError("scitt export: statement receipt_id mismatch")

    expected_payload = _jcs_bytes(statement)
    tagged_hex = str(export_doc.get("cose_sign1_tag18_hex") or "").strip().lower()
    tagged, _ = _decode_cbor_item(bytes.fromhex(tagged_hex), 0)
    if not isinstance(tagged, dict) or tagged.get("tag") != 18:
        raise ValueError("scitt export: expected CBOR tag 18 COSE_Sign1 array")
    cose = tagged.get("value")
    if not isinstance(cose, list) or len(cose) != 4:
        raise ValueError("scitt export: COSE_Sign1 must be a 4-element array")
    protected_raw, _unprotected, payload, signature = cose
    if not isinstance(protected_raw, (bytes, bytearray)):
        raise ValueError("scitt export: protected header must be bstr")
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("scitt export: payload must be bstr")
    if not isinstance(signature, (bytes, bytearray)):
        raise ValueError("scitt export: signature must be bstr")
    if bytes(payload) != expected_payload:
        raise ValueError("scitt export: COSE payload mismatch")

    sig_structure = _encode_cbor_array(
        [
            _encode_cbor_tstr("Signature1"),
            _encode_cbor_bstr(bytes(protected_raw)),
            _encode_cbor_bstr(b""),
            _encode_cbor_bstr(bytes(payload)),
        ]
    )
    pub_hex = _require_hex64(
        export_doc.get("signing_public_key_ed25519_hex"),
        "signing_public_key_ed25519_hex",
    )
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    try:
        public_key.verify(bytes(signature), sig_structure)
    except InvalidSignature as exc:
        raise ValueError("scitt export: COSE_Sign1 signature invalid") from exc
