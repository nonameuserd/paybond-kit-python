"""Verify SEP-2828 MCP decision/outcome record signatures before evidence mapping."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from paybond_kit.json_digest import normalize_json

_SIGNATURE_KEYS = frozenset(
    {
        "signature",
        "ed25519_signature_hex",
        "message_digest_sha256_hex",
        "signing_public_key_ed25519_hex",
    }
)
_ASSERTED_BLOCKS = ("issuerAsserted", "receiptAsserted")
_DIGEST_PREFIX_RE = re.compile(r"^(sha256|blake3):", re.IGNORECASE)


def _read_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _strip_digest_prefix(digest: str) -> str:
    return _DIGEST_PREFIX_RE.sub("", digest)


def _canonical_json_bytes(value: Any) -> bytes:
    normalized = normalize_json(value)
    text = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strip_signature_fields(record: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in record.items():
        if key in _SIGNATURE_KEYS:
            continue
        if key in _ASSERTED_BLOCKS:
            asserted = _read_object(value)
            if asserted is None:
                continue
            stripped = {
                inner_key: inner_value
                for inner_key, inner_value in asserted.items()
                if inner_key not in _SIGNATURE_KEYS
            }
            if stripped:
                out[key] = stripped
            continue
        out[key] = value
    return out


def _extract_signature_material(record: dict[str, Any]) -> tuple[str, str]:
    for block_name in _ASSERTED_BLOCKS:
        block = _read_object(record.get(block_name))
        if block is None:
            continue
        signature = block.get("ed25519_signature_hex") or block.get("signature")
        public_key = block.get("signing_public_key_ed25519_hex")
        if isinstance(signature, str) and signature and isinstance(public_key, str) and public_key:
            return signature.strip(), public_key.strip()

    signature = record.get("ed25519_signature_hex") or record.get("signature")
    public_key = record.get("signing_public_key_ed25519_hex")
    if isinstance(signature, str) and signature and isinstance(public_key, str) and public_key:
        return signature.strip(), public_key.strip()

    raise ValueError("SEP-2828 record missing ed25519 signature and signing_public_key_ed25519_hex")


def _verify_ed25519_sha256_hex(*, digest_hex: str, signature_hex: str, public_key_hex: str) -> None:
    try:
        from paybond_kit._native import verify_ed25519_sha256_hex as native_verify

        if native_verify(digest_hex, signature_hex, public_key_hex):
            return
    except ImportError:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        try:
            public_key.verify(bytes.fromhex(signature_hex), bytes.fromhex(digest_hex))
            return
        except InvalidSignature as exc:
            raise ValueError("SEP-2828 record signature verification failed") from exc

    raise ValueError("SEP-2828 record signature verification failed")


def verify_sep2828_record_signature(record: dict[str, Any], *, label: str) -> None:
    signature_hex, public_key_hex = _extract_signature_material(record)
    digest_hex = _sha256_hex(_canonical_json_bytes(_strip_signature_fields(record)))
    _verify_ed25519_sha256_hex(
        digest_hex=digest_hex,
        signature_hex=signature_hex,
        public_key_hex=public_key_hex,
    )


def _record_content_digest_hex(record: dict[str, Any]) -> str:
    return _sha256_hex(_canonical_json_bytes(_strip_signature_fields(record)))


def verify_sep2828_receipt_pair(decision: dict[str, Any], outcome: dict[str, Any]) -> None:
    verify_sep2828_record_signature(decision, label="decision")
    verify_sep2828_record_signature(outcome, label="outcome")

    decision_back_link = _read_object(decision.get("backLink"))
    outcome_back_link = _read_object(outcome.get("backLink"))
    if decision_back_link is None or outcome_back_link is None:
        raise ValueError("SEP-2828 decision and outcome records must both include backLink")

    decision_digest = decision_back_link.get("attestationDigest")
    outcome_digest = outcome_back_link.get("attestationDigest")
    if not isinstance(decision_digest, str) or not decision_digest:
        raise ValueError("SEP-2828 decision backLink.attestationDigest is required")
    if decision_digest != outcome_digest:
        raise ValueError("SEP-2828 decision and outcome backLink.attestationDigest must match")

    outcome_derived = _read_object(outcome.get("outcomeDerived"))
    if outcome_derived is None:
        raise ValueError("SEP-2828 outcome record must include outcomeDerived")

    expected_decision_digest = _strip_digest_prefix(_record_content_digest_hex(decision))
    decision_digest_field = outcome_derived.get("decisionDigest")
    if not isinstance(decision_digest_field, str) or not decision_digest_field:
        raise ValueError("SEP-2828 outcomeDerived.decisionDigest is required for pairing")
    actual_decision_digest = _strip_digest_prefix(decision_digest_field)
    if actual_decision_digest != expected_decision_digest:
        raise ValueError("SEP-2828 outcomeDerived.decisionDigest does not match signed decision record")
