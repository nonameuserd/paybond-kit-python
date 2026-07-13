"""PEF wrapper for agent-receipt audit handoff (content-addressed frame_id)."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

PEF_CLAIM_TYPE_AGENT_RECEIPT_V1 = "paybond_agent_receipt_v1"
PEF_CANON_VERSION_JCS_RFC8785_V1 = "urn:x402:canonicalisation:jcs-rfc8785-v1"
PEF_VERSION_V1 = "1"
PEF_RECEIPT_FORMAT_AGENT_RECEIPT_V1 = "paybond.agent_receipt_v1"


def _canonicalize_json(value: Any) -> Any:
    if isinstance(value, list):
        return [_canonicalize_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonicalize_json(value[key]) for key in sorted(value)}
    return value


def jcs_canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785 JCS bytes for an arbitrary JSON value."""
    return json.dumps(
        _canonicalize_json(value),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_prefixed(hex_digest: str) -> str:
    return f"sha256:{hex_digest}"


def agent_receipt_pef_receipt_hash(receipt: Mapping[str, Any]) -> str:
    """Compute receipt_hash = sha256: + hex(SHA-256(JCS(receipt)))."""
    digest = hashlib.sha256(jcs_canonical_bytes(receipt)).hexdigest()
    return _sha256_prefixed(digest)


def agent_receipt_pef_preimage(
    *,
    receipt: Mapping[str, Any],
    frame_provider_did: str,
    frame_timestamp_ms: int,
    receipt_hash: str,
) -> dict[str, Any]:
    """Build the PEF preimage (excludes frame_id and signature)."""
    provider = frame_provider_did.strip()
    if not provider:
        raise ValueError("pef: frame_provider_did is required")
    if not isinstance(frame_timestamp_ms, int) or frame_timestamp_ms < 0:
        raise ValueError("pef: frame_timestamp_ms must be a non-negative integer")
    return {
        "canon_version": PEF_CANON_VERSION_JCS_RFC8785_V1,
        "claim_type": PEF_CLAIM_TYPE_AGENT_RECEIPT_V1,
        "frame_provider_did": provider,
        "frame_timestamp_ms": frame_timestamp_ms,
        "pef_version": PEF_VERSION_V1,
        "receipt": dict(receipt),
        "receipt_format": PEF_RECEIPT_FORMAT_AGENT_RECEIPT_V1,
        "receipt_hash": receipt_hash,
    }


def agent_receipt_pef_frame_id(preimage: Mapping[str, Any]) -> str:
    """Derive frame_id = sha256: + hex(SHA-256(JCS(preimage)))."""
    digest = hashlib.sha256(jcs_canonical_bytes(preimage)).hexdigest()
    return _sha256_prefixed(digest)


def build_agent_receipt_pef_frame(
    *,
    receipt: Mapping[str, Any],
    frame_provider_did: str,
    frame_timestamp_ms: int,
) -> dict[str, Any]:
    """
    Build a content-addressed PEF wrapper around an ARS receipt.

    Does not modify or re-sign the inner ARS envelope. RFC 9421 detached
    signatures are an optional extension point (omit ``signature`` for now).
    """
    receipt_hash = agent_receipt_pef_receipt_hash(receipt)
    preimage = agent_receipt_pef_preimage(
        receipt=receipt,
        frame_provider_did=frame_provider_did,
        frame_timestamp_ms=frame_timestamp_ms,
        receipt_hash=receipt_hash,
    )
    return {
        "canon_version": PEF_CANON_VERSION_JCS_RFC8785_V1,
        "claim_type": PEF_CLAIM_TYPE_AGENT_RECEIPT_V1,
        "frame_id": agent_receipt_pef_frame_id(preimage),
        "frame_provider_did": str(preimage["frame_provider_did"]),
        "frame_timestamp_ms": frame_timestamp_ms,
        "pef_version": PEF_VERSION_V1,
        "receipt": dict(receipt),
        "receipt_format": PEF_RECEIPT_FORMAT_AGENT_RECEIPT_V1,
        "receipt_hash": receipt_hash,
    }


def verify_agent_receipt_pef_frame_id(frame: Mapping[str, Any]) -> None:
    """Recompute frame_id / receipt_hash and fail closed on mismatch."""
    receipt = frame.get("receipt")
    if not isinstance(receipt, Mapping):
        raise ValueError("pef: receipt must be an object")
    expected_receipt_hash = agent_receipt_pef_receipt_hash(receipt)
    if frame.get("receipt_hash") != expected_receipt_hash:
        raise ValueError("pef: receipt_hash mismatch")
    frame_timestamp_ms = frame.get("frame_timestamp_ms")
    if not isinstance(frame_timestamp_ms, int) or frame_timestamp_ms < 0:
        raise ValueError("pef: frame_timestamp_ms must be a non-negative integer")
    preimage = agent_receipt_pef_preimage(
        receipt=receipt,
        frame_provider_did=str(frame.get("frame_provider_did") or ""),
        frame_timestamp_ms=frame_timestamp_ms,
        receipt_hash=expected_receipt_hash,
    )
    expected_frame_id = agent_receipt_pef_frame_id(preimage)
    if frame.get("frame_id") != expected_frame_id:
        raise ValueError("pef: frame_id mismatch")
    if frame.get("claim_type") != PEF_CLAIM_TYPE_AGENT_RECEIPT_V1:
        raise ValueError("pef: unexpected claim_type")
