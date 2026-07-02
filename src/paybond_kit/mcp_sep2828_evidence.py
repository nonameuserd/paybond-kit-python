"""Map SEP-2828-style MCP decision/outcome records into artifact_attested evidence."""

from __future__ import annotations

import re
from typing import Any, TypedDict

from paybond_kit.sep2828_signature import verify_sep2828_receipt_pair


class ArtifactAttestedEvidence(TypedDict):
    artifact_blake3_hex: list[str]
    operation: str
    vendor_ref_id: str


_DIGEST_PREFIX_RE = re.compile(r"^(sha256|blake3):", re.IGNORECASE)


def strip_digest_prefix(digest: str) -> str:
    return _DIGEST_PREFIX_RE.sub("", digest)


def _read_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _read_back_link(record: dict[str, Any]) -> dict[str, str] | None:
    back_link = _read_object(record.get("backLink"))
    if back_link is None:
        return None
    digest = back_link.get("attestationDigest")
    if not isinstance(digest, str) or not digest:
        return None
    nonce = back_link.get("attestationNonce")
    return {
        "attestationDigest": digest,
        **({"attestationNonce": nonce} if isinstance(nonce, str) else {}),
    }


def _push_digest(hashes: list[str], digest: Any) -> None:
    if not isinstance(digest, str) or not digest:
        return
    normalized = strip_digest_prefix(digest)
    if normalized not in hashes:
        hashes.append(normalized)


def map_sep2828_receipts_to_artifact_attested_evidence(
    decision: dict[str, Any],
    outcome: dict[str, Any],
) -> ArtifactAttestedEvidence:
    verify_sep2828_receipt_pair(decision, outcome)

    outcome_derived = _read_object(outcome.get("outcomeDerived"))
    status = str(outcome_derived.get("status", "")) if outcome_derived else ""
    operation = "attested" if status == "executed" else "pending"

    back_link = _read_back_link(outcome) or _read_back_link(decision)
    hashes: list[str] = []
    if outcome_derived:
        _push_digest(hashes, outcome_derived.get("decisionDigest"))
        _push_digest(hashes, outcome_derived.get("resultCommitment"))

    if not hashes and back_link:
        _push_digest(hashes, back_link["attestationDigest"])

    vendor_ref = back_link["attestationDigest"] if back_link else "mcp-unknown"
    return {
        "artifact_blake3_hex": hashes,
        "operation": operation,
        "vendor_ref_id": vendor_ref,
    }
