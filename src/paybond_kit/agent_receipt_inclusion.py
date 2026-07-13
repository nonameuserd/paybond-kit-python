"""Tenant-scoped agent-receipt Merkle inclusion proof verify (ARS Phase 4)."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from paybond_kit.agent_receipt import AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519

AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1 = "paybond.agent_receipt_transparency_sth_v1"
AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1 = (
    "paybond.agent_receipt_transparency_inclusion_proof_v1"
)
AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION = 1

_HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")
_HEX128 = __import__("re").compile(r"^[0-9a-f]{128}$")


def _require_hex64(value: object, field: str) -> str:
    normalized = str(value).strip().lower()
    if not _HEX64.match(normalized):
        raise ValueError(
            f"agent receipt transparency: {field} must be a lowercase 64-byte hex SHA-256 digest"
        )
    return normalized


def _require_hex128(value: object, field: str) -> str:
    normalized = str(value).strip().lower()
    if not _HEX128.match(normalized):
        raise ValueError(
            f"agent receipt transparency: {field} must be a lowercase 128-char hex Ed25519 signature"
        )
    return normalized


def _largest_power_of_two_less_than(n: int) -> int:
    if n <= 1:
        return 0
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_leaf_hash_rfc6962(leaf_data: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || leaf_data)."""
    return hashlib.sha256(b"\x00" + leaf_data).digest()


def merkle_node_hash_rfc6962(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _reconstruct_merkle_root(
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    audit_path: Sequence[bytes],
) -> tuple[bytes, int]:
    if tree_size == 1:
        return leaf_hash, 0
    k = _largest_power_of_two_less_than(tree_size)
    if leaf_index < k:
        left, consumed = _reconstruct_merkle_root(leaf_hash, leaf_index, k, audit_path)
        if consumed >= len(audit_path):
            raise ValueError("agent receipt transparency: audit path too short")
        right = audit_path[consumed]
        return merkle_node_hash_rfc6962(left, right), consumed + 1
    right, consumed = _reconstruct_merkle_root(
        leaf_hash, leaf_index - k, tree_size - k, audit_path
    )
    if consumed >= len(audit_path):
        raise ValueError("agent receipt transparency: audit path too short")
    left = audit_path[consumed]
    return merkle_node_hash_rfc6962(left, right), consumed + 1


def _allows_signing_public_key(
    key_hex: str, trusted: Sequence[str] | None
) -> bool:
    if not trusted:
        return True
    normalized = key_hex.strip().lower()
    return any(value.strip().lower() == normalized for value in trusted)


def _canonical_sth_bytes(sth: Mapping[str, Any]) -> bytes:
    canonical = {
        "kind": AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1,
        "schema_version": AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
        "tenant_id": str(sth["tenant_id"]).strip(),
        "tree_size": int(sth["tree_size"]),
        "root_hash_sha256_hex": str(sth["root_hash_sha256_hex"]).strip().lower(),
        "issued_at": str(sth["issued_at"]).strip(),
        "signing_algorithm": AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
    }
    return json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_signed_tree_head_v1(
    sth: Mapping[str, Any],
    *,
    expected_signing_public_keys: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Verify a signed tree head (digest + Ed25519)."""
    if str(sth.get("kind", "")).strip() != AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1:
        raise ValueError(
            f"agent receipt transparency: kind must be {AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1}"
        )
    if int(sth.get("schema_version", -1)) != AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION:
        raise ValueError(
            "agent receipt transparency: schema_version must be "
            f"{AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION}"
        )
    tenant_id = str(sth.get("tenant_id", "")).strip()
    if not tenant_id:
        raise ValueError("agent receipt transparency: tenant_id is required")
    tree_size = int(sth["tree_size"])
    if tree_size < 0:
        raise ValueError("agent receipt transparency: tree_size must be non-negative")
    if str(sth.get("signing_algorithm", "")).strip() != AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519:
        raise ValueError(
            "agent receipt transparency: signing_algorithm must be "
            f"{AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519}"
        )
    root_hash = _require_hex64(sth["root_hash_sha256_hex"], "root_hash_sha256_hex")
    message_digest = _require_hex64(
        sth["message_digest_sha256_hex"], "message_digest_sha256_hex"
    )
    public_key_hex = _require_hex64(
        sth["signing_public_key_ed25519_hex"], "signing_public_key_ed25519_hex"
    )
    if not _allows_signing_public_key(public_key_hex, expected_signing_public_keys):
        raise ValueError(
            "agent receipt transparency: signing_public_key_ed25519_hex is not in the "
            "configured trusted key set"
        )
    normalized = {
        **dict(sth),
        "tenant_id": tenant_id,
        "tree_size": tree_size,
        "root_hash_sha256_hex": root_hash,
        "issued_at": str(sth["issued_at"]).strip(),
        "signing_algorithm": AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
    }
    digest = hashlib.sha256(_canonical_sth_bytes(normalized)).digest()
    if digest.hex() != message_digest:
        raise ValueError("agent receipt transparency: message digest mismatch")
    signature_hex = _require_hex128(sth["ed25519_signature_hex"], "ed25519_signature_hex")
    verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        verifier.verify(bytes.fromhex(signature_hex), digest)
    except InvalidSignature as exc:
        raise ValueError(
            "agent receipt transparency: ed25519 signature verification failed"
        ) from exc
    normalized["message_digest_sha256_hex"] = message_digest
    normalized["signing_public_key_ed25519_hex"] = public_key_hex
    normalized["ed25519_signature_hex"] = signature_hex
    return normalized


def verify_agent_receipt_inclusion(
    proof: Mapping[str, Any],
    *,
    expected_signing_public_keys: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Verify a receipt digest is included under a published signed tree head."""
    if str(proof.get("kind", "")).strip() != AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1:
        raise ValueError(
            "agent receipt transparency: kind must be "
            f"{AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1}"
        )
    if int(proof.get("schema_version", -1)) != AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION:
        raise ValueError(
            "agent receipt transparency: schema_version must be "
            f"{AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION}"
        )
    tenant_id = str(proof.get("tenant_id", "")).strip()
    receipt_id = str(proof.get("receipt_id", "")).strip()
    if not tenant_id:
        raise ValueError("agent receipt transparency: tenant_id is required")
    if not receipt_id:
        raise ValueError("agent receipt transparency: receipt_id is required")
    tree_size = int(proof["tree_size"])
    leaf_index = int(proof["leaf_index"])
    if tree_size <= 0:
        raise ValueError("agent receipt transparency: tree_size must be positive")
    if leaf_index < 0 or leaf_index >= tree_size:
        raise ValueError("agent receipt transparency: leaf_index out of range")

    message_digest = _require_hex64(
        proof["message_digest_sha256_hex"], "message_digest_sha256_hex"
    )
    leaf_hash_hex = _require_hex64(proof["leaf_hash_sha256_hex"], "leaf_hash_sha256_hex")
    root_hash_hex = _require_hex64(proof["root_hash_sha256_hex"], "root_hash_sha256_hex")
    sth = verify_signed_tree_head_v1(
        proof["tree_head"],
        expected_signing_public_keys=expected_signing_public_keys,
    )
    if sth["tenant_id"] != tenant_id:
        raise ValueError("agent receipt transparency: tree_head.tenant_id mismatch")
    if int(sth["tree_size"]) != tree_size:
        raise ValueError("agent receipt transparency: tree_head.tree_size mismatch")
    if sth["root_hash_sha256_hex"] != root_hash_hex:
        raise ValueError("agent receipt transparency: tree_head.root_hash mismatch")

    leaf_hash = merkle_leaf_hash_rfc6962(bytes.fromhex(message_digest))
    if leaf_hash.hex() != leaf_hash_hex:
        raise ValueError(
            "agent receipt transparency: leaf_hash does not match message digest"
        )
    audit_path = [
        bytes.fromhex(_require_hex64(entry, f"audit_path_sha256_hex[{i}]"))
        for i, entry in enumerate(proof.get("audit_path_sha256_hex") or [])
    ]
    root, consumed = _reconstruct_merkle_root(leaf_hash, leaf_index, tree_size, audit_path)
    if consumed != len(audit_path):
        raise ValueError("agent receipt transparency: audit path too long")
    if root.hex() != root_hash_hex:
        raise ValueError(
            "agent receipt transparency: inclusion proof does not match root hash"
        )
    return {
        **dict(proof),
        "tenant_id": tenant_id,
        "receipt_id": receipt_id,
        "message_digest_sha256_hex": message_digest,
        "leaf_hash_sha256_hex": leaf_hash_hex,
        "root_hash_sha256_hex": root_hash_hex,
        "leaf_index": leaf_index,
        "tree_size": tree_size,
        "audit_path_sha256_hex": [entry.hex() for entry in audit_path],
        "tree_head": sth,
    }
