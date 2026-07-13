from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from paybond_kit.agent_receipt import AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519
from paybond_kit.agent_receipt_inclusion import (
    AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1,
    AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
    AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1,
    merkle_leaf_hash_rfc6962,
    merkle_node_hash_rfc6962,
    verify_agent_receipt_inclusion,
)


def _largest_power_of_two_less_than(n: int) -> int:
    if n <= 1:
        return 0
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _merkle_root(leaf_hashes: list[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _largest_power_of_two_less_than(n)
    return merkle_node_hash_rfc6962(_merkle_root(leaf_hashes[:k]), _merkle_root(leaf_hashes[k:]))


def _inclusion_path(leaf_hashes: list[bytes], leaf_index: int) -> list[bytes]:
    n = len(leaf_hashes)
    if n == 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if leaf_index < k:
        return _inclusion_path(leaf_hashes[:k], leaf_index) + [_merkle_root(leaf_hashes[k:])]
    return _inclusion_path(leaf_hashes[k:], leaf_index - k) + [_merkle_root(leaf_hashes[:k])]


def test_verify_agent_receipt_inclusion_round_trip() -> None:
    digests: list[str] = []
    leaf_hashes: list[bytes] = []
    for i in range(5):
        digest = hashlib.sha256(bytes([i + 7])).digest()
        digests.append(digest.hex())
        leaf_hashes.append(merkle_leaf_hash_rfc6962(digest))
    root = _merkle_root(leaf_hashes)
    private_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"py-inclusion").digest())
    public_key = private_key.public_key().public_bytes_raw()
    canonical = {
        "kind": AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1,
        "schema_version": AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
        "tenant_id": "tenant.example",
        "tree_size": len(leaf_hashes),
        "root_hash_sha256_hex": root.hex(),
        "issued_at": "2026-01-01T00:00:00.000Z",
        "signing_algorithm": AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
    }
    canonical_bytes = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    digest = hashlib.sha256(canonical_bytes).digest()
    signature = private_key.sign(digest)
    sth = {
        **canonical,
        "signing_public_key_ed25519_hex": public_key.hex(),
        "message_digest_sha256_hex": digest.hex(),
        "ed25519_signature_hex": signature.hex(),
    }
    leaf_index = 2
    path = _inclusion_path(leaf_hashes, leaf_index)
    proof = {
        "kind": AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1,
        "schema_version": AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
        "tenant_id": "tenant.example",
        "receipt_id": "receipt-2",
        "message_digest_sha256_hex": digests[leaf_index],
        "leaf_index": leaf_index,
        "tree_size": len(leaf_hashes),
        "leaf_hash_sha256_hex": leaf_hashes[leaf_index].hex(),
        "audit_path_sha256_hex": [entry.hex() for entry in path],
        "root_hash_sha256_hex": root.hex(),
        "tree_head": sth,
    }
    verified = verify_agent_receipt_inclusion(proof)
    assert verified["leaf_index"] == 2
    assert verified["tree_head"]["tree_size"] == 5
