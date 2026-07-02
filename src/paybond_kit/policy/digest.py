"""Canonical policy document digests (Gateway-compatible)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from paybond_kit.policy.schema import PaybondPolicyDocumentV1, policy_document_to_dict


def _canonicalize_json(value: Any) -> Any:
    if isinstance(value, list):
        return [_canonicalize_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonicalize_json(value[key]) for key in sorted(value)}
    return value


def canonical_policy_document_digest(document: PaybondPolicyDocumentV1) -> str:
    """Return ``sha256:<hex>`` for the canonical JSON encoding of a v1 policy document."""
    wire = policy_document_to_dict(document)
    text = json.dumps(_canonicalize_json(wire), sort_keys=True, separators=(",", ":"))
    digest_hex = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest_hex}"


def policy_version_label(name: str, digest: str) -> str:
    """Human-readable policy version label (``{name}@{digest_short}``)."""
    trimmed = digest.strip()
    if trimmed.startswith("sha256:") and len(trimmed) >= 15:
        short = trimmed[7:15]
    else:
        short = trimmed[:8]
    return f"{name}@{short}"
