"""Canonical payee evidence signing (Rust extension backed by ``paybond-evidence``)."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID


def sign_payee_evidence_binding(
    *,
    tenant_id: str,
    intent_id: UUID,
    payee_did: str,
    payload: dict[str, Any],
    artifacts_blake3_hex: list[str],
    submitted_at_rfc3339: str,
    payee_signing_seed: bytes,
) -> dict[str, Any]:
    """
    Build a Harbor ``POST /intents/{id}/evidence`` JSON body with a detached Ed25519 signature.

    ``tenant_id`` must match the ``HarborClient`` tenant header for the same run (tenant isolation).

    Args:
        tenant_id: Harbor tenant realm (must match ``x-tenant-id`` on submission).
        intent_id: Intent UUID in the URL path.
        payee_did: Payee DID bound to the intent.
        payload: Evidence JSON payload (must satisfy the intent evidence schema server-side).
        artifacts_blake3_hex: Optional list of 64-char hex BLAKE3 digests (artifact blobs).
        submitted_at_rfc3339: Evidence binding timestamp (RFC3339, UTC recommended).
        payee_signing_seed: 32-byte Ed25519 seed corresponding to the payee key advertised to Harbor.

    Returns:
        A dict ready for JSON serialization to Harbor.

    Raises:
        ImportError: If the native extension was not built (run ``maturin develop`` from ``kit/python``).
        ValueError: For malformed UUIDs, JSON, timestamps, or wrong seed length.
        RuntimeError: For signing failures surfaced from Rust.
    """
    try:
        from paybond_kit import _native
    except ImportError as exc:  # pragma: no cover - exercised when wheel lacks native
        raise ImportError(
            "paybond_kit._native is required for evidence signing. Install a published wheel with "
            "`pip install paybond-kit`, or from a checkout run `maturin develop` "
            "(Rust toolchain required)."
        ) from exc

    if len(payee_signing_seed) != 32:
        raise ValueError("payee_signing_seed must be exactly 32 bytes")

    raw: str = _native.sign_payee_evidence_binding_json(
        tenant_id,
        str(intent_id),
        payee_did,
        json.dumps(payload),
        artifacts_blake3_hex,
        submitted_at_rfc3339,
        payee_signing_seed,
    )
    return json.loads(raw)
