"""Sign replay-safe AgentRecognitionProofV1 payloads for Gateway Harbor mutations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

AGENT_RECOGNITION_PROOF_SCHEMA_VERSION = 1
AGENT_RECOGNITION_PROOF_KIND_V1 = "paybond.agent_recognition_proof_v1"
AGENT_RECOGNITION_SIGNATURE_ALGORITHM_ED25519 = "ed25519-sha256-json-v1"
AGENT_RECOGNITION_GATEWAY_VERIFIER_ID = "paybond-gateway"
AGENT_RECOGNITION_PURPOSE_CREATE = "harbor.intent.create"
AGENT_RECOGNITION_PURPOSE_FUND = "harbor.intent.fund"
AGENT_RECOGNITION_PURPOSE_EVIDENCE_SUBMIT = "harbor.intent.evidence.submit"
AGENT_RECOGNITION_PURPOSE_SETTLEMENT_CONFIRM = "harbor.intent.settlement.confirm"
AGENT_RECOGNITION_MAX_FRESHNESS = timedelta(minutes=10)

_SCOPE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class AgentRecognitionRequestEnvelope:
    method: str
    path: str
    body_digest_sha256_hex: str


def _format_rfc3339_seconds(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_scope_token(value: str, field: str) -> str:
    normalized = value.strip().lower()
    if not normalized:
        raise ValueError(f"agent recognition proof: {field} is required")
    if not _SCOPE_TOKEN_RE.fullmatch(normalized):
        raise ValueError(f"agent recognition proof: {field} {normalized!r} is not canonical")
    return normalized


def _request_body_bytes(body: bytes | Mapping[str, Any]) -> bytes:
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def new_agent_recognition_request_envelope(
    method: str,
    path: str,
    body: bytes | Mapping[str, Any],
) -> AgentRecognitionRequestEnvelope:
    normalized_method = method.strip().upper()
    normalized_path = path.strip() or "/"
    if not normalized_method:
        raise ValueError("agent recognition proof: request_envelope.method is required")
    if not normalized_path.startswith("/"):
        raise ValueError('agent recognition proof: request_envelope.path must begin with "/"')
    digest = hashlib.sha256(_request_body_bytes(body)).hexdigest()
    return AgentRecognitionRequestEnvelope(
        method=normalized_method,
        path=normalized_path,
        body_digest_sha256_hex=digest,
    )


def _marshal_canonical_agent_recognition_proof(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_agent_recognition_proof_v1(
    signing_seed: bytes,
    *,
    key_id: str,
    purpose: str,
    tenant_id: str,
    method: str,
    path: str,
    body: bytes | Mapping[str, Any],
    verifier_id: str = AGENT_RECOGNITION_GATEWAY_VERIFIER_ID,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Validate, canonicalize, and sign a replay-safe recognition proof."""
    if len(signing_seed) != 32:
        raise ValueError("agent recognition proof: signing key must be an ed25519 private key")

    tenant = tenant_id.strip()
    if not tenant:
        raise ValueError("agent recognition proof: verifier_context.tenant_id is required")

    now = datetime.now(timezone.utc)
    issued = issued_at.astimezone(timezone.utc) if issued_at is not None else now - timedelta(minutes=1)
    expires = expires_at.astimezone(timezone.utc) if expires_at is not None else issued + timedelta(minutes=4)
    issued = issued.replace(microsecond=0)
    expires = expires.replace(microsecond=0)

    if expires <= issued:
        raise ValueError("agent recognition proof: expires_at must be after issued_at")
    if expires - issued > AGENT_RECOGNITION_MAX_FRESHNESS:
        raise ValueError("agent recognition proof: freshness window must not exceed 10m0s")

    resolved_nonce = (nonce or str(uuid4())).strip()
    if not resolved_nonce:
        raise ValueError("agent recognition proof: nonce is required")
    if len(resolved_nonce) > 256:
        raise ValueError("agent recognition proof: nonce must be 256 bytes or fewer")

    request_envelope = new_agent_recognition_request_envelope(method, path, body)
    if not _HEX64_RE.fullmatch(request_envelope.body_digest_sha256_hex):
        raise ValueError(
            "agent recognition proof: request_envelope.body_digest_sha256_hex must be a "
            "lowercase 64-byte hex SHA-256 digest"
        )

    canonical_payload = {
        "schema_version": AGENT_RECOGNITION_PROOF_SCHEMA_VERSION,
        "kind": AGENT_RECOGNITION_PROOF_KIND_V1,
        "key_id": _normalize_scope_token(key_id, "key_id"),
        "signature_algorithm": AGENT_RECOGNITION_SIGNATURE_ALGORITHM_ED25519,
        "issued_at": _format_rfc3339_seconds(issued),
        "expires_at": _format_rfc3339_seconds(expires),
        "nonce": resolved_nonce,
        "purpose": _normalize_scope_token(purpose, "purpose"),
        "verifier_context": {
            "tenant_id": tenant,
            "verifier_id": _normalize_scope_token(verifier_id, "verifier_context.verifier_id"),
        },
        "request_envelope": {
            "method": request_envelope.method,
            "path": request_envelope.path,
            "body_digest_sha256_hex": request_envelope.body_digest_sha256_hex,
        },
    }
    canonical = _marshal_canonical_agent_recognition_proof(canonical_payload)
    digest = hashlib.sha256(canonical).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(signing_seed)
    public_key = private_key.public_key().public_bytes_raw()
    signature = private_key.sign(digest)

    return {
        **canonical_payload,
        "message_digest_sha256_hex": digest.hex(),
        "signing_public_key_ed25519_hex": public_key.hex(),
        "ed25519_signature_hex": signature.hex(),
    }


def sign_harbor_create_recognition_proof(
    *,
    tenant_id: str,
    intent_body: Mapping[str, Any],
    key_id: str,
    signing_seed: bytes,
) -> dict[str, Any]:
    """Build a recognition proof for Gateway ``POST /harbor/intents``."""
    return sign_agent_recognition_proof_v1(
        signing_seed,
        key_id=key_id,
        purpose=AGENT_RECOGNITION_PURPOSE_CREATE,
        tenant_id=tenant_id,
        method="POST",
        path="/harbor/intents",
        body=intent_body,
    )


def sign_harbor_fund_recognition_proof(
    *,
    tenant_id: str,
    intent_id: str,
    key_id: str,
    signing_seed: bytes,
) -> dict[str, Any]:
    """Build a recognition proof for Gateway ``POST /harbor/intents/{intent_id}/fund``."""
    return sign_agent_recognition_proof_v1(
        signing_seed,
        key_id=key_id,
        purpose=AGENT_RECOGNITION_PURPOSE_FUND,
        tenant_id=tenant_id,
        method="POST",
        path=f"/harbor/intents/{intent_id}/fund",
        body={},
    )


def sign_harbor_evidence_submit_recognition_proof(
    *,
    tenant_id: str,
    intent_id: str,
    evidence_body: Mapping[str, Any],
    key_id: str,
    signing_seed: bytes,
) -> dict[str, Any]:
    """Build a recognition proof for Gateway ``POST /harbor/intents/{intent_id}/evidence``."""
    return sign_agent_recognition_proof_v1(
        signing_seed,
        key_id=key_id,
        purpose=AGENT_RECOGNITION_PURPOSE_EVIDENCE_SUBMIT,
        tenant_id=tenant_id,
        method="POST",
        path=f"/harbor/intents/{intent_id}/evidence",
        body=evidence_body,
    )


def sign_harbor_settlement_confirm_recognition_proof(
    *,
    tenant_id: str,
    intent_id: str,
    body: Mapping[str, Any] | None = None,
    key_id: str,
    signing_seed: bytes,
) -> dict[str, Any]:
    """Build a recognition proof for Gateway ``POST /harbor/intents/{intent_id}/settlement/confirm``."""
    return sign_agent_recognition_proof_v1(
        signing_seed,
        key_id=key_id,
        purpose=AGENT_RECOGNITION_PURPOSE_SETTLEMENT_CONFIRM,
        tenant_id=tenant_id,
        method="POST",
        path=f"/harbor/intents/{intent_id}/settlement/confirm",
        body=dict(body or {}),
    )
