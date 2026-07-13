"""ACTA decision-receipt projection for paybond.agent_receipt_v1."""

from __future__ import annotations

from typing import Any, Mapping, MutableMapping

ACTA_AGENT_RECEIPT_TYPE = "paybond:agent_receipt"
ACTA_SIGNATURE_ALG_EDDSA = "EdDSA"


def _as_mapping(value: object) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    return None


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed if trimmed else None


def _sha256_prefixed(hex_digest: str) -> str:
    normalized = hex_digest.strip().lower()
    if normalized.startswith("sha256:"):
        return normalized
    return f"sha256:{normalized}"


def project_acta_decision_from_agent_receipt(receipt: Mapping[str, Any]) -> str:
    """Map ARS execution/outcome fields to an ACTA allow/deny decision."""
    scope = (_optional_string(receipt.get("scope")) or "").lower()
    outcome = _as_mapping(receipt.get("outcome")) or {}
    execution = _as_mapping(receipt.get("execution")) or {}
    evidence = _as_mapping(receipt.get("evidence")) or {}

    if scope == "intent_terminal":
        settlement = (_optional_string(outcome.get("settlement_outcome")) or "").upper()
        if settlement in {"FAILED", "REVERSED"}:
            return "deny"
        if settlement in {"SETTLED", "PENDING_FINALITY"}:
            return "allow"
        harbor = (_optional_string(outcome.get("harbor_state")) or "").lower()
        if harbor in {"failed", "failure", "refunded"}:
            return "deny"
        return "allow"

    exec_outcome = (_optional_string(execution.get("outcome")) or "").lower()
    if exec_outcome and exec_outcome != "executed":
        return "deny"
    if evidence.get("predicate_passed") is False or outcome.get("predicate_passed") is False:
        return "deny"
    return "allow"


def project_agent_receipt_to_acta_decision_receipt(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Project a composed/verified ARS receipt into an ACTA decision-receipt shape.

    Signature fields are copied for correlation. Authenticity remains native ARS verify.
    """
    receipt_id = _optional_string(receipt.get("receipt_id"))
    issued_at = _optional_string(receipt.get("issued_at"))
    scope = _optional_string(receipt.get("scope"))
    pub_key = (_optional_string(receipt.get("signing_public_key_ed25519_hex")) or "").lower()
    sig = (_optional_string(receipt.get("ed25519_signature_hex")) or "").lower()
    message_digest = (
        _optional_string(receipt.get("message_digest_sha256_hex")) or ""
    ).lower() or None

    if not receipt_id:
        raise ValueError("acta projection: receipt_id is required")
    if not issued_at:
        raise ValueError("acta projection: issued_at is required")
    if not scope:
        raise ValueError("acta projection: scope is required")
    if not pub_key:
        raise ValueError("acta projection: signing_public_key_ed25519_hex is required")
    if not sig:
        raise ValueError("acta projection: ed25519_signature_hex is required")

    authorization = _as_mapping(receipt.get("authorization")) or {}
    policy = _as_mapping(authorization.get("policy")) or {}
    execution = _as_mapping(receipt.get("execution")) or {}
    outcome = _as_mapping(receipt.get("outcome")) or {}
    continuity = _as_mapping(receipt.get("continuity")) or {}

    payload: MutableMapping[str, Any] = {
        "type": ACTA_AGENT_RECEIPT_TYPE,
        "issued_at": issued_at,
        "issuer_id": pub_key,
        "decision": project_acta_decision_from_agent_receipt(receipt),
        "ars_receipt_id": receipt_id,
        "ars_scope": scope,
        "ars_kind": "paybond.agent_receipt_v1",
    }

    tool_name = _optional_string(execution.get("tool_name"))
    if tool_name:
        payload["tool_name"] = tool_name

    reason = (
        _optional_string(outcome.get("harbor_state"))
        or _optional_string(outcome.get("spend_reservation_outcome"))
        or _optional_string(outcome.get("settlement_outcome"))
    )
    if reason:
        payload["reason"] = reason

    policy_digest_hex = _optional_string(policy.get("content_digest_sha256_hex"))
    if policy_digest_hex:
        payload["policy_digest"] = _sha256_prefixed(policy_digest_hex)

    session_id = _optional_string(execution.get("run_id")) or _optional_string(
        continuity.get("run_id")
    )
    if session_id:
        payload["session_id"] = session_id

    action_ref = _optional_string(execution.get("arguments_digest_sha256_hex")) or message_digest
    if action_ref:
        payload["action_ref"] = action_ref.lower()

    if message_digest:
        payload["payload_digest"] = _sha256_prefixed(message_digest)

    return {
        "payload": dict(payload),
        "signature": {
            "alg": ACTA_SIGNATURE_ALG_EDDSA,
            "kid": pub_key,
            "sig": sig,
        },
    }
