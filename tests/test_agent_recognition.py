"""Tests for agent recognition proof signing."""

from __future__ import annotations

import hashlib
import json

from paybond_kit.agent_recognition import (
    AGENT_RECOGNITION_PURPOSE_CREATE,
    AGENT_RECOGNITION_PURPOSE_EVIDENCE_SUBMIT,
    AGENT_RECOGNITION_PURPOSE_FUND,
    AGENT_RECOGNITION_PURPOSE_SETTLEMENT_CONFIRM,
    new_agent_recognition_request_envelope,
    sign_agent_recognition_proof_v1,
    sign_harbor_create_recognition_proof,
    sign_harbor_fund_recognition_proof,
    sign_harbor_evidence_submit_recognition_proof,
    sign_harbor_settlement_confirm_recognition_proof,
)


def _seed(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def test_sign_agent_recognition_proof_v1_canonicalizes_fields() -> None:
    signing_seed = _seed("agent-recognition-proof-roundtrip")
    body = b'{"rollback":true}'
    proof = sign_agent_recognition_proof_v1(
        signing_seed,
        key_id=" kid-1 ",
        purpose=" harbor.policy.rollback ",
        tenant_id=" acme-pilot ",
        method=" post ",
        path=" /harbor/policy/v1/rollback ",
        body=body,
        nonce=" nonce-123 ",
    )

    assert proof["kind"] == "paybond.agent_recognition_proof_v1"
    assert proof["key_id"] == "kid-1"
    assert proof["purpose"] == "harbor.policy.rollback"
    assert proof["verifier_context"] == {
        "tenant_id": "acme-pilot",
        "verifier_id": "paybond-gateway",
    }
    assert proof["request_envelope"] == {
        "method": "POST",
        "path": "/harbor/policy/v1/rollback",
        "body_digest_sha256_hex": hashlib.sha256(body).hexdigest(),
    }
    assert len(proof["message_digest_sha256_hex"]) == 64
    assert len(proof["signing_public_key_ed25519_hex"]) == 64
    assert len(proof["ed25519_signature_hex"]) == 128


def test_sign_harbor_create_recognition_proof_binds_body() -> None:
    signing_seed = _seed("httpserver-agent-recognition")
    intent_body = {
        "intent_id": "550e8400-e29b-41d4-a716-446655440000",
        "max_spend_cents": 500,
        "currency": "USD",
    }
    proof = sign_harbor_create_recognition_proof(
        tenant_id="tenant-a",
        intent_body=intent_body,
        key_id="kid-1",
        signing_seed=signing_seed,
    )

    assert proof["purpose"] == AGENT_RECOGNITION_PURPOSE_CREATE
    assert proof["request_envelope"]["path"] == "/harbor/intents"
    assert proof["request_envelope"]["body_digest_sha256_hex"] == hashlib.sha256(
        json.dumps(intent_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def test_sign_harbor_fund_recognition_proof_binds_empty_body() -> None:
    signing_seed = _seed("httpserver-agent-recognition")
    proof = sign_harbor_fund_recognition_proof(
        tenant_id="tenant-a",
        intent_id="550e8400-e29b-41d4-a716-446655440000",
        key_id="kid-1",
        signing_seed=signing_seed,
    )

    assert proof["purpose"] == AGENT_RECOGNITION_PURPOSE_FUND
    assert proof["request_envelope"]["path"] == (
        "/harbor/intents/550e8400-e29b-41d4-a716-446655440000/fund"
    )
    assert proof["request_envelope"]["body_digest_sha256_hex"] == hashlib.sha256(
        json.dumps({}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def test_sign_harbor_evidence_submit_recognition_proof_binds_body() -> None:
    signing_seed = _seed("httpserver-agent-recognition")
    evidence_body = {
        "payload": {"status": "completed", "cost_cents": 100},
        "payee_did": "did:web:vendor.example",
        "submitted_at": "2026-06-30T12:00:00Z",
    }
    proof = sign_harbor_evidence_submit_recognition_proof(
        tenant_id="tenant-a",
        intent_id="550e8400-e29b-41d4-a716-446655440000",
        evidence_body=evidence_body,
        key_id="kid-1",
        signing_seed=signing_seed,
    )

    assert proof["purpose"] == AGENT_RECOGNITION_PURPOSE_EVIDENCE_SUBMIT
    assert proof["request_envelope"]["path"] == (
        "/harbor/intents/550e8400-e29b-41d4-a716-446655440000/evidence"
    )
    assert proof["request_envelope"]["body_digest_sha256_hex"] == hashlib.sha256(
        json.dumps(evidence_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def test_sign_harbor_settlement_confirm_recognition_proof_binds_body() -> None:
    signing_seed = _seed("httpserver-agent-recognition")
    body = {"note": "confirm implied action"}
    proof = sign_harbor_settlement_confirm_recognition_proof(
        tenant_id="tenant-a",
        intent_id="550e8400-e29b-41d4-a716-446655440000",
        body=body,
        key_id="kid-1",
        signing_seed=signing_seed,
    )

    assert proof["purpose"] == AGENT_RECOGNITION_PURPOSE_SETTLEMENT_CONFIRM
    assert proof["request_envelope"]["path"] == (
        "/harbor/intents/550e8400-e29b-41d4-a716-446655440000/settlement/confirm"
    )
    assert proof["request_envelope"]["body_digest_sha256_hex"] == hashlib.sha256(
        json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def test_new_agent_recognition_request_envelope_matches_gateway_path() -> None:
    envelope = new_agent_recognition_request_envelope(
        "POST",
        "/harbor/intents/intent-1/evidence",
        {"payload": {"ok": True}},
    )
    assert envelope.method == "POST"
    assert envelope.path == "/harbor/intents/intent-1/evidence"
