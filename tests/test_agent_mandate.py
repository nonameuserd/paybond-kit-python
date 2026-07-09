"""Parity tests for agent mandate canonical JSON and verification."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from paybond_kit.agent_mandate import (
    agent_mandate_digest_sha256_hex,
    canonical_agent_mandate_json_bytes,
    normalize_agent_mandate_v1,
    sign_agent_mandate_v1,
    verify_signed_agent_mandate_v1,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "go/gateway/internal/protocolv2/testdata/agent_mandate_canonical_v1.json"
)


def _ed25519_seed(label: str) -> bytes:
    return hashlib.sha256(label.encode("utf-8")).digest()


def _test_agent_mandate(expires_at: str) -> dict:
    return {
        "authorization": {
            "kind": " principal ",
            "tenant_id": " acme-pilot ",
            "principal_subject": " user-123 ",
            "principal_type": " User ",
        },
        "agent": {
            "subject": " did:paybond:travel-booker ",
            "issuer": " urn:orchestrator:example ",
            "key_id": " kid-1 ",
            "display_name": " Travel Booker ",
        },
        "allowed_actions": [" tool.use ", "intent.create"],
        "allowed_tools": [" Stripe/Capture ", "travel.book", "travel.book"],
        "spend_ceiling": {
            "amount_minor": 250000,
            "currency": " USD ",
        },
        "settlement": {
            "default_rail": " STRIPE_CONNECT ",
            "allowed_rails": ["x402_usdc_base", "stripe_connect", "stripe_connect"],
        },
        "constraint": {
            "kind": " policy ",
            "id": " travel_hold ",
            "version": " v3 ",
        },
        "expires_at": expires_at,
        "nonce": " nonce-123 ",
        "human_presence_mode": " HUMAN_PRESENT ",
    }


@pytest.fixture(scope="module")
def fixtures() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_file_version(fixtures: dict) -> None:
    assert fixtures["version"] == 1
    assert len(fixtures["cases"]) > 0


@pytest.mark.parametrize("case", json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))["cases"], ids=lambda c: c["name"])
def test_go_canonical_parity(case: dict) -> None:
    body = canonical_agent_mandate_json_bytes(case["mandate"])
    digest = agent_mandate_digest_sha256_hex(case["mandate"])
    expected_bytes = bytes.fromhex(case["canonical_json_hex"])

    assert body.decode("utf-8") == case["canonical_json"]
    assert body == expected_bytes
    assert digest == case["digest_sha256_hex"]


def test_normalize_agent_mandate_v1_canonicalizes_fields() -> None:
    normalized = normalize_agent_mandate_v1(_test_agent_mandate("2030-01-02T03:04:05Z"))

    assert normalized["kind"] == "paybond.agent_mandate_v1"
    assert normalized["authorization"]["kind"] == "principal"
    assert normalized["authorization"]["tenant_id"] == "acme-pilot"
    assert normalized["authorization"]["principal_type"] == "user"
    assert normalized["allowed_actions"] == ["intent.create", "tool.use"]
    assert normalized["allowed_tools"] == ["stripe/capture", "travel.book"]
    assert normalized["spend_ceiling"]["currency"] == "usd"
    assert normalized["settlement"]["default_rail"] == "stripe_connect"
    assert normalized["settlement"]["allowed_rails"] == ["stripe_connect", "x402_usdc_base"]
    assert normalized["constraint"]["kind"] == "policy"
    assert normalized["human_presence_mode"] == "human_present"
    assert normalized["nonce"] == "nonce-123"


def test_digest_stable_before_and_after_normalization() -> None:
    raw = _test_agent_mandate("2030-01-02T03:04:05Z")
    normalized = normalize_agent_mandate_v1(raw)
    assert agent_mandate_digest_sha256_hex(raw) == agent_mandate_digest_sha256_hex(normalized)


def test_rejects_tenant_scoped_mandates_with_principal_fields() -> None:
    mandate = _test_agent_mandate("2030-01-02T03:04:05Z")
    mandate["authorization"]["kind"] = "tenant"
    with pytest.raises(ValueError, match="tenant-scoped mandates"):
        normalize_agent_mandate_v1(mandate)


def test_sign_and_verify_round_trip() -> None:
    seed = _ed25519_seed("agent-mandate-sign-roundtrip")
    now = datetime(2026, 5, 17, 16, 0, 0, tzinfo=UTC)
    signed = sign_agent_mandate_v1(seed, _test_agent_mandate("2026-05-17T18:00:00+00:00"))

    assert signed["signing_algorithm"] == "ed25519-sha256-json-v1"
    assert len(signed["message_digest_sha256_hex"]) == 64

    verify_signed_agent_mandate_v1(signed, now=now)


def test_rejects_expired_mandates() -> None:
    seed = _ed25519_seed("agent-mandate-expired")
    now = datetime(2026, 5, 17, 16, 0, 0, tzinfo=UTC)
    signed = sign_agent_mandate_v1(seed, _test_agent_mandate("2026-05-17T15:59:00+00:00"))

    with pytest.raises(ValueError, match="expired at"):
        verify_signed_agent_mandate_v1(signed, now=now)


def test_rejects_tampered_mandate_bodies() -> None:
    seed = _ed25519_seed("agent-mandate-tamper")
    now = datetime(2026, 5, 17, 16, 0, 0, tzinfo=UTC)
    signed = sign_agent_mandate_v1(seed, _test_agent_mandate("2026-05-17T18:00:00+00:00"))
    signed["allowed_tools"] = ["travel.cancel"]

    with pytest.raises(ValueError, match="message digest mismatch"):
        verify_signed_agent_mandate_v1(signed, now=now)
