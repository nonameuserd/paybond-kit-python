from __future__ import annotations

import json
from typing import NotRequired, TypedDict

import pytest

import paybond_kit.agent.run  # Prime agent imports before paybond_kit.policy package init.
from paybond_kit.completion_catalog import get_completion_preset
from paybond_kit.policy import PaybondPolicy, PaybondPolicyIntentSpecError

TRAVEL_POLICY: dict[str, object] = {
    "version": 1,
    "name": "travel-agent-v1",
    "default_deny": True,
    "tools": {
        "travel.book_hotel": {
            "side_effecting": True,
            "max_spend_cents": 20000,
            "evidence_preset": "cost_and_completion",
            "vendor_pack": "travel_booking_v1",
        },
        "search.web": {
            "side_effecting": False,
        },
    },
    "intent": {
        "policy_binding": {
            "template_id": "travel_agent_template",
            "version_seq": 3,
            "head_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        "budget": {
            "currency": "usd",
            "max_spend_usd": 200,
        },
        "allowed_tools": ["travel.book_hotel"],
    },
}

PRINCIPAL_SEED = bytes([1] * 32)
PAYEE_SEED = bytes([2] * 32)


class _IntentCreateKwargs(TypedDict):
    principal_did: str
    principal_signing_seed: bytes
    payee_did: str
    payee_signing_seed: bytes
    deadline_rfc3339: str
    settlement_rail: str
    recognition_proof: dict[str, object]
    materialized_predicate: dict[str, object]
    policy_template_id: str
    policy_version_seq: int
    policy_content_digest_hex: str
    intent_id: NotRequired[str]
    amount_cents: NotRequired[int]
    currency: NotRequired[str]
    budget: NotRequired[dict[str, object]]


def _base_kwargs() -> _IntentCreateKwargs:
    return {
        "principal_did": "did:paybond:principal",
        "principal_signing_seed": PRINCIPAL_SEED,
        "payee_did": "did:paybond:payee",
        "payee_signing_seed": PAYEE_SEED,
        "deadline_rfc3339": "2026-12-31T23:59:59Z",
        "settlement_rail": "stripe_connect",
        "recognition_proof": {"kind": "test"},
        "materialized_predicate": {"all": [{"field": "status", "eq": "ok"}]},
        "policy_template_id": "travel_agent_template",
        "policy_version_seq": 3,
        "policy_content_digest_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }


def test_policy_to_intent_create_input_maps_policy_alignment() -> None:
    policy = PaybondPolicy.load(TRAVEL_POLICY)
    input_ = policy.to_intent_create_input(**_base_kwargs())

    assert input_.allowed_tools == ["travel.book_hotel"]
    assert input_.currency == "usd"
    assert input_.amount_cents == 20000
    assert input_.budget["max"] == 20000
    assert input_.policy_template_id == "travel_agent_template"
    assert input_.policy_version_seq == 3
    assert input_.completion_preset_id == "cost_and_completion"
    assert input_.evidence_schema == get_completion_preset("cost_and_completion")["evidence_schema"]


def test_policy_to_intent_create_input_resolves_custom_operation() -> None:
    policy = PaybondPolicy.load(
        {
            "version": 1,
            "name": "ops-v1",
            "default_deny": True,
            "tools": {
                "book_hotel": {
                    "side_effecting": True,
                    "operation": "travel.book_hotel",
                    "evidence_preset": "cost_and_completion",
                }
            },
            "intent": {
                "policy_binding": {
                    "template_id": "travel_agent_template",
                    "version_seq": 3,
                },
                "allowed_tools": ["book_hotel"],
            },
        }
    )
    kwargs = _base_kwargs()
    kwargs.update(
        {
            "amount_cents": 5000,
            "currency": "usd",
            "budget": {"max": 5000},
        }
    )
    input_ = policy.to_intent_create_input(**kwargs)
    assert input_.allowed_tools == ["travel.book_hotel"]


def test_policy_to_intent_create_input_builds_native_create_body() -> None:
    pytest.importorskip("paybond_kit._native")
    from paybond_kit._native import build_signed_create_intent_with_policy_binding_json

    policy = PaybondPolicy.load(TRAVEL_POLICY)
    kwargs = _base_kwargs()
    kwargs["intent_id"] = "00000000-0000-4000-8000-000000000001"
    input_ = policy.to_intent_create_input(**kwargs)
    assert input_.intent_id is not None

    wire = build_signed_create_intent_with_policy_binding_json(
        "tenant-1",
        input_.principal_signing_seed,
        input_.payee_signing_seed,
        input_.intent_id,
        input_.principal_did,
        input_.payee_did,
        json.dumps(input_.budget),
        input_.currency,
        input_.amount_cents,
        json.dumps(input_.evidence_schema),
        input_.deadline_rfc3339,
        json.dumps(input_.materialized_predicate),
        input_.predicate_ref,
        json.dumps(input_.allowed_tools),
        input_.settlement_rail,
        input_.policy_template_id,
        input_.policy_version_seq,
        input_.policy_content_digest_hex,
    )
    body = json.loads(wire)

    assert body["signing_version"] == 7
    assert body["policy_binding"] == {
        "template_id": "travel_agent_template",
        "version_seq": 3,
    }
    assert body["allowed_tools"] == ["travel.book_hotel"]


def test_policy_to_intent_create_input_rejects_digest_mismatch() -> None:
    policy = PaybondPolicy.load(TRAVEL_POLICY)
    kwargs = _base_kwargs()
    kwargs["policy_content_digest_hex"] = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )

    with pytest.raises(PaybondPolicyIntentSpecError):
        policy.to_intent_create_input(**kwargs)


def test_policy_to_intent_create_input_requires_policy_binding() -> None:
    policy = PaybondPolicy.load(
        {
            "version": 1,
            "name": "no-binding",
            "default_deny": True,
            "tools": {
                "travel.book_hotel": {
                    "side_effecting": True,
                    "evidence_preset": "cost_and_completion",
                }
            },
            "intent": {
                "allowed_tools": ["travel.book_hotel"],
            },
        }
    )

    with pytest.raises(PaybondPolicyIntentSpecError):
        policy.to_intent_create_input(**_base_kwargs())
