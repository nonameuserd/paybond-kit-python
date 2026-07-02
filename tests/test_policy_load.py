from __future__ import annotations

import json
from pathlib import Path

import pytest

from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.schema import parse_paybond_policy_document_v1

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
            "head_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        "budget": {
            "currency": "usd",
            "max_spend_usd": 200,
        },
        "allowed_tools": ["travel.book_hotel"],
    },
}

TRAVEL_POLICY_YAML = """version: 1
name: travel-agent-v1
default_deny: true
tools:
  travel.book_hotel:
    side_effecting: true
    max_spend_cents: 20000
    evidence_preset: cost_and_completion
    vendor_pack: travel_booking_v1
  search.web:
    side_effecting: false
intent:
  policy_binding:
    template_id: travel_agent_template
    head_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  budget:
    currency: usd
    max_spend_usd: 200
  allowed_tools:
    - travel.book_hotel
"""


def test_paybond_policy_load_from_object() -> None:
    policy = PaybondPolicy.load(TRAVEL_POLICY)
    assert policy.name == "travel-agent-v1"
    assert policy.default_deny is True
    assert policy.intent is not None
    assert policy.intent.allowed_tools == ("travel.book_hotel",)


def test_paybond_policy_load_from_yaml_file(tmp_path: Path) -> None:
    path = tmp_path / "paybond.policy.yaml"
    path.write_text(TRAVEL_POLICY_YAML, encoding="utf-8")
    policy = PaybondPolicy.load(path)
    assert policy.source == str(path)
    assert policy.name == "travel-agent-v1"


def test_paybond_policy_load_from_json_file(tmp_path: Path) -> None:
    path = tmp_path / "paybond.policy.json"
    path.write_text(json.dumps(TRAVEL_POLICY), encoding="utf-8")
    policy = PaybondPolicy.load(path)
    assert policy.name == "travel-agent-v1"


def test_paybond_policy_to_tool_registry_fixed_spend() -> None:
    policy = PaybondPolicy.load(TRAVEL_POLICY)
    registry = policy.to_tool_registry()

    assert registry.default_deny is True
    assert registry.is_side_effecting("travel.book_hotel") is True
    assert registry.is_side_effecting("search.web") is False
    assert registry.resolve_spend_cents("travel.book_hotel", {}) == 20000
    assert registry.resolve_operation("travel.book_hotel") == "travel.book_hotel"
    entry = registry.get_side_effecting_entry("travel.book_hotel")
    assert entry is not None
    assert entry.evidence_preset == "cost_and_completion"


def test_paybond_policy_to_tool_registry_spend_from_args() -> None:
    policy = PaybondPolicy.load(
        {
            "version": 1,
            "name": "spend-path-v1",
            "default_deny": True,
            "tools": {
                "travel.book_hotel": {
                    "side_effecting": True,
                    "spend_from_args": "estimated_price_cents",
                    "evidence_preset": "cost_and_completion",
                }
            },
        }
    )
    registry = policy.to_tool_registry()

    assert registry.resolve_spend_cents("travel.book_hotel", {"estimated_price_cents": 1500}) == 1500
    assert registry.resolve_spend_cents("travel.book_hotel", {}) is None


def test_paybond_policy_to_tool_registry_custom_operation() -> None:
    policy = PaybondPolicy.load(
        {
            "version": 1,
            "name": "ops-v1",
            "default_deny": False,
            "tools": {
                "book_hotel": {
                    "side_effecting": True,
                    "operation": "travel.book_hotel",
                    "evidence_preset": "cost_and_completion",
                }
            },
        }
    )
    registry = policy.to_tool_registry()

    assert registry.resolve_operation("book_hotel") == "travel.book_hotel"
    assert registry.side_effecting_operations() == ["travel.book_hotel"]


def test_paybond_policy_from_document() -> None:
    document = parse_paybond_policy_document_v1(TRAVEL_POLICY)
    policy = PaybondPolicy.from_document(document)
    assert policy.name == "travel-agent-v1"
