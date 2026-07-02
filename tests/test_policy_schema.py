from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from paybond_kit.policy.schema import (
    PAYBOND_POLICY_SCHEMA_VERSION,
    PaybondPolicyValidationError,
    load_policy_json_schema,
    parse_paybond_policy_document,
    parse_paybond_policy_document_v1,
    policy_document_to_dict,
    policy_schema_path,
    validate_paybond_policy_jsonschema,
)

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"

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


def test_policy_schema_file_matches_repo_copy() -> None:
    repo_schema = (POLICY_DIR / "policy.schema.json").read_text(encoding="utf-8")
    bundled_schema = policy_schema_path().read_text(encoding="utf-8")
    assert bundled_schema == repo_schema


def test_policy_json_schema_is_valid_meta_schema() -> None:
    schema = load_policy_json_schema()
    jsonschema.Draft202012Validator.check_schema(schema)


def test_parse_travel_policy_example() -> None:
    doc = parse_paybond_policy_document(TRAVEL_POLICY)
    assert doc.version == PAYBOND_POLICY_SCHEMA_VERSION
    assert doc.name == "travel-agent-v1"
    assert doc.default_deny is True
    assert doc.tools["travel.book_hotel"].evidence_preset == "cost_and_completion"
    assert doc.intent is not None
    assert doc.intent.allowed_tools == ("travel.book_hotel",)


def test_parse_rejects_unsupported_version() -> None:
    invalid = dict(TRAVEL_POLICY)
    invalid["version"] = 99
    with pytest.raises(PaybondPolicyValidationError, match="version must be 1 or 2"):
        parse_paybond_policy_document(invalid)


def test_parse_v2_org_base_policy() -> None:
    doc = parse_paybond_policy_document(
        {
            "version": 2,
            "name": "acme-agent-spend-v1",
            "default_deny": True,
            "tools": {
                "travel.book_hotel": {
                    "side_effecting": True,
                    "max_spend_cents": 20000,
                    "evidence_preset": "cost_and_completion",
                }
            },
        }
    )
    assert doc.version == 2
    assert getattr(doc, "extends", None) is None


def test_parse_v2_tenant_overlay() -> None:
    doc = parse_paybond_policy_document(
        {
            "version": 2,
            "name": "acme-travel-tenant-east",
            "extends": {
                "org_policy_id": "acme-agent-spend-v1",
                "org_id": "org_acme_corp",
            },
            "default_deny": True,
            "overrides": {
                "tools": {
                    "travel.book_hotel": {"max_spend_cents": 15000},
                }
            },
            "tools": {},
        }
    )
    assert doc.version == 2
    assert doc.extends is not None
    assert doc.extends.org_id == "org_acme_corp"


def test_parse_requires_evidence_preset_for_side_effecting_tools() -> None:
    invalid = {
        "version": 1,
        "name": "travel-agent-v1",
        "default_deny": True,
        "tools": {
            "travel.book_hotel": {
                "side_effecting": True,
                "max_spend_cents": 20000,
            }
        },
    }
    with pytest.raises(PaybondPolicyValidationError, match="evidence_preset"):
        parse_paybond_policy_document(invalid)


def test_parse_rejects_conflicting_spend_fields() -> None:
    invalid = {
        "version": 1,
        "name": "travel-agent-v1",
        "default_deny": True,
        "tools": {
            "travel.book_hotel": {
                "side_effecting": True,
                "evidence_preset": "cost_and_completion",
                "max_spend_cents": 100,
                "spend_from_args": "estimated_price_cents",
            }
        },
    }
    with pytest.raises(PaybondPolicyValidationError, match="mutually exclusive"):
        parse_paybond_policy_document(invalid)


def test_validate_paybond_policy_jsonschema_accepts_example() -> None:
    validate_paybond_policy_jsonschema(TRAVEL_POLICY)  # type: ignore[arg-type]


def test_policy_document_round_trip() -> None:
    doc = parse_paybond_policy_document_v1(TRAVEL_POLICY)
    assert policy_document_to_dict(doc) == TRAVEL_POLICY


def test_example_validates_against_repo_json_schema() -> None:
    schema = json.loads((POLICY_DIR / "policy.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=TRAVEL_POLICY, schema=schema)
