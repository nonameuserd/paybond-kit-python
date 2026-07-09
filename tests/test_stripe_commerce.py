import pytest
from pathlib import Path

from paybond_kit.json_digest import json_value_digest
from paybond_kit.policy.init import ScaffoldPolicyFromPresetOptions, scaffold_policy_from_preset
from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.presets import (
    is_known_policy_preset_id,
    list_policy_preset_ids,
    read_policy_preset_yaml,
    resolve_composed_preset_document,
    resolve_policy_preset_path,
)
from paybond_kit.solution_catalog import (
    get_solution_smoke_defaults,
    is_known_solution_id,
    list_solution_ids,
    load_solution_manifest,
)
from paybond_kit.stripe_commerce import (
    PAYBOND_STRIPE_METADATA_INTENT_ID_KEY,
    PAYBOND_STRIPE_METADATA_RAIL_KEY,
    PAYBOND_STRIPE_METADATA_TENANT_ID_KEY,
    assert_not_stripe_funding_webhook,
    build_paybond_stripe_metadata,
    map_stripe_tool_result_to_evidence,
)

SAMPLE_TOOL_RESULT = {
    "payment_intent_id": "pi_3NxExample",
    "charge_id": "ch_3NxExample",
    "cost_cents": 1250,
    "status": "succeeded",
}


def test_build_paybond_stripe_metadata_shape() -> None:
    metadata = build_paybond_stripe_metadata(
        {
            "tenant_id": "tenant-a",
            "intent_id": "00000000-0000-0000-0000-000000000111",
        }
    )
    assert metadata == {
        PAYBOND_STRIPE_METADATA_TENANT_ID_KEY: "tenant-a",
        PAYBOND_STRIPE_METADATA_INTENT_ID_KEY: "00000000-0000-0000-0000-000000000111",
    }


def test_build_paybond_stripe_metadata_includes_rail() -> None:
    metadata = build_paybond_stripe_metadata(
        {
            "tenant_id": "tenant-a",
            "intent_id": "00000000-0000-0000-0000-000000000111",
            "rail": "stripe_connect",
        }
    )
    assert metadata[PAYBOND_STRIPE_METADATA_RAIL_KEY] == "stripe_connect"


def test_build_paybond_stripe_metadata_rejects_invalid_rail() -> None:
    with pytest.raises(ValueError, match="rail must be stripe_connect or stripe_ach_debit"):
        build_paybond_stripe_metadata(
            {
                "tenant_id": "tenant-a",
                "intent_id": "00000000-0000-0000-0000-000000000111",
                "rail": "stripe_mpp",  # type: ignore[typeddict-item]
            }
        )


def test_map_stripe_tool_result_to_stripe_charge_evidence() -> None:
    evidence = map_stripe_tool_result_to_evidence(SAMPLE_TOOL_RESULT, {"preset": "stripe_charge"})
    expected_digest = (
        "blake3:"
        + json_value_digest({"charge_id": "ch_3NxExample", "cost_cents": 1250}).hex()
    )
    assert evidence == {
        "charge_id": "ch_3NxExample",
        "http_status": 200,
        "response_digest": expected_digest,
    }


def test_map_stripe_tool_result_to_cost_and_completion_evidence() -> None:
    evidence = map_stripe_tool_result_to_evidence(
        SAMPLE_TOOL_RESULT,
        {"preset": "cost_and_completion"},
    )
    assert evidence == {"status": "completed", "cost_cents": 1250}


def test_assert_not_stripe_funding_webhook_rejects_event_envelope() -> None:
    with pytest.raises(ValueError, match="funding signals"):
        assert_not_stripe_funding_webhook(
            {
                "id": "evt_123",
                "type": "payment_intent.succeeded",
                "data": {
                    "object": {
                        "id": "pi_123",
                        "metadata": {
                            "tenant_id": "tenant-a",
                            "paybond_intent_id": "00000000-0000-0000-0000-000000000111",
                        },
                    }
                },
            }
        )


def test_map_stripe_tool_result_rejects_webhook_envelope() -> None:
    with pytest.raises(ValueError, match="data.object envelopes are funding signals"):
        map_stripe_tool_result_to_evidence(
            {
                "data": {
                    "object": {
                        "id": "pi_1",
                        "metadata": {"tenant_id": "tenant-a"},
                    }
                }
            },
            {"preset": "stripe_charge"},
        )


def test_stripe_commerce_preset_and_solution_registered() -> None:
    assert is_known_policy_preset_id("stripe-commerce")
    assert is_known_solution_id("stripe-commerce")
    assert "stripe-commerce" in list_policy_preset_ids()
    assert "stripe-commerce" in list_solution_ids()


def test_stripe_commerce_preset_loads_stripe_charge_policy() -> None:
    path = resolve_policy_preset_path("stripe-commerce")
    assert path.endswith("stripe-commerce.yaml")

    yaml_text = read_policy_preset_yaml("stripe-commerce")
    assert "payments.charge_customer:" in yaml_text
    assert "evidence_preset: stripe_charge" in yaml_text

    document = resolve_composed_preset_document("stripe-commerce")
    assert document.name == "stripe-commerce-agent-v1"
    charge_tool = document.tools["payments.charge_customer"]
    assert charge_tool.evidence_preset == "stripe_charge"
    assert document.intent is not None
    assert document.intent.budget is not None
    budget = document.intent.budget
    max_spend = budget["max_spend_usd"] if isinstance(budget, dict) else budget.max_spend_usd
    assert max_spend == 500


def test_stripe_commerce_solution_smoke_defaults() -> None:
    manifest = load_solution_manifest("stripe-commerce")
    assert manifest["id"] == "stripe-commerce"
    assert manifest["primary_operation"] == "payments.charge_customer"
    assert manifest["completion_preset"] == "stripe_charge"

    smoke = get_solution_smoke_defaults("stripe-commerce")
    assert smoke["operation"] == "payments.charge_customer"
    assert smoke["requested_spend_cents"] == 2500
    assert smoke["evidence_preset"] == "stripe_charge"
    assert smoke["result_body"] == {
        "payment_intent_id": "pi_smoke",
        "charge_id": "ch_smoke",
        "cost_cents": 2500,
        "status": "succeeded",
    }


def test_scaffold_stripe_commerce_policy_from_preset(tmp_path: Path) -> None:
    out = tmp_path / "paybond.policy.yaml"
    result = scaffold_policy_from_preset(
        ScaffoldPolicyFromPresetOptions(out=out, preset_id="stripe-commerce")
    )
    assert result["preset"] == "stripe-commerce"
    assert result["name"] == "stripe-commerce-agent-v1"
    policy = PaybondPolicy.load(str(out))
    assert "payments.charge_customer" in policy.document.tools
