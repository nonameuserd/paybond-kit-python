from __future__ import annotations

from pathlib import Path

from paybond_kit.agent.facade import resolve_agent_policy_source


def test_layered_presets_match_flat_files() -> None:
    _ = resolve_agent_policy_source("travel")
    from paybond_kit.policy.compose import assert_layered_preset_matches_flat
    from paybond_kit.policy.presets import list_policy_preset_ids

    for preset_id in list_policy_preset_ids():
        assert_layered_preset_matches_flat(preset_id)


def test_compose_travel_preset_shape() -> None:
    from paybond_kit.policy.compose import compose_layered_policy_preset_document

    composed = compose_layered_policy_preset_document("travel")
    assert composed["name"] == "travel-agent-v1"
    tools = composed["tools"]
    assert isinstance(tools, dict)
    travel_hotel = tools["travel.book_hotel"]
    assert isinstance(travel_hotel, dict)
    assert travel_hotel["max_spend_cents"] == 20000
    assert travel_hotel["evidence_preset"] == "cost_and_completion"
    intent = composed["intent"]
    assert isinstance(intent, dict)
    assert intent["allowed_tools"] == ["travel.book_hotel"]
    assert intent["budget"] == {"currency": "usd", "max_spend_usd": 200}


def test_scaffold_policy_from_preset_writes_header(tmp_path: Path) -> None:
    from paybond_kit.policy.init import ScaffoldPolicyFromPresetOptions, scaffold_policy_from_preset
    from paybond_kit.policy.validate import PolicyValidator

    out = tmp_path / "paybond.policy.yaml"
    result = scaffold_policy_from_preset(
        ScaffoldPolicyFromPresetOptions(out=out, preset_id="travel", force=False)
    )
    assert result["preset"] == "travel"
    assert result["name"] == "travel-agent-v1"
    text = out.read_text(encoding="utf-8")
    assert "Reference implementation — edit freely" in text
    assert "paybond policy init --preset travel --force" in text
    report = PolicyValidator.validate(out)
    assert report.valid is True
