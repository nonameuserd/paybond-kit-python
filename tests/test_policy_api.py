from __future__ import annotations

from paybond_kit.agent.facade import resolve_agent_policy_source


def test_flat_travel_matches_compose_default() -> None:
    from paybond_kit.policy.compose import assert_layered_preset_matches_flat, compose_bundled_preset_default
    from paybond_kit.policy.presets import resolve_composed_preset_document

    assert_layered_preset_matches_flat("travel")
    assert compose_bundled_preset_default("travel") == resolve_composed_preset_document("travel")


def test_policy_presets_travel_matches_flat() -> None:
    from paybond_kit.policy.policy_api import paybond_policy_presets
    from paybond_kit.policy.presets import resolve_composed_preset_document

    _ = resolve_agent_policy_source("travel")
    preset = paybond_policy_presets.travel()
    assert preset.document == resolve_composed_preset_document("travel")


def test_custom_max_spend_tightens_tool_cap() -> None:
    from paybond_kit.policy.policy_api import VerticalPolicyOptions, paybond_policy_presets

    _ = resolve_agent_policy_source("travel")
    preset = paybond_policy_presets.travel(VerticalPolicyOptions(max_spend=5000))
    assert preset.document.tools["travel.book_hotel"].max_spend_cents == 5000


def test_compose_read_only_filters_side_effecting_tools() -> None:
    from paybond_kit.policy.compose import compose_policy_layers
    from paybond_kit.policy.domain import domain
    from paybond_kit.policy.guardrails import read_only

    _ = resolve_agent_policy_source("travel")
    document = compose_policy_layers(domain.travel(), read_only())
    assert "travel.book_hotel" not in document.tools
    assert "search.web" in document.tools
