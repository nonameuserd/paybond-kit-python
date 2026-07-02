"""Policy preset catalog for CLI list/show commands."""

from __future__ import annotations

from paybond_kit.policy.compose import LAYERED_POLICY_PRESET_IDS
from paybond_kit.policy.guardrail_spec import list_guardrail_catalog_entries
from paybond_kit.policy.presets import is_layered_policy_preset_id, list_policy_preset_ids
from paybond_kit.solution_catalog import list_solution_ids, load_solution_manifest

DOMAIN_TITLES = {
    "travel": "Travel booking",
    "shopping": "Shopping checkout",
    "saas": "SaaS provisioning",
    "aws": "AWS operator",
}


def list_policy_domain_catalog() -> list[dict[str, object]]:
    return [
        {"id": preset_id, "title": DOMAIN_TITLES.get(preset_id, preset_id), "layered": True}
        for preset_id in LAYERED_POLICY_PRESET_IDS
    ]


def list_policy_preset_catalog() -> list[dict[str, object]]:
    return [
        {
            "id": preset_id,
            "kind": "composed" if is_layered_policy_preset_id(preset_id) else "flat",
            "layered": is_layered_policy_preset_id(preset_id),
        }
        for preset_id in list_policy_preset_ids()
    ]


def list_policy_solution_catalog() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for solution_id in list_solution_ids():
        manifest = load_solution_manifest(solution_id)
        rows.append(
            {
                "id": manifest["id"],
                "title": manifest["title"],
                "domain": manifest["policy_default"]["domain"],
                "guardrails": list(manifest["policy_default"]["guardrails"]),
                "primary_operation": manifest["primary_operation"],
            }
        )
    return rows


def list_policy_presets_catalog() -> dict[str, object]:
    return {
        "domains": list_policy_domain_catalog(),
        "guardrails": list_guardrail_catalog_entries(),
        "solutions": list_policy_solution_catalog(),
        "presets": list_policy_preset_catalog(),
    }
