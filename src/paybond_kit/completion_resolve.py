"""Resolve vendor packs to underlying completion archetypes."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from paybond_kit.completion_catalog import CompletionPreset, get_completion_preset, load_completion_catalog

CompletionPresetKind = Literal["archetype", "vendor_pack"]


class ResolvedCompletionPreset(TypedDict):
    preset: CompletionPreset
    archetype: CompletionPreset
    kind: CompletionPresetKind
    harbor_template_id: str
    parameters: dict[str, Any]
    evidence_schema: dict[str, Any]


def preset_kind(preset: CompletionPreset) -> CompletionPresetKind:
    if preset.get("kind") == "vendor_pack":
        return "vendor_pack"
    return "archetype"


def is_vendor_pack(preset: CompletionPreset) -> bool:
    return preset_kind(preset) == "vendor_pack"


def resolve_completion_preset(preset_id: str) -> ResolvedCompletionPreset:
    preset = get_completion_preset(preset_id)
    if not is_vendor_pack(preset):
        return {
            "preset": preset,
            "archetype": preset,
            "kind": "archetype",
            "harbor_template_id": preset["harbor_template_id"],
            "parameters": preset["parameters"],
            "evidence_schema": preset["evidence_schema"],
        }
    archetype_id = preset.get("archetype_preset_id")
    if not archetype_id:
        raise ValueError(f"vendor pack {preset_id} missing archetype_preset_id")
    archetype = get_completion_preset(archetype_id)
    merged_parameters = {**archetype["parameters"], **preset["parameters"]}
    return {
        "preset": preset,
        "archetype": archetype,
        "kind": "vendor_pack",
        "harbor_template_id": archetype["harbor_template_id"],
        "parameters": merged_parameters,
        "evidence_schema": preset["evidence_schema"],
    }


def map_vendor_evidence_to_canonical(
    preset: CompletionPreset,
    vendor_evidence: dict[str, Any],
) -> dict[str, Any]:
    field_map = preset.get("evidence_field_map") or {}
    out: dict[str, Any] = {}
    for vendor_key, value in vendor_evidence.items():
        canonical_key = field_map.get(vendor_key, vendor_key)
        if canonical_key == "artifact_blake3_hex" and not isinstance(value, list):
            out[canonical_key] = [value]
            continue
        out[canonical_key] = value
    return out


def contract_snapshot_for_preset(preset_id: str) -> dict[str, str | None]:
    from paybond_kit.completion_contract_digest import compute_vendor_contract_digests

    preset = get_completion_preset(preset_id)
    digests = compute_vendor_contract_digests(preset)
    contract = preset.get("vendor_contract")
    if contract:
        return {
            "completion_preset_id": preset["preset_id"],
            "vendor_contract_provider": contract["provider"],
            "vendor_api_version": contract["api_version"],
            "vendor_schema_digest_hex": contract["schema_digest_hex"],
            "canonical_schema_digest_hex": contract["canonical_schema_digest_hex"],
        }
    if preset.get("kind") == "vendor_pack":
        raise ValueError(f"vendor pack {preset_id} missing vendor_contract")
    return {
        "completion_preset_id": preset["preset_id"],
        "vendor_contract_provider": None,
        "vendor_api_version": None,
        "vendor_schema_digest_hex": None,
        "canonical_schema_digest_hex": digests["canonical_schema_digest_hex"],
    }


def completion_preset_deprecation_warning(preset_id: str) -> str | None:
    preset = get_completion_preset(preset_id)
    if not preset.get("deprecated"):
        return None
    replacement = preset.get("superseded_by") or "a newer preset"
    return f"completion preset {preset_id} is deprecated; use {replacement} instead"


def vendor_evidence_schema(preset: CompletionPreset) -> dict[str, Any] | None:
    schema = preset.get("vendor_evidence_schema")
    return schema if isinstance(schema, dict) else None


def list_archetype_preset_ids() -> list[str]:
    return [preset["preset_id"] for preset in load_completion_catalog()["presets"] if not is_vendor_pack(preset)]
