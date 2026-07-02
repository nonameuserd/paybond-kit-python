"""Load the shared completion preset catalog consumed by CLI scaffolding and policy helpers."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, NotRequired, Required, TypedDict, cast

from paybond_kit.completion_catalog_integrity import verify_bundled_completion_catalog_integrity


class SpendHints(TypedDict, total=False):
    approval_threshold_cents: int
    per_tool_max_cents: int


class CompletionPreset(TypedDict, total=False):
    preset_id: Required[str]
    title: Required[str]
    description: Required[str]
    harbor_template_id: Required[str]
    parameters: Required[dict[str, Any]]
    evidence_schema: Required[dict[str, Any]]
    sample_evidence: Required[dict[str, Any]]
    sample_failing_evidence: Required[dict[str, Any]]
    human_summary: Required[str]
    recommended_amount_cents: NotRequired[int]
    spend_hints: NotRequired[SpendHints]
    kind: NotRequired[str]
    archetype_preset_id: NotRequired[str]
    evidence_field_map: NotRequired[dict[str, str]]
    vendor_evidence_schema: NotRequired[dict[str, Any]]
    vendor_sample_evidence: NotRequired[dict[str, Any]]
    scope: NotRequired[str]
    rail_hints: NotRequired[list[str]]
    forbidden_evidence_fields: NotRequired[list[str]]
    anti_patterns: NotRequired[list[str]]
    deprecated: NotRequired[bool]
    superseded_by: NotRequired[str]
    vendor_contract: NotRequired[dict[str, Any]]


class CompletionPresetCatalog(TypedDict):
    version: int
    presets: list[CompletionPreset]


def _catalog_candidate_paths() -> list[Path]:
    module_dir = Path(__file__).resolve().parent
    paths = [
        module_dir / "data" / "completion_presets" / "catalog.json",
        module_dir.parents[3] / "kit" / "completion-presets" / "catalog.json",
        module_dir.parents[2] / "completion-presets" / "catalog.json",
    ]
    env_path = os.environ.get("PAYBOND_COMPLETION_CATALOG", "").strip()
    if env_path:
        paths.insert(0, Path(env_path))
    return paths


@lru_cache(maxsize=1)
def load_completion_catalog() -> CompletionPresetCatalog:
    last_error: Exception | None = None
    for candidate in _catalog_candidate_paths():
        try:
            raw = candidate.read_bytes()
            verify_bundled_completion_catalog_integrity(raw)
            return cast(CompletionPresetCatalog, json.loads(raw.decode("utf-8")))
        except OSError as exc:
            last_error = exc
    raise RuntimeError(
        "completion preset catalog not found "
        f"({', '.join(str(path) for path in _catalog_candidate_paths())}): {last_error}"
    )


def completion_preset_template_row(preset: CompletionPreset) -> dict[str, Any]:
    """Serialize catalog preset metadata for `paybond policy templates` output."""
    return {
        "preset_id": preset["preset_id"],
        "title": preset["title"],
        "harbor_template_id": preset["harbor_template_id"],
        "human_summary": preset["human_summary"],
        "recommended_amount_cents": preset.get("recommended_amount_cents"),
        "kind": preset.get("kind", "archetype"),
        "archetype_preset_id": preset.get("archetype_preset_id"),
        "scope": preset.get("scope"),
        "rail_hints": preset.get("rail_hints"),
        "deprecated": preset.get("deprecated", False),
        "superseded_by": preset.get("superseded_by"),
    }


def list_completion_preset_ids() -> list[str]:
    return [preset["preset_id"] for preset in load_completion_catalog()["presets"]]


def get_completion_preset(preset_id: str) -> CompletionPreset:
    for preset in load_completion_catalog()["presets"]:
        if preset["preset_id"] == preset_id:
            return preset
    raise ValueError(f"unknown completion preset: {preset_id}")


def get_completion_preset_by_template_id(template_id: str) -> CompletionPreset | None:
    matches = [
        preset
        for preset in load_completion_catalog()["presets"]
        if preset["harbor_template_id"] == template_id
    ]
    if not matches:
        return None
    for preset in matches:
        if preset.get("kind") != "vendor_pack":
            return preset
    return matches[0]


def list_completion_presets_by_template_id(template_id: str) -> list[CompletionPreset]:
    return [
        preset
        for preset in load_completion_catalog()["presets"]
        if preset["harbor_template_id"] == template_id
    ]
