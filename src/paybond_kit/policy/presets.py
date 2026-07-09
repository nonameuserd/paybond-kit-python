"""Bundled vertical policy presets (travel, shopping, etc.)."""

from __future__ import annotations

import os
from pathlib import Path

from paybond_kit.policy.compose import compose_bundled_preset_default, compose_layered_policy_preset_document, is_layered_policy_preset
from paybond_kit.policy.parse_text import parse_policy_document_text
from paybond_kit.policy.schema import PaybondPolicyDocumentV1, parse_paybond_policy_document_v1

KNOWN_POLICY_PRESET_IDS = (
    "travel",
    "shopping",
    "saas",
    "aws",
    "stripe-commerce",
    "read-only",
    "strict",
)

PolicyPresetId = str
LayeredPolicyPresetId = str


def _preset_candidate_paths(preset_id: str) -> list[Path]:
    file_name = f"{preset_id}.yaml"
    module_dir = Path(__file__).resolve().parent
    roots = [
        module_dir.parent / "data" / "policy" / "presets",
        module_dir.parents[3] / "policy" / "presets",
        module_dir.parents[2] / "policy" / "presets",
    ]
    paths = [root / file_name for root in roots]
    env_root = os.environ.get("PAYBOND_POLICY_PRESETS_DIR", "").strip()
    if env_root:
        paths.insert(0, Path(env_root) / file_name)
    return paths


def is_known_policy_preset_id(value: str) -> bool:
    """True when ``value`` is a bundled vertical policy preset id (not a file path)."""
    return value.strip() in KNOWN_POLICY_PRESET_IDS


def list_policy_preset_ids() -> tuple[str, ...]:
    """List bundled vertical policy preset ids shipped with paybond-kit."""
    return KNOWN_POLICY_PRESET_IDS


def resolve_policy_preset_path(preset_id: str) -> str:
    """Resolve a bundled preset id to an on-disk paybond.policy.yaml path."""
    trimmed = preset_id.strip()
    if not is_known_policy_preset_id(trimmed):
        raise ValueError(f"unknown policy preset: {trimmed}")
    for candidate in _preset_candidate_paths(trimmed):
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(f"policy preset file not found for: {trimmed}")


def is_layered_policy_preset_id(value: str) -> bool:
    return is_layered_policy_preset(value.strip())


def read_policy_preset_yaml(preset_id: str) -> str:
    """Load a bundled vertical policy preset as YAML text."""
    path = resolve_policy_preset_path(preset_id)
    return Path(path).read_text(encoding="utf-8")


def resolve_composed_preset_document(preset_id: str) -> PaybondPolicyDocumentV1:
    trimmed = preset_id.strip()
    if not is_known_policy_preset_id(trimmed):
        raise ValueError(f"unknown policy preset: {trimmed}")
    if is_layered_policy_preset(trimmed):
        return compose_bundled_preset_default(trimmed)
    flat_path = resolve_policy_preset_path(trimmed)
    return parse_paybond_policy_document_v1(
        parse_policy_document_text(read_policy_preset_yaml(trimmed), source_label=flat_path)
    )


def read_composed_preset_yaml_object(preset_id: str) -> dict[str, object]:
    return compose_layered_policy_preset_document(preset_id)
