"""Load bundled domain and guardrail YAML layers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from paybond_kit.policy.parse_text import parse_policy_document_text

LAYERED_POLICY_PRESET_IDS = ("travel", "shopping", "saas", "aws")


def _preset_layer_candidate_paths(subdir: str, file_name: str) -> list[Path]:
    module_dir = Path(__file__).resolve().parent
    roots = [
        module_dir / "data" / "policy" / "presets",
        module_dir.parents[3] / "policy" / "presets",
        module_dir.parents[2] / "policy" / "presets",
    ]
    return [root / subdir / file_name for root in roots]


def read_preset_layer_yaml(subdir: str, file_name: str) -> str:
    for candidate in _preset_layer_candidate_paths(subdir, file_name):
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise FileNotFoundError(f"policy preset layer not found: {subdir}/{file_name}")


def load_bundled_domain_document(preset_id: str) -> dict[str, Any]:
    return parse_policy_document_text(
        read_preset_layer_yaml("domain", f"{preset_id}.yaml"),
        source_label=f"domain/{preset_id}.yaml",
    )


def load_bundled_default_guardrails_document(preset_id: str) -> dict[str, Any]:
    return parse_policy_document_text(
        read_preset_layer_yaml("guardrails", f"default-{preset_id}.yaml"),
        source_label=f"guardrails/default-{preset_id}.yaml",
    )
