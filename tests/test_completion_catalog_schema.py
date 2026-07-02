from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from paybond_kit.completion_catalog import (
    get_completion_preset_by_template_id,
    load_completion_catalog,
)
from paybond_kit.completion_contract_digest import verify_catalog_vendor_contracts

CATALOG_DIR = Path(__file__).resolve().parents[2] / "completion-presets"


def test_completion_catalog_validates_json_schema() -> None:
    schema = json.loads((CATALOG_DIR / "catalog.schema.json").read_text(encoding="utf-8"))
    catalog = json.loads((CATALOG_DIR / "catalog.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=catalog, schema=schema)


def test_vendor_pack_presets_have_required_metadata() -> None:
    catalog = load_completion_catalog()
    vendor_packs = [preset for preset in catalog["presets"] if preset.get("kind") == "vendor_pack"]
    assert vendor_packs, "expected at least one vendor_pack preset in catalog"
    for preset in vendor_packs:
        preset_id = preset["preset_id"]
        assert preset.get("scope") == "tool_completion", preset_id
        assert preset.get("archetype_preset_id"), preset_id
        forbidden = preset.get("forbidden_evidence_fields")
        assert forbidden, preset_id
        assert len(forbidden) > 0, preset_id
        assert preset.get("vendor_contract"), preset_id


def test_vendor_pack_vendor_contract_digests() -> None:
    verify_catalog_vendor_contracts(load_completion_catalog())


def test_bundled_catalog_matches_repo_catalog() -> None:
    repo_catalog = (CATALOG_DIR / "catalog.json").read_text(encoding="utf-8")
    bundled_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "paybond_kit"
        / "data"
        / "completion_presets"
        / "catalog.json"
    )
    assert bundled_path.read_text(encoding="utf-8") == repo_catalog


def test_get_completion_preset_by_template_id_prefers_archetype() -> None:
    preset = get_completion_preset_by_template_id("api_response_v1")
    assert preset is not None
    assert preset["preset_id"] == "api_response_ok"
    assert preset.get("kind") != "vendor_pack"
