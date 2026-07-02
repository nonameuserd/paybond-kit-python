from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from paybond_kit.completion_catalog import CompletionPresetCatalog, load_completion_catalog
from paybond_kit.completion_contract_digest import verify_catalog_vendor_contracts

CATALOG_DIR = Path(__file__).resolve().parents[2] / "completion-presets"


def test_vendor_contract_digests_match_schemas() -> None:
    catalog = load_completion_catalog()
    verify_catalog_vendor_contracts(catalog)
    vendor_packs = [preset for preset in catalog["presets"] if preset.get("kind") == "vendor_pack"]
    assert len(vendor_packs) == 9
    for preset in vendor_packs:
        contract = preset.get("vendor_contract")
        assert isinstance(contract, dict), preset["preset_id"]
        assert contract.get("quality_fields"), preset["preset_id"]


def test_vendor_contract_declared_in_repo_catalog() -> None:
    catalog = cast(
        CompletionPresetCatalog,
        json.loads((CATALOG_DIR / "catalog.json").read_text(encoding="utf-8")),
    )
    verify_catalog_vendor_contracts(catalog)
