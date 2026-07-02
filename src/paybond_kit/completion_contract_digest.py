"""BLAKE3 digests for completion preset vendor_contract schema pinning."""

from __future__ import annotations

from typing import Any, TypedDict

from paybond_kit.completion_catalog import CompletionPreset, CompletionPresetCatalog
from paybond_kit.json_digest import json_value_digest


class VendorContractDigests(TypedDict):
    schema_digest_hex: str
    canonical_schema_digest_hex: str


def digest_to_hex(digest: bytes) -> str:
    return digest.hex()


def completion_schema_digest_hex(schema: dict[str, Any]) -> str:
    return digest_to_hex(json_value_digest(schema))


def compute_vendor_contract_digests(
    preset: CompletionPreset,
) -> VendorContractDigests:
    vendor_schema = preset.get("vendor_evidence_schema")
    canonical_schema = preset["evidence_schema"]
    if not isinstance(vendor_schema, dict):
        raise ValueError(f"{preset['preset_id']}: missing vendor_evidence_schema")
    return {
        "schema_digest_hex": completion_schema_digest_hex(vendor_schema),
        "canonical_schema_digest_hex": completion_schema_digest_hex(canonical_schema),
    }


def _vendor_schema_field_names(schema: dict[str, Any]) -> set[str]:
    props = schema.get("properties")
    if not isinstance(props, dict):
        return set()
    return set(props)


def verify_vendor_contract(preset: CompletionPreset) -> None:
    if preset.get("kind") != "vendor_pack":
        return
    preset_id = preset["preset_id"]
    contract = preset.get("vendor_contract")
    if not isinstance(contract, dict):
        raise ValueError(f"{preset_id}: vendor_pack missing vendor_contract")
    vendor_schema = preset.get("vendor_evidence_schema")
    canonical_schema = preset.get("evidence_schema")
    if not isinstance(vendor_schema, dict) or not isinstance(canonical_schema, dict):
        raise ValueError(f"{preset_id}: vendor_pack missing evidence schemas")
    computed = compute_vendor_contract_digests(preset)
    if contract.get("schema_digest_hex") != computed["schema_digest_hex"]:
        raise ValueError(
            f"{preset_id}: vendor_contract.schema_digest_hex mismatch "
            f"(catalog={contract.get('schema_digest_hex')}, computed={computed['schema_digest_hex']})"
        )
    if contract.get("canonical_schema_digest_hex") != computed["canonical_schema_digest_hex"]:
        raise ValueError(
            f"{preset_id}: vendor_contract.canonical_schema_digest_hex mismatch "
            f"(catalog={contract.get('canonical_schema_digest_hex')}, "
            f"computed={computed['canonical_schema_digest_hex']})"
        )
    quality_fields = contract.get("quality_fields")
    if not isinstance(quality_fields, list) or not quality_fields:
        raise ValueError(f"{preset_id}: vendor_contract.quality_fields must be a non-empty array")
    allowed = _vendor_schema_field_names(vendor_schema)
    for field in quality_fields:
        if not isinstance(field, str) or field not in allowed:
            raise ValueError(
                f"{preset_id}: quality_fields entry {field!r} is not a vendor_evidence_schema property"
            )


def verify_catalog_vendor_contracts(catalog: CompletionPresetCatalog) -> None:
    presets = catalog["presets"]
    vendor_packs = [preset for preset in presets if preset.get("kind") == "vendor_pack"]
    if not vendor_packs:
        raise ValueError("catalog must contain at least one vendor_pack preset")
    for preset in vendor_packs:
        verify_vendor_contract(preset)
