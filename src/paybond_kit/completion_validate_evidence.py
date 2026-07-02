"""Local completion evidence JSON Schema validation (signal-only, Harbor-aligned)."""

from __future__ import annotations

from typing import Any, TypedDict

import jsonschema
from jsonschema import ValidationError

from paybond_kit.completion_catalog import get_completion_preset
from paybond_kit.completion_forbidden_fields import (
    forbidden_fields_in_evidence,
    forbidden_fields_in_vendor_payload,
)
from paybond_kit.completion_resolve import (
    is_vendor_pack,
    map_vendor_evidence_to_canonical,
    resolve_completion_preset,
    vendor_evidence_schema,
)


class CompletionEvidenceValidationReport(TypedDict):
    preset_id: str
    vendor_schema_ok: bool
    canonical_schema_ok: bool
    quality_fields_missing: list[str]
    forbidden_fields_present: list[str]
    pack_stale: bool
    drift_kinds: list[str]
    canonical_payload: dict[str, Any] | None


def _push_drift_kind(kinds: list[str], kind: str) -> None:
    if kind not in kinds:
        kinds.append(kind)


def _classify_jsonschema_error(error: ValidationError) -> str:
    message = error.message
    if not list(error.absolute_path) and "required" in message:
        return "missing_field"
    if "required" in message:
        return "missing_field"
    return "type_mismatch"


def _validate_json_schema(schema: dict[str, Any], instance: Any) -> list[str]:
    validator = jsonschema.Draft202012Validator(schema)
    kinds: list[str] = []
    for error in sorted(validator.iter_errors(instance), key=str):
        _push_drift_kind(kinds, _classify_jsonschema_error(error))
    return kinds


def _missing_quality_fields(payload: dict[str, Any], quality_fields: list[str] | None) -> list[str]:
    if not quality_fields:
        return []
    return [field for field in quality_fields if payload.get(field) is None]


def validate_completion_evidence(
    *,
    preset_id: str,
    vendor_payload: dict[str, Any] | None = None,
    canonical_payload: dict[str, Any] | None = None,
    frozen_vendor_api_version: str | None = None,
    frozen_vendor_schema_digest_hex: str | None = None,
    frozen_canonical_schema_digest_hex: str | None = None,
) -> CompletionEvidenceValidationReport:
    preset = get_completion_preset(preset_id)
    resolved = resolve_completion_preset(preset_id)
    contract = preset.get("vendor_contract")
    drift_kinds: list[str] = []
    vendor_schema_ok = True
    canonical_schema_ok = True

    canonical = canonical_payload
    if canonical is None and vendor_payload is not None and is_vendor_pack(preset):
        canonical = map_vendor_evidence_to_canonical(preset, vendor_payload)
    if canonical is None and not is_vendor_pack(preset) and vendor_payload is not None:
        canonical = vendor_payload

    pack_stale = False
    if (
        frozen_vendor_api_version
        and isinstance(contract, dict)
        and contract.get("api_version")
        and frozen_vendor_api_version != contract["api_version"]
    ):
        pack_stale = True
        _push_drift_kind(drift_kinds, "pack_stale")
    if (
        frozen_vendor_schema_digest_hex
        and isinstance(contract, dict)
        and contract.get("schema_digest_hex")
        and frozen_vendor_schema_digest_hex != contract["schema_digest_hex"]
    ):
        pack_stale = True
        _push_drift_kind(drift_kinds, "pack_stale")
    if (
        frozen_canonical_schema_digest_hex
        and isinstance(contract, dict)
        and contract.get("canonical_schema_digest_hex")
        and frozen_canonical_schema_digest_hex != contract["canonical_schema_digest_hex"]
    ):
        pack_stale = True
        _push_drift_kind(drift_kinds, "pack_stale")

    if canonical is not None:
        for kind in _validate_json_schema(resolved["evidence_schema"], canonical):
            canonical_schema_ok = False
            _push_drift_kind(drift_kinds, kind)
    elif not is_vendor_pack(preset):
        canonical_schema_ok = False
        _push_drift_kind(drift_kinds, "missing_field")

    vendor_schema = vendor_evidence_schema(preset)
    if is_vendor_pack(preset):
        if vendor_payload is not None and vendor_schema is not None and not pack_stale:
            for kind in _validate_json_schema(vendor_schema, vendor_payload):
                vendor_schema_ok = False
                _push_drift_kind(drift_kinds, kind)
        elif vendor_payload is None:
            vendor_schema_ok = False
            _push_drift_kind(drift_kinds, "missing_field")

    quality_fields = contract.get("quality_fields") if isinstance(contract, dict) else None
    quality_target = vendor_payload if vendor_payload is not None else canonical
    quality_missing: list[str] = []
    if isinstance(quality_target, dict) and isinstance(quality_fields, list):
        quality_missing = _missing_quality_fields(quality_target, [str(field) for field in quality_fields])
        for _field in quality_missing:
            _push_drift_kind(drift_kinds, "quality_field_missing")

    forbidden = preset.get("forbidden_evidence_fields")
    forbidden_list = [str(field) for field in forbidden] if isinstance(forbidden, list) else None
    forbidden_hits: list[str] = []
    if forbidden_list:
        if isinstance(vendor_payload, dict):
            forbidden_hits.extend(
                forbidden_fields_in_vendor_payload(preset, vendor_payload, forbidden_list)
            )
        if isinstance(canonical, dict):
            for field in forbidden_fields_in_evidence(canonical, forbidden_list):
                if field not in forbidden_hits:
                    forbidden_hits.append(field)
    for _field in forbidden_hits:
        if is_vendor_pack(preset) and isinstance(vendor_payload, dict):
            vendor_schema_ok = False
        if isinstance(canonical, dict):
            canonical_schema_ok = False
        _push_drift_kind(drift_kinds, "forbidden_field_present")

    return {
        "preset_id": preset_id,
        "vendor_schema_ok": vendor_schema_ok,
        "canonical_schema_ok": canonical_schema_ok,
        "quality_fields_missing": quality_missing,
        "forbidden_fields_present": forbidden_hits,
        "pack_stale": pack_stale,
        "drift_kinds": drift_kinds,
        "canonical_payload": canonical,
    }
