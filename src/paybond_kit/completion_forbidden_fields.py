"""Detect rail-owned fields that must not appear in completion evidence payloads."""

from __future__ import annotations

from typing import Any

from paybond_kit.completion_catalog import CompletionPreset


def forbidden_fields_in_evidence(
    evidence: dict[str, Any] | None,
    forbidden: list[str] | None,
) -> list[str]:
    if not evidence or not forbidden:
        return []
    blocked = set(forbidden)
    return [key for key in evidence if key in blocked]


def forbidden_fields_in_vendor_payload(
    preset: CompletionPreset,
    vendor_payload: dict[str, Any] | None,
    forbidden: list[str] | None,
) -> list[str]:
    if not vendor_payload or not forbidden:
        return []
    blocked = set(forbidden)
    field_map = preset.get("evidence_field_map") or {}
    mapped = field_map if isinstance(field_map, dict) else {}
    hits: list[str] = []
    for vendor_key in vendor_payload:
        canonical_key = mapped.get(vendor_key, vendor_key)
        if vendor_key in blocked or canonical_key in blocked:
            if vendor_key not in hits:
                hits.append(vendor_key)
    return hits
