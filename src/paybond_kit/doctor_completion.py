"""Doctor checks for completion catalog alignment."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from paybond_kit.completion_catalog import CompletionPreset, load_completion_catalog
from paybond_kit.completion_resolve import (
    completion_preset_deprecation_warning,
    is_vendor_pack,
    resolve_completion_preset,
    vendor_evidence_schema,
)

GatewayGetter = Callable[[str], dict[str, Any]]

STRIPE_FUNDING_WEBHOOK_EVENT_TYPES = frozenset(
    {"payment_intent.succeeded", "charge.succeeded"},
)

_SCAFFOLD_PATTERNS = (
    re.compile(r"^paybond-completion-[\w-]+\.(ts|js|py)$"),
    re.compile(r"^paybond-paid-tool-guard\.(ts|js|py)$"),
    re.compile(r"^paybond_completion_[\w]+\.py$"),
)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def _schema_property_keys(schema: dict[str, Any] | None) -> list[str]:
    if not schema:
        return []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return list(properties.keys())
    return []


def _forbidden_field_hits(property_keys: list[str], forbidden: list[str] | None) -> list[str]:
    if not forbidden:
        return []
    blocked = set(forbidden)
    return [key for key in property_keys if key in blocked]


def _vendor_schema_forbidden_hits(
    preset: CompletionPreset,
    vendor_schema: dict[str, Any] | None,
    forbidden: list[str] | None,
) -> list[str]:
    if not vendor_schema:
        return []
    field_map = preset.get("evidence_field_map") or {}
    mapped = field_map if isinstance(field_map, dict) else {}
    unmapped_vendor_keys = [
        key for key in _schema_property_keys(vendor_schema) if key not in mapped
    ]
    return _forbidden_field_hits(unmapped_vendor_keys, forbidden)


def is_stripe_funding_webhook_event_type(event_type: Any) -> bool:
    return isinstance(event_type, str) and event_type in STRIPE_FUNDING_WEBHOOK_EVENT_TYPES


def _find_completion_scaffolds(cwd: Path) -> list[Path]:
    if not cwd.is_dir():
        return []
    return [path for path in cwd.iterdir() if any(pattern.match(path.name) for pattern in _SCAFFOLD_PATTERNS)]


def _extract_preset_id(body: str) -> str | None:
    ts_match = re.search(r'export const COMPLETION_PRESET_ID = "([^"]+)"', body)
    if ts_match:
        return ts_match.group(1)
    py_match = re.search(r'^COMPLETION_PRESET_ID = "([^"]+)"', body, re.MULTILINE)
    return py_match.group(1) if py_match else None


def _extract_template_parameters(body: str) -> dict[str, Any] | None:
    ts_match = re.search(
        r"export const completionTemplateParameters = (\{[\s\S]*?\}) as const;",
        body,
    )
    if ts_match:
        try:
            parsed = json.loads(ts_match.group(1))
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    py_match = re.search(
        r"^completion_template_parameters: dict\[str, Any\] = (\{[\s\S]*?\})\n\n",
        body,
        re.MULTILINE,
    )
    if py_match:
        try:
            parsed = json.loads(py_match.group(1).replace("'", '"'))
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _extract_evidence_schema(body: str) -> dict[str, Any] | None:
    ts_match = re.search(
        r"export const completionEvidenceSchema = (\{[\s\S]*?\}) as const;",
        body,
    )
    if ts_match:
        try:
            parsed = json.loads(ts_match.group(1))
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    py_match = re.search(
        r"^completion_evidence_schema: dict\[str, Any\] = (\{[\s\S]*?\})\n\n",
        body,
        re.MULTILINE,
    )
    if py_match:
        try:
            parsed = json.loads(py_match.group(1).replace("'", '"'))
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _extract_vendor_contract_pin(body: str) -> dict[str, Any]:
    ts_api = re.search(r'export const VENDOR_CONTRACT_API_VERSION = "([^"]+)"', body)
    py_api = re.search(r'^VENDOR_CONTRACT_API_VERSION = "([^"]+)"', body, re.MULTILINE)
    ts_vendor = re.search(r'export const VENDOR_SCHEMA_DIGEST_HEX = "([^"]+)"', body)
    py_vendor = re.search(r'^VENDOR_SCHEMA_DIGEST_HEX = "([^"]+)"', body, re.MULTILINE)
    ts_canonical = re.search(r'export const CANONICAL_SCHEMA_DIGEST_HEX = "([^"]+)"', body)
    py_canonical = re.search(r'^CANONICAL_SCHEMA_DIGEST_HEX = "([^"]+)"', body, re.MULTILINE)
    ts_quality = re.search(r"export const VENDOR_QUALITY_FIELDS = (\[[\s\S]*?\]) as const;", body)
    py_quality = re.search(
        r"^VENDOR_QUALITY_FIELDS: tuple\[str, \.\.\.\] = tuple\((\[[\s\S]*?\])\)",
        body,
        re.MULTILINE,
    )
    quality_fields: list[str] | None = None
    quality_raw = (ts_quality.group(1) if ts_quality else None) or (py_quality.group(1) if py_quality else None)
    if quality_raw:
        try:
            parsed = json.loads(quality_raw)
            if isinstance(parsed, list):
                quality_fields = [str(field) for field in parsed]
        except json.JSONDecodeError:
            quality_fields = None
    return {
        "api_version": (ts_api.group(1) if ts_api else None) or (py_api.group(1) if py_api else None),
        "vendor_schema_digest": (ts_vendor.group(1) if ts_vendor else None)
        or (py_vendor.group(1) if py_vendor else None),
        "canonical_schema_digest": (ts_canonical.group(1) if ts_canonical else None)
        or (py_canonical.group(1) if py_canonical else None),
        "quality_fields": quality_fields,
    }


def _push_pack_stale_check(
    checks: list[dict[str, Any]],
    warnings: list[str],
    scaffold_count: int,
) -> None:
    if warnings:
        checks.append(
            {
                "name": "completion_pack_stale",
                "ok": True,
                "message": f"warn: {'; '.join(warnings)}",
                "details": {"warnings": warnings},
            }
        )
        return
    checks.append(
        {
            "name": "completion_pack_stale",
            "ok": True,
            "message": (
                "no local completion scaffold files in cwd"
                if scaffold_count == 0
                else "local vendor pack scaffolds match catalog contract pins"
            ),
        }
    )


def _push_quality_fields_check(
    checks: list[dict[str, Any]],
    warnings: list[str],
    scaffold_count: int,
) -> None:
    if warnings:
        checks.append(
            {
                "name": "completion_quality_fields",
                "ok": True,
                "message": f"warn: {'; '.join(warnings)}",
                "details": {"warnings": warnings},
            }
        )
        return
    checks.append(
        {
            "name": "completion_quality_fields",
            "ok": True,
            "message": (
                "no local completion scaffold files in cwd"
                if scaffold_count == 0
                else "vendor pack scaffolds export catalog quality_fields pins"
            ),
        }
    )


def _push_funding_event_misuse_check(
    checks: list[dict[str, Any]],
    warnings: list[str],
    scaffold_count: int,
) -> None:
    if warnings:
        checks.append(
            {
                "name": "completion_funding_event_misuse",
                "ok": True,
                "message": f"warn: {'; '.join(warnings)}",
                "details": {"warnings": warnings},
            }
        )
        return
    checks.append(
        {
            "name": "completion_funding_event_misuse",
            "ok": True,
            "message": (
                "no local completion scaffold files in cwd"
                if scaffold_count == 0
                else "no Stripe funding webhook event types in webhook_confirmed scaffolds or policy heads"
            ),
        }
    )


def run_completion_catalog_doctor_checks(
    *,
    cwd: Path,
    gateway_get: GatewayGetter | None = None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    try:
        catalog = load_completion_catalog()
        checks.append(
            {
                "name": "completion_catalog",
                "ok": True,
                "message": f"catalog v{catalog['version']} loaded ({len(catalog['presets'])} presets)",
            }
        )
    except Exception as exc:  # noqa: BLE001
        checks.append({"name": "completion_catalog", "ok": False, "message": str(exc)})
        return checks

    scaffold_paths = _find_completion_scaffolds(cwd)
    funding_event_warnings: list[str] = []
    pack_stale_warnings: list[str] = []
    quality_field_warnings: list[str] = []
    if not scaffold_paths:
        checks.append(
            {
                "name": "completion_local_scaffold",
                "ok": True,
                "message": "no local completion scaffold files in cwd",
            }
        )
    else:
        divergences: list[str] = []
        deprecated_presets: list[str] = []
        forbidden_field_warnings: list[str] = []
        for scaffold_path in scaffold_paths:
            body = scaffold_path.read_text(encoding="utf-8")
            preset_id = _extract_preset_id(body)
            if not preset_id:
                continue
            deprecation_warning = completion_preset_deprecation_warning(preset_id)
            if deprecation_warning:
                deprecated_presets.append(f"{scaffold_path.name}: {deprecation_warning}")
            try:
                resolved = resolve_completion_preset(preset_id)
            except (KeyError, ValueError):
                divergences.append(f"{scaffold_path.name}: unknown preset {preset_id}")
                continue
            embedded = _extract_evidence_schema(body)
            expected = (
                resolved["preset"]["evidence_schema"]
                if is_vendor_pack(resolved["preset"])
                else resolved["evidence_schema"]
            )
            if embedded and _stable_json(expected) != _stable_json(embedded):
                divergences.append(
                    f"{scaffold_path.name}: evidence_schema diverges from catalog for {preset_id}"
                )

            forbidden = resolved["preset"].get("forbidden_evidence_fields")
            forbidden_list = forbidden if isinstance(forbidden, list) else None
            hits = list(
                dict.fromkeys(
                    _forbidden_field_hits(_schema_property_keys(embedded), forbidden_list)
                    + _vendor_schema_forbidden_hits(
                        resolved["preset"],
                        vendor_evidence_schema(resolved["preset"]),
                        forbidden_list,
                    )
                )
            )
            if hits:
                forbidden_field_warnings.append(
                    f"{scaffold_path.name}: evidence schema includes forbidden field(s) for "
                    f"{preset_id}: {', '.join(hits)}"
                )

            if resolved["harbor_template_id"] == "webhook_confirmation_v1":
                embedded_params = _extract_template_parameters(body)
                expected_event_type = (
                    embedded_params.get("expected_event_type")
                    if isinstance(embedded_params, dict)
                    else None
                )
                if expected_event_type is None:
                    expected_event_type = resolved["parameters"].get("expected_event_type")
                if is_stripe_funding_webhook_event_type(expected_event_type):
                    funding_event_warnings.append(
                        f"{scaffold_path.name}: expected_event_type {expected_event_type} is a Stripe "
                        "funding webhook, not tool-completion evidence"
                    )

            if is_vendor_pack(resolved["preset"]):
                contract = resolved["preset"].get("vendor_contract")
                pin = _extract_vendor_contract_pin(body)
                if isinstance(contract, dict):
                    if not pin.get("api_version"):
                        pack_stale_warnings.append(
                            f"{scaffold_path.name}: missing VENDOR_CONTRACT_API_VERSION pin for "
                            f"{preset_id}; re-run paybond init completion"
                        )
                    elif pin["api_version"] != contract.get("api_version"):
                        pack_stale_warnings.append(
                            f"{scaffold_path.name}: pinned api_version {pin['api_version']} lags catalog "
                            f"{contract.get('api_version')} for {preset_id}"
                        )
                    if (
                        pin.get("vendor_schema_digest")
                        and pin["vendor_schema_digest"] != contract.get("schema_digest_hex")
                    ):
                        pack_stale_warnings.append(
                            f"{scaffold_path.name}: pinned vendor schema digest diverges from catalog for "
                            f"{preset_id}"
                        )
                    if (
                        pin.get("canonical_schema_digest")
                        and pin["canonical_schema_digest"] != contract.get("canonical_schema_digest_hex")
                    ):
                        pack_stale_warnings.append(
                            f"{scaffold_path.name}: pinned canonical schema digest diverges from catalog for "
                            f"{preset_id}"
                        )
                    expected_quality = contract.get("quality_fields")
                    expected_list = (
                        [str(field) for field in expected_quality]
                        if isinstance(expected_quality, list)
                        else []
                    )
                    pin_quality = pin.get("quality_fields")
                    if expected_list and not pin_quality:
                        quality_field_warnings.append(
                            f"{scaffold_path.name}: missing VENDOR_QUALITY_FIELDS export for {preset_id}"
                        )
                    elif isinstance(pin_quality, list) and sorted(pin_quality) != sorted(expected_list):
                        quality_field_warnings.append(
                            f"{scaffold_path.name}: VENDOR_QUALITY_FIELDS diverge from catalog for {preset_id}"
                        )

        if divergences:
            checks.append(
                {
                    "name": "completion_local_scaffold",
                    "ok": True,
                    "message": f"warn: {'; '.join(divergences)}",
                    "details": {"divergences": divergences},
                }
            )
        else:
            checks.append(
                {
                    "name": "completion_local_scaffold",
                    "ok": True,
                    "message": f"checked {len(scaffold_paths)} scaffold file(s); evidence schemas match catalog",
                }
            )

        if deprecated_presets:
            checks.append(
                {
                    "name": "completion_deprecated_preset",
                    "ok": True,
                    "message": f"warn: {'; '.join(deprecated_presets)}",
                    "details": {"warnings": deprecated_presets},
                }
            )
        else:
            checks.append(
                {
                    "name": "completion_deprecated_preset",
                    "ok": True,
                    "message": "no deprecated completion presets in local scaffolds",
                }
            )

        if forbidden_field_warnings:
            checks.append(
                {
                    "name": "completion_forbidden_fields",
                    "ok": True,
                    "message": f"warn: {'; '.join(forbidden_field_warnings)}",
                    "details": {"warnings": forbidden_field_warnings},
                }
            )
        else:
            checks.append(
                {
                    "name": "completion_forbidden_fields",
                    "ok": True,
                    "message": "local scaffold evidence schemas exclude catalog forbidden fields",
                }
            )

    if not scaffold_paths:
        checks.append(
            {
                "name": "completion_deprecated_preset",
                "ok": True,
                "message": "no local completion scaffold files in cwd",
            }
        )
        checks.append(
            {
                "name": "completion_forbidden_fields",
                "ok": True,
                "message": "no local completion scaffold files in cwd",
            }
        )

    _push_pack_stale_check(checks, pack_stale_warnings, len(scaffold_paths))
    _push_quality_fields_check(checks, quality_field_warnings, len(scaffold_paths))

    if gateway_get is None:
        checks.append(
            {
                "name": "completion_policy_heads",
                "ok": True,
                "message": "skipped policy head check (no gateway credentials)",
            }
        )
        _push_funding_event_misuse_check(checks, funding_event_warnings, len(scaffold_paths))
        return checks

    head_warnings: list[str] = []
    for preset in catalog["presets"]:
        if is_vendor_pack(preset) or preset["harbor_template_id"] == "true_v1":
            continue
        try:
            versions = gateway_get(
                f"/harbor/policy/v1/versions?template_id={preset['harbor_template_id']}"
            )
            head_seq = versions.get("current_head_seq")
            if head_seq is None:
                continue
            rows = versions.get("versions")
            if not isinstance(rows, list):
                continue
            head = next(
                (row for row in rows if isinstance(row, dict) and row.get("version_seq") == head_seq),
                None,
            )
            if not isinstance(head, dict):
                continue
            head_params = head.get("parameters")
            if not isinstance(head_params, dict):
                head_params = {}
            if _stable_json(preset["parameters"]) != _stable_json(head_params):
                head_warnings.append(
                    f"{preset['harbor_template_id']} head seq {head_seq} parameters diverge from "
                    f"catalog preset {preset['preset_id']}"
                )
            if preset["harbor_template_id"] == "webhook_confirmation_v1" and is_stripe_funding_webhook_event_type(
                head_params.get("expected_event_type")
            ):
                funding_event_warnings.append(
                    f"{preset['harbor_template_id']} head seq {head_seq} uses Stripe funding event type "
                    f"{head_params.get('expected_event_type')}"
                )
        except Exception as exc:  # noqa: BLE001
            head_warnings.append(
                f"{preset['harbor_template_id']}: could not load policy versions ({exc})"
            )

    if head_warnings:
        checks.append(
            {
                "name": "completion_policy_heads",
                "ok": True,
                "message": f"warn: {'; '.join(head_warnings)}",
                "details": {"warnings": head_warnings},
            }
        )
    else:
        checks.append(
            {
                "name": "completion_policy_heads",
                "ok": True,
                "message": "published policy heads match catalog defaults (or no heads published)",
            }
        )

    _push_funding_event_misuse_check(checks, funding_event_warnings, len(scaffold_paths))
    return checks
