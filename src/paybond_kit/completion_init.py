"""Scaffold completion evidence helpers from the shared preset catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from paybond_kit.completion_catalog import (
    CompletionPreset,
    get_completion_preset,
    list_completion_preset_ids,
)
from paybond_kit.completion_resolve import is_vendor_pack, resolve_completion_preset, vendor_evidence_schema


def _schema_property_to_py_type(schema: dict[str, Any]) -> str:
    prop_type = schema.get("type")
    if prop_type in ("integer", "number"):
        return "int"
    if prop_type == "array":
        items = schema.get("items")
        if isinstance(items, dict) and items.get("type") == "string":
            return "list[str]"
        return "list[Any]"
    return "str"


def _required_fields(preset: CompletionPreset) -> list[str]:
    vendor_schema = vendor_evidence_schema(preset)
    schema = vendor_schema if is_vendor_pack(preset) and vendor_schema else preset["evidence_schema"]
    required = schema.get("required")
    if isinstance(required, list):
        return [str(field) for field in required]
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return list(properties.keys())
    return []


def _canonical_required_fields(preset: CompletionPreset) -> list[str]:
    required = preset["evidence_schema"].get("required")
    if isinstance(required, list):
        return [str(field) for field in required]
    properties = preset["evidence_schema"].get("properties")
    if isinstance(properties, dict):
        return list(properties.keys())
    return []


def _evidence_comments(preset: CompletionPreset) -> str:
    required = _required_fields(preset)
    lines = [
        f"# Preset: {preset['preset_id']} ({preset['title']})",
    ]
    if is_vendor_pack(preset):
        lines.append(f"# Vendor pack over archetype: {preset.get('archetype_preset_id')}")
    else:
        lines.append(f"# Harbor template: {preset['harbor_template_id']}")
    lines.extend(
        [
            f"# {preset['human_summary']}",
            "# Map each paid-tool operation to the evidence fields below before submit_completion_evidence(...).",
        ]
    )
    if required:
        lines.append(f"# Required evidence fields: {', '.join(required)}")
    lines.extend(
        [
            "# Sandbox: bootstrap with completion_preset to evaluate a strong Harbor predicate on evidence submit.",
            "# Production: publish the managed template head, then create intents with policy_binding (signing v5).",
            "#   paybond policy templates",
            f"#   paybond policy preview --template {preset['harbor_template_id']} "
            "--parameters-file parameters.json --evidence-file evidence.json",
        ]
    )
    return "\n".join(lines)


def _template(preset: CompletionPreset) -> str:
    resolved = resolve_completion_preset(preset["preset_id"])
    vendor_schema = vendor_evidence_schema(preset)
    schema_for_fields = vendor_schema if is_vendor_pack(preset) and vendor_schema else preset["evidence_schema"]
    properties = schema_for_fields.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}
    required = _required_fields(preset)
    field_lines = []
    dict_lines = []
    for field in required:
        prop = properties.get(field, {"type": "string"})
        if not isinstance(prop, dict):
            prop = {"type": "string"}
        field_lines.append(f"    {field}: {_schema_property_to_py_type(prop)}")
        dict_lines.append(f'        "{field}": fields.{field},')

    canonical_properties = preset["evidence_schema"].get("properties", {})
    if not isinstance(canonical_properties, dict):
        canonical_properties = {}
    canonical_lines = []
    for field in _canonical_required_fields(preset):
        prop = canonical_properties.get(field, {"type": "string"})
        if not isinstance(prop, dict):
            prop = {"type": "string"}
        canonical_lines.append(f"    {field}: {_schema_property_to_py_type(prop)}")

    recommended = preset.get("recommended_amount_cents", 500)
    comments = _evidence_comments(preset)
    evidence_schema = json.dumps(preset["evidence_schema"], indent=4)
    parameters = json.dumps(resolved["parameters"], indent=4)
    sample_source = preset.get("vendor_sample_evidence") if is_vendor_pack(preset) else preset["sample_evidence"]
    sample_evidence = json.dumps(sample_source, indent=4)
    archetype_line = (
        f'ARCHETYPE_PRESET_ID = "{preset.get("archetype_preset_id")}"\n'
        if is_vendor_pack(preset)
        else ""
    )
    vendor_contract = preset.get("vendor_contract")
    vendor_contract_exports = ""
    if is_vendor_pack(preset) and isinstance(vendor_contract, dict):
        quality_fields = vendor_contract.get("quality_fields", [])
        quality_literal = json.dumps(quality_fields, indent=4)
        vendor_contract_exports = f'''
VENDOR_CONTRACT_API_VERSION = "{vendor_contract.get("api_version", "")}"
VENDOR_SCHEMA_DIGEST_HEX = "{vendor_contract.get("schema_digest_hex", "")}"
CANONICAL_SCHEMA_DIGEST_HEX = "{vendor_contract.get("canonical_schema_digest_hex", "")}"
VENDOR_QUALITY_FIELDS: tuple[str, ...] = tuple({quality_literal})
'''
    vendor_helpers = ""
    build_fn = f'''def build_completion_evidence(fields: CompletionEvidence) -> dict[str, Any]:
    return {{
{chr(10).join(dict_lines)}
    }}'''
    evidence_class_name = "CompletionEvidence"
    if is_vendor_pack(preset):
        field_map = json.dumps(preset.get("evidence_field_map") or {}, indent=4)
        vendor_helpers = f'''

@dataclass(frozen=True)
class VendorEvidence:
{chr(10).join(field_lines)}


def map_vendor_evidence_to_canonical(fields: VendorEvidence) -> dict[str, Any]:
    field_map: dict[str, str] = {field_map}
    out: dict[str, Any] = {{}}
    for vendor_key, value in fields.__dict__.items():
        canonical_key = field_map.get(vendor_key, vendor_key)
        out[canonical_key] = value
    return out
'''
        build_fn = '''def build_completion_evidence(fields: VendorEvidence) -> dict[str, Any]:
    return map_vendor_evidence_to_canonical(fields)'''
        evidence_class_name = "VendorEvidence"
        field_lines = canonical_lines
        submit_fn = '''async def submit_completion_evidence(
    paybond: Paybond,
    guardrail: SandboxGuardrailBootstrapResult,
    evidence: VendorEvidence,
    *,
    operation: str | None = None,
    requested_spend_cents: int | None = None,
    artifacts: list[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> SandboxGuardrailEvidenceResult:
    vendor_payload = {key: value for key, value in evidence.__dict__.items()}
    return await paybond.guardrails.submit_sandbox_evidence(
        guardrail.intent_id,
        build_completion_evidence(evidence),
        vendor_payload=vendor_payload,
        artifacts=artifacts,
        operation=operation if operation is not None else guardrail.operation,
        requested_spend_cents=(
            requested_spend_cents if requested_spend_cents is not None else guardrail.requested_spend_cents
        ),
        metadata=metadata,
        idempotency_key=idempotency_key,
    )'''
    else:
        submit_fn = f'''async def submit_completion_evidence(
    paybond: Paybond,
    guardrail: SandboxGuardrailBootstrapResult,
    evidence: {evidence_class_name},
    *,
    operation: str | None = None,
    requested_spend_cents: int | None = None,
    artifacts: list[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> SandboxGuardrailEvidenceResult:
    return await paybond.guardrails.submit_sandbox_evidence(
        guardrail.intent_id,
        build_completion_evidence(evidence),
        artifacts=artifacts,
        operation=operation if operation is not None else guardrail.operation,
        requested_spend_cents=(
            requested_spend_cents if requested_spend_cents is not None else guardrail.requested_spend_cents
        ),
        metadata=metadata,
        idempotency_key=idempotency_key,
    )'''

    return f'''from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from paybond_kit import Paybond, SandboxGuardrailBootstrapResult, SandboxGuardrailEvidenceResult

{comments}

COMPLETION_PRESET_ID = "{preset['preset_id']}"
HARBOR_TEMPLATE_ID = "{resolved['harbor_template_id']}"
{archetype_line}{vendor_contract_exports}
completion_evidence_schema: dict[str, Any] = {evidence_schema}

completion_template_parameters: dict[str, Any] = {parameters}

sample_completion_evidence: dict[str, Any] = {sample_evidence}
{vendor_helpers}

@dataclass(frozen=True)
class CompletionEvidence:
{chr(10).join(field_lines)}


{build_fn}


# Production: use paybond.intents.create_with_policy_binding after publishing {preset['harbor_template_id']}.
policy_binding_stub = {{
    "template_id": HARBOR_TEMPLATE_ID,
    "parameters": completion_template_parameters,
    # "head_seq" and "digest_hex" are assigned after: paybond policy publish ...
}}

DEFAULT_OPERATION = "paid_tool.operation"
DEFAULT_REQUESTED_SPEND_CENTS = {recommended}


def _read_env_value(body: str, key: str) -> str | None:
    prefix = f"{{key}}="
    export_prefix = f"export {{key}}="
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith(export_prefix):
            value = line[len(export_prefix):].strip()
        elif line.startswith(prefix):
            value = line[len(prefix):].strip()
        else:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\\"":
            value = value[1:-1]
        return value.strip() or None
    return None


def load_paybond_env_file(env_file: str = ".env.local") -> None:
    if os.environ.get("PAYBOND_API_KEY", "").strip():
        return
    path = Path(env_file)
    try:
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    api_key = _read_env_value(body, "PAYBOND_API_KEY")
    if api_key:
        os.environ["PAYBOND_API_KEY"] = api_key


async def open_paybond_from_env(env_file: str | None = ".env.local") -> Paybond:
    if env_file is not None:
        load_paybond_env_file(env_file)
    api_key = os.environ.get("PAYBOND_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("PAYBOND_API_KEY is required; run paybond login or configure your agent host to pass it")
    return await Paybond.open(
        api_key=api_key,
        gateway_base_url=(
            os.environ.get("PAYBOND_GATEWAY_URL")
            or os.environ.get("PAYBOND_GATEWAY_BASE_URL")
            or "https://api.paybond.ai"
        ),
        expected_environment="sandbox",
    )


async def bootstrap_sandbox_guardrail_intent(
    paybond: Paybond,
    *,
    operation: str = DEFAULT_OPERATION,
    requested_spend_cents: int = DEFAULT_REQUESTED_SPEND_CENTS,
    currency: str = "usd",
    metadata: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> SandboxGuardrailBootstrapResult:
    return await paybond.guardrails.bootstrap_sandbox(
        operation=operation,
        requested_spend_cents=requested_spend_cents,
        currency=currency,
        evidence_schema=completion_evidence_schema,
        completion_preset=COMPLETION_PRESET_ID,
        metadata=metadata,
        idempotency_key=idempotency_key,
    )


{submit_fn}
'''


def scaffold_completion_init(*, preset_id: str, out: Path, force: bool = False) -> None:
    preset = get_completion_preset(preset_id)
    if out.exists() and not force:
        raise FileExistsError(f"{out} already exists; pass --force to overwrite")
    out.write_text(_template(preset), encoding="utf-8")


def run_completion_init(argv: list[str] | None = None) -> int:
    presets = list_completion_preset_ids()
    parser = argparse.ArgumentParser(
        description="Scaffold a completion evidence helper aligned with the shared preset catalog."
    )
    parser.add_argument("--preset", choices=presets, required=True)
    parser.add_argument("--out", default="")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    out = Path(args.out or f"paybond_completion_{args.preset}.py")
    try:
        scaffold_completion_init(preset_id=args.preset, out=out, force=args.force)
    except FileExistsError as exc:
        parser.error(str(exc))
    print(f"Created Paybond completion integration: {out}")
    return 0
