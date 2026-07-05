"""Scaffold starter paybond.policy.yaml files."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path

from paybond_kit.completion_catalog import get_completion_preset
from paybond_kit.policy.parse_text import parse_policy_document_text
from paybond_kit.policy.compose import compose_policy_layers
from paybond_kit.policy.domain import domain
from paybond_kit.policy.guardrail_spec import parse_guardrail_specs
from paybond_kit.policy.presets import is_known_policy_preset_id, resolve_composed_preset_document
from paybond_kit.policy.render_yaml import render_policy_document_yaml
from paybond_kit.policy.schema import PaybondPolicyDocumentV1, PaybondPolicyValidationError

_ORG_ID_RE = re.compile(r"^org_[a-z][a-z0-9_]*$")
_POLICY_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")


@dataclass(frozen=True, slots=True)
class ScaffoldPaybondPolicyOptions:
    out: str | Path
    operation: str
    evidence_preset: str
    force: bool = False


@dataclass(frozen=True, slots=True)
class ScaffoldOrgBasePolicyOptions:
    out: str | Path
    policy_id: str
    operation: str
    evidence_preset: str
    max_spend_cents: int | None = None
    force: bool = False


@dataclass(frozen=True, slots=True)
class ScaffoldTenantOverlayPolicyOptions:
    out: str | Path
    extends_ref: str
    name: str | None = None
    operation: str | None = None
    evidence_preset: str | None = None
    base_policy: str | None = None
    force: bool = False


def parse_policy_extends_ref(ref: str) -> tuple[str, str]:
    """Parse `org_id/org_policy_id` extends reference used by CLI and docs."""
    trimmed = ref.strip()
    slash = trimmed.find("/")
    if slash <= 0 or slash >= len(trimmed) - 1:
        raise PaybondPolicyValidationError(
            "extends must be org_id/org_policy_id (example: org_acme_corp/acme-agent-spend-v1)"
        )
    org_id = trimmed[:slash]
    org_policy_id = trimmed[slash + 1 :]
    if not _ORG_ID_RE.fullmatch(org_id):
        raise PaybondPolicyValidationError(f"org_id must match org_<snake_case>: {org_id}")
    if not _POLICY_NAME_RE.fullmatch(org_policy_id):
        raise PaybondPolicyValidationError(
            f"org_policy_id must be a lowercase policy name: {org_policy_id}"
        )
    return org_id, org_policy_id


def _overlay_name_from_policy_id(org_policy_id: str, explicit: str | None = None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    return org_policy_id if org_policy_id.endswith("-overlay-v1") else f"{org_policy_id}-overlay-v1"


def _policy_name_from_operation(operation: str) -> str:
    slug = (
        operation.strip()
        .lower()
        .replace(".", "-")
        .replace("_", "-")
    )
    slug = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in slug)
    while "--" in slug:
        slug = slug.replace("--", "-")
    slug = slug.strip("-") or "agent"
    return slug if slug.endswith("-v1") else f"{slug}-v1"


def _template_id_stub_for_preset(preset_id: str) -> str:
    try:
        return get_completion_preset(preset_id)["harbor_template_id"]
    except ValueError:
        return "completion_v1"


def render_org_base_policy_yaml(options: ScaffoldOrgBasePolicyOptions) -> str:
    policy_id = options.policy_id.strip()
    operation = options.operation.strip()
    evidence_preset = options.evidence_preset.strip()
    if not policy_id:
        raise PaybondPolicyValidationError("policy_id is required")
    if not _POLICY_NAME_RE.fullmatch(policy_id):
        raise PaybondPolicyValidationError("policy_id must be a lowercase policy name")
    if not operation:
        raise PaybondPolicyValidationError("operation is required")
    if not evidence_preset:
        raise PaybondPolicyValidationError("evidence preset is required")

    get_completion_preset(evidence_preset)

    template_id = _template_id_stub_for_preset(evidence_preset)
    max_spend_line = (
        f"\n    max_spend_cents: {options.max_spend_cents}"
        if options.max_spend_cents is not None
        else ""
    )

    return f"""version: 2
name: {policy_id}
default_deny: true

tools:
  {operation}:
    side_effecting: true
    evidence_preset: {evidence_preset}{max_spend_line}
    operation: {operation}

intent:
  # Production: publish template head, then paybond.intents.create_with_policy_binding(policy.to_intent_create_input(...))
  policy_binding:
    template_id: {template_id}
  allowed_tools:
    - {operation}
"""


def scaffold_org_base_policy(options: ScaffoldOrgBasePolicyOptions) -> dict[str, object]:
    out_path = Path(options.out)
    if out_path.exists() and not options.force:
        raise PaybondPolicyValidationError(f"{out_path} already exists (pass --force to overwrite)")

    yaml = render_org_base_policy_yaml(options)
    out_path.write_text(yaml, encoding="utf-8")
    return {
        "out": str(out_path),
        "policy_id": options.policy_id.strip(),
        "operation": options.operation.strip(),
        "evidence_preset": options.evidence_preset.strip(),
        "bytes_written": len(yaml.encode("utf-8")),
    }


def render_tenant_overlay_policy_yaml(options: ScaffoldTenantOverlayPolicyOptions) -> str:
    org_id, org_policy_id = parse_policy_extends_ref(options.extends_ref)
    name = _overlay_name_from_policy_id(org_policy_id, options.name)
    if not _POLICY_NAME_RE.fullmatch(name):
        raise PaybondPolicyValidationError("overlay name must be a lowercase policy name")

    operation = options.operation.strip() if options.operation else None
    evidence_preset = options.evidence_preset.strip() if options.evidence_preset else None
    if operation and not evidence_preset:
        raise PaybondPolicyValidationError("tenant-only tool requires --evidence-preset")
    if evidence_preset and not operation:
        raise PaybondPolicyValidationError("--evidence-preset requires --operation for tenant-only tools")
    if evidence_preset:
        get_completion_preset(evidence_preset)

    base_policy_line = (
        f"\n  base_policy: {options.base_policy.strip()}"
        if options.base_policy and options.base_policy.strip()
        else ""
    )

    tools_block = ""
    if operation and evidence_preset:
        tools_block = f"""tools:
  {operation}:
    side_effecting: true
    evidence_preset: {evidence_preset}
    operation: {operation}
"""

    return f"""version: 2
name: {name}
extends:
  org_policy_id: {org_policy_id}
  org_id: {org_id}{base_policy_line}
default_deny: true

{tools_block}"""


def scaffold_tenant_overlay_policy(options: ScaffoldTenantOverlayPolicyOptions) -> dict[str, object]:
    org_id, org_policy_id = parse_policy_extends_ref(options.extends_ref)
    name = _overlay_name_from_policy_id(org_policy_id, options.name)
    out_path = Path(options.out)
    if out_path.exists() and not options.force:
        raise PaybondPolicyValidationError(f"{out_path} already exists (pass --force to overwrite)")

    yaml = render_tenant_overlay_policy_yaml(options)
    out_path.write_text(yaml, encoding="utf-8")
    result: dict[str, object] = {
        "out": str(out_path),
        "name": name,
        "org_id": org_id,
        "org_policy_id": org_policy_id,
        "bytes_written": len(yaml.encode("utf-8")),
    }
    if options.operation and options.operation.strip():
        result["operation"] = options.operation.strip()
    if options.evidence_preset and options.evidence_preset.strip():
        result["evidence_preset"] = options.evidence_preset.strip()
    return result


def render_paybond_policy_yaml(options: ScaffoldPaybondPolicyOptions) -> str:
    operation = options.operation.strip()
    evidence_preset = options.evidence_preset.strip()
    if not operation:
        raise PaybondPolicyValidationError("operation is required")
    if not evidence_preset:
        raise PaybondPolicyValidationError("evidence preset is required")

    get_completion_preset(evidence_preset)

    name = _policy_name_from_operation(operation)
    template_id = _template_id_stub_for_preset(evidence_preset)

    return f"""version: 1
name: {name}
default_deny: true

tools:
  {operation}:
    side_effecting: true
    evidence_preset: {evidence_preset}
    operation: {operation}

intent:
  # Production: publish template head, then paybond.intents.create_with_policy_binding(policy.to_intent_create_input(...))
  policy_binding:
    template_id: {template_id}
  allowed_tools:
    - {operation}
"""


@dataclass(frozen=True, slots=True)
class ScaffoldPolicyFromPresetOptions:
    out: str | Path
    preset_id: str
    max_spend_usd: float | None = None
    force: bool = False


@dataclass(frozen=True, slots=True)
class ScaffoldComposedPolicyOptions:
    out: str | Path
    domain_id: str
    guardrails: str
    force: bool = False


def _policy_preset_scaffold_header(regenerate_command: str) -> str:
    return (
        f"# Reference implementation — edit freely. Regenerate with:\n"
        f"# {regenerate_command}\n\n"
    )


def _apply_max_spend_usd_override(
    document: PaybondPolicyDocumentV1,
    max_spend_usd_value: float,
) -> PaybondPolicyDocumentV1:
    cents = int(round(max_spend_usd_value * 100))
    tools = {
        name: replace(entry, max_spend_cents=cents) if entry.side_effecting else entry
        for name, entry in document.tools.items()
    }
    budget_currency = "usd"
    if document.intent and document.intent.budget:
        budget = document.intent.budget
        if isinstance(budget, dict):
            budget_currency = str(budget.get("currency") or "usd")
        else:
            budget_currency = budget.currency or "usd"
    intent = document.intent
    if intent is None:
        from paybond_kit.policy.schema import PaybondPolicyIntentSection

        intent = PaybondPolicyIntentSection(
            budget={"currency": budget_currency, "max_spend_usd": max_spend_usd_value}
        )
    else:
        intent = replace(
            intent,
            budget={"currency": budget_currency, "max_spend_usd": max_spend_usd_value},
        )
    return replace(document, tools=tools, intent=intent)


def _resolve_preset_init_document(options: ScaffoldPolicyFromPresetOptions) -> PaybondPolicyDocumentV1:
    document = resolve_composed_preset_document(options.preset_id)
    if options.max_spend_usd is None:
        return document
    return _apply_max_spend_usd_override(document, options.max_spend_usd)


def _resolve_composed_init_document(options: ScaffoldComposedPolicyOptions) -> PaybondPolicyDocumentV1:
    loader = getattr(domain, options.domain_id)
    layers = parse_guardrail_specs(options.guardrails)
    return compose_policy_layers(loader(), *layers)


def render_policy_preset_scaffold_yaml(
    preset_id: str,
    *,
    max_spend_usd: float | None = None,
) -> str:
    regenerate = (
        f"paybond policy init --preset {preset_id} --max-spend {max_spend_usd} --force"
        if max_spend_usd is not None
        else f"paybond policy init --preset {preset_id} --force"
    )
    document = (
        _resolve_preset_init_document(
            ScaffoldPolicyFromPresetOptions(out="", preset_id=preset_id, max_spend_usd=max_spend_usd)
        )
        if max_spend_usd is not None
        else resolve_composed_preset_document(preset_id)
    )
    body = render_policy_document_yaml(document).rstrip()
    return f"{_policy_preset_scaffold_header(regenerate)}{body}\n"


def render_composed_policy_scaffold_yaml(options: ScaffoldComposedPolicyOptions) -> str:
    regenerate = (
        f"paybond policy init --domain {options.domain_id} "
        f"--guardrails {options.guardrails} --force"
    )
    body = render_policy_document_yaml(_resolve_composed_init_document(options)).rstrip()
    return f"{_policy_preset_scaffold_header(regenerate)}{body}\n"


def render_composed_policy_preview_yaml(domain_id: str, guardrails: str) -> str:
    return render_policy_document_yaml(
        _resolve_composed_init_document(
            ScaffoldComposedPolicyOptions(out="", domain_id=domain_id, guardrails=guardrails)
        )
    )


def render_policy_preset_preview_yaml(preset_id: str, *, max_spend_usd: float | None = None) -> str:
    document = (
        _resolve_preset_init_document(
            ScaffoldPolicyFromPresetOptions(out="", preset_id=preset_id, max_spend_usd=max_spend_usd)
        )
        if max_spend_usd is not None
        else resolve_composed_preset_document(preset_id)
    )
    return render_policy_document_yaml(document)


def scaffold_policy_from_preset(options: ScaffoldPolicyFromPresetOptions) -> dict[str, object]:
    preset_id = options.preset_id.strip()
    if not is_known_policy_preset_id(preset_id):
        raise PaybondPolicyValidationError(f"unknown policy preset: {preset_id}")

    out_path = Path(options.out)
    if out_path.exists() and not options.force:
        raise PaybondPolicyValidationError(f"{out_path} already exists (pass --force to overwrite)")

    yaml = render_policy_preset_scaffold_yaml(preset_id, max_spend_usd=options.max_spend_usd)
    out_path.write_text(yaml, encoding="utf-8")
    parsed = parse_policy_document_text(yaml, source_label=str(out_path))
    name = parsed.get("name")
    result: dict[str, object] = {
        "out": str(out_path),
        "preset": preset_id,
        "name": name if isinstance(name, str) else preset_id,
        "bytes_written": len(yaml.encode("utf-8")),
    }
    if options.max_spend_usd is not None:
        result["max_spend_usd"] = options.max_spend_usd
    return result


def scaffold_composed_policy(options: ScaffoldComposedPolicyOptions) -> dict[str, object]:
    out_path = Path(options.out)
    if out_path.exists() and not options.force:
        raise PaybondPolicyValidationError(f"{out_path} already exists (pass --force to overwrite)")

    yaml = render_composed_policy_scaffold_yaml(options)
    out_path.write_text(yaml, encoding="utf-8")
    parsed = parse_policy_document_text(yaml, source_label=str(out_path))
    name = parsed.get("name")
    return {
        "out": str(out_path),
        "domain": options.domain_id,
        "guardrails": options.guardrails,
        "name": name if isinstance(name, str) else options.domain_id,
        "bytes_written": len(yaml.encode("utf-8")),
    }


def scaffold_paybond_policy(options: ScaffoldPaybondPolicyOptions) -> dict[str, object]:
    out_path = Path(options.out)
    if out_path.exists() and not options.force:
        raise PaybondPolicyValidationError(f"{out_path} already exists (pass --force to overwrite)")

    yaml = render_paybond_policy_yaml(options)
    out_path.write_text(yaml, encoding="utf-8")
    return {
        "out": str(out_path),
        "name": _policy_name_from_operation(options.operation),
        "operation": options.operation.strip(),
        "evidence_preset": options.evidence_preset.strip(),
        "bytes_written": len(yaml.encode("utf-8")),
    }
