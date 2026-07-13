"""Deterministic org-base and tenant-overlay policy merge."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from paybond_kit.policy.schema import (
    PaybondPolicyAdapterSection,
    PaybondPolicyBinding,
    PaybondPolicyBindingOverride,
    PaybondPolicyDocument,
    PaybondPolicyDocumentV1,
    PaybondPolicyDocumentV2,
    PaybondPolicyIntentSection,
    PaybondPolicyToolEntry,
    PaybondPolicyToolOverrideEntry,
    PaybondPolicyValidationError,
    is_paybond_policy_overlay,
)

PolicyMergeDeniedWidening = dict[str, str]


@dataclass(frozen=True, slots=True)
class PolicyMergeReport:
    org_policy_id: str | None
    org_id: str | None
    base_policy_name: str
    overlay_policy_name: str | None
    overrides_applied: tuple[str, ...]
    denied_widenings: tuple[PolicyMergeDeniedWidening, ...]


@dataclass(frozen=True, slots=True)
class PolicyMergeResult:
    effective: PaybondPolicyDocumentV1
    report: PolicyMergeReport


@dataclass(frozen=True, slots=True)
class PolicyMergeOptions:
    approved_evidence_presets: tuple[str, ...] | None = None


def _clone_tool_entry(entry: PaybondPolicyToolEntry) -> PaybondPolicyToolEntry:
    return PaybondPolicyToolEntry(
        side_effecting=entry.side_effecting,
        max_spend_cents=entry.max_spend_cents,
        spend_from_args=entry.spend_from_args,
        evidence_preset=entry.evidence_preset,
        vendor_pack=entry.vendor_pack,
        operation=entry.operation,
    )


def _merge_stricter_default_deny(*values: bool) -> bool:
    return any(value is True for value in values)


def _deny(
    denied: list[PolicyMergeDeniedWidening],
    *,
    path: str,
    code: str,
    message: str,
) -> None:
    denied.append({"path": path, "code": code, "message": message})


def _merge_tool_fields(
    base: PaybondPolicyToolEntry,
    patch: PaybondPolicyToolOverrideEntry,
    tool_name: str,
    report: PolicyMergeReport,
    denied: list[PolicyMergeDeniedWidening],
    overrides_applied: list[str],
) -> PaybondPolicyToolEntry:
    merged = _clone_tool_entry(base)

    if patch.side_effecting is not None:
        if base.side_effecting and patch.side_effecting is False:
            _deny(
                denied,
                path=f"tools.{tool_name}.side_effecting",
                code="policy.cannot_disable_org_side_effecting_tool",
                message=f'cannot disable org-required side-effecting tool "{tool_name}"',
            )
        else:
            merged = PaybondPolicyToolEntry(
                side_effecting=patch.side_effecting,
                max_spend_cents=merged.max_spend_cents,
                spend_from_args=merged.spend_from_args,
                evidence_preset=merged.evidence_preset,
                vendor_pack=merged.vendor_pack,
                operation=merged.operation,
            )
            overrides_applied.append(f"tools.{tool_name}.side_effecting")

    if patch.max_spend_cents is not None:
        if base.max_spend_cents is not None and patch.max_spend_cents > base.max_spend_cents:
            _deny(
                denied,
                path=f"tools.{tool_name}.max_spend_cents",
                code="policy.cannot_raise_spend_cap",
                message=(
                    f"tenant max_spend_cents ({patch.max_spend_cents}) exceeds "
                    f"org cap ({base.max_spend_cents})"
                ),
            )
        else:
            merged = PaybondPolicyToolEntry(
                side_effecting=merged.side_effecting,
                max_spend_cents=patch.max_spend_cents,
                spend_from_args=None if patch.max_spend_cents is not None else merged.spend_from_args,
                evidence_preset=merged.evidence_preset,
                vendor_pack=merged.vendor_pack,
                operation=merged.operation,
            )
            overrides_applied.append(f"tools.{tool_name}.max_spend_cents")

    if patch.spend_from_args is not None:
        if base.max_spend_cents is not None:
            _deny(
                denied,
                path=f"tools.{tool_name}.spend_from_args",
                code="policy.cannot_override_org_spend_mode",
                message=f'cannot replace org max_spend_cents with spend_from_args on "{tool_name}"',
            )
        else:
            merged = PaybondPolicyToolEntry(
                side_effecting=merged.side_effecting,
                max_spend_cents=None,
                spend_from_args=patch.spend_from_args,
                evidence_preset=merged.evidence_preset,
                vendor_pack=merged.vendor_pack,
                operation=merged.operation,
            )
            overrides_applied.append(f"tools.{tool_name}.spend_from_args")

    if patch.evidence_preset is not None:
        if patch.evidence_preset != base.evidence_preset and report.org_policy_id is not None:
            overrides_applied.append(f"tools.{tool_name}.evidence_preset")
        merged = PaybondPolicyToolEntry(
            side_effecting=merged.side_effecting,
            max_spend_cents=merged.max_spend_cents,
            spend_from_args=merged.spend_from_args,
            evidence_preset=patch.evidence_preset,
            vendor_pack=merged.vendor_pack,
            operation=merged.operation,
        )

    if patch.vendor_pack is not None:
        merged = PaybondPolicyToolEntry(
            side_effecting=merged.side_effecting,
            max_spend_cents=merged.max_spend_cents,
            spend_from_args=merged.spend_from_args,
            evidence_preset=merged.evidence_preset,
            vendor_pack=patch.vendor_pack,
            operation=merged.operation,
        )
        overrides_applied.append(f"tools.{tool_name}.vendor_pack")

    if patch.operation is not None:
        merged = PaybondPolicyToolEntry(
            side_effecting=merged.side_effecting,
            max_spend_cents=merged.max_spend_cents,
            spend_from_args=merged.spend_from_args,
            evidence_preset=merged.evidence_preset,
            vendor_pack=merged.vendor_pack,
            operation=patch.operation,
        )
        overrides_applied.append(f"tools.{tool_name}.operation")

    if merged.side_effecting and not merged.evidence_preset:
        _deny(
            denied,
            path=f"tools.{tool_name}.evidence_preset",
            code="policy.missing_evidence_preset",
            message=f'side-effecting tool "{tool_name}" must declare evidence_preset after merge',
        )

    if merged.max_spend_cents is not None and merged.spend_from_args is not None:
        _deny(
            denied,
            path=f"tools.{tool_name}",
            code="policy.conflicting_spend_fields",
            message="max_spend_cents and spend_from_args are mutually exclusive",
        )

    return merged


def _merge_policy_binding(
    base: PaybondPolicyBinding | None,
    overlay: PaybondPolicyBinding | None,
    override: PaybondPolicyBindingOverride | None,
    denied: list[PolicyMergeDeniedWidening],
    overrides_applied: list[str],
) -> PaybondPolicyBinding | None:
    if base is None and overlay is None and override is None:
        return None

    template_id = (
        (override.template_id if override is not None else None)
        or (overlay.template_id if overlay is not None else None)
        or (base.template_id if base is not None else None)
    )
    if not template_id:
        return None

    overlay_template = (
        (override.template_id if override is not None else None)
        or (overlay.template_id if overlay is not None else None)
    )
    if base is not None and overlay_template and overlay_template != base.template_id:
        _deny(
            denied,
            path="intent.policy_binding.template_id",
            code="policy.cannot_change_org_template",
            message=(
                f'tenant template_id "{overlay_template}" must match org template "{base.template_id}"'
            ),
        )

    version_seq = None
    if override is not None and override.version_seq is not None:
        version_seq = override.version_seq
    elif overlay is not None and overlay.version_seq is not None:
        version_seq = overlay.version_seq
    elif base is not None:
        version_seq = base.version_seq

    if version_seq is not None and base is not None and base.version_seq is not None:
        if version_seq < base.version_seq:
            _deny(
                denied,
                path="intent.policy_binding.version_seq",
                code="policy.cannot_downgrade_template_version",
                message=(
                    f"tenant version_seq ({version_seq}) is older than org version_seq ({base.version_seq})"
                ),
            )
        elif override is not None and override.version_seq is not None:
            overrides_applied.append("intent.policy_binding.version_seq")

    head_digest = None
    if override is not None and override.head_digest is not None:
        head_digest = override.head_digest
    elif overlay is not None and overlay.head_digest is not None:
        head_digest = overlay.head_digest
    elif base is not None:
        head_digest = base.head_digest

    if head_digest is not None and base is not None and base.head_digest and head_digest != base.head_digest:
        _deny(
            denied,
            path="intent.policy_binding.head_digest",
            code="policy.cannot_change_org_head_digest",
            message="tenant head_digest must match the org-pinned template head",
        )
    elif override is not None and override.head_digest is not None:
        overrides_applied.append("intent.policy_binding.head_digest")

    return PaybondPolicyBinding(
        template_id=template_id,
        version_seq=version_seq,
        head_digest=head_digest,
    )


def _merge_budget(
    base: dict[str, Any] | None,
    overlay: dict[str, Any] | None,
    override: dict[str, Any] | None,
    denied: list[PolicyMergeDeniedWidening],
    overrides_applied: list[str],
) -> dict[str, Any] | None:
    merged: dict[str, Any] = {}
    if base:
        merged.update(base)
    if overlay:
        merged.update(overlay)
    if override:
        merged.update(override)
    if not merged:
        return None

    org_max = (base or {}).get("max_spend_usd")
    tenant_max = (override or overlay or {}).get("max_spend_usd")
    if org_max is not None and tenant_max is not None and tenant_max > org_max:
        _deny(
            denied,
            path="intent.budget.max_spend_usd",
            code="policy.cannot_raise_budget_cap",
            message=f"tenant max_spend_usd ({tenant_max}) exceeds org cap ({org_max})",
        )
    elif override is not None and override.get("max_spend_usd") is not None:
        overrides_applied.append("intent.budget.max_spend_usd")

    return merged


def _intersect_allowed_tools(
    org_allowed: tuple[str, ...] | None,
    tenant_allowed: tuple[str, ...] | None,
    denied: list[PolicyMergeDeniedWidening],
    overrides_applied: list[str],
) -> tuple[str, ...] | None:
    if not tenant_allowed:
        return org_allowed
    if not org_allowed:
        return tenant_allowed

    org_set = set(org_allowed)
    widened = [tool for tool in tenant_allowed if tool not in org_set]
    if widened:
        _deny(
            denied,
            path="intent.allowed_tools",
            code="policy.cannot_widen_allowed_tools",
            message=f"tenant allowed_tools widens org allowlist: {', '.join(widened)}",
        )

    intersection = tuple(tool for tool in tenant_allowed if tool in org_set)
    if len(intersection) != len(tenant_allowed):
        overrides_applied.append("intent.allowed_tools")
    return intersection


def _merge_adapter_section(
    base: PaybondPolicyAdapterSection | None,
    overlay: PaybondPolicyAdapterSection | None,
    override: PaybondPolicyAdapterSection | None,
    denied: list[PolicyMergeDeniedWidening],
    overrides_applied: list[str],
) -> PaybondPolicyAdapterSection | None:
    values = [
        None if base is None else base.deny_provider_executed_tools,
        None if overlay is None else overlay.deny_provider_executed_tools,
        None if override is None else override.deny_provider_executed_tools,
    ]
    if all(value is None for value in values):
        return None

    if base is not None and base.deny_provider_executed_tools is True:
        if (overlay is not None and overlay.deny_provider_executed_tools is False) or (
            override is not None and override.deny_provider_executed_tools is False
        ):
            _deny(
                denied,
                path="adapter.deny_provider_executed_tools",
                code="policy.cannot_relax_provider_executed_deny",
                message="tenant cannot disable org-required deny_provider_executed_tools",
            )

    if override is not None and override.deny_provider_executed_tools is not None:
        overrides_applied.append("overrides.adapter.deny_provider_executed_tools")

    deny = _merge_stricter_default_deny(
        *(False if value is None else value for value in values)
    )
    return PaybondPolicyAdapterSection(deny_provider_executed_tools=deny)


def _base_document_to_effective_v1(
    document: PaybondPolicyDocumentV1 | PaybondPolicyDocumentV2,
) -> PaybondPolicyDocumentV1:
    intent = None
    if document.intent is not None:
        intent = PaybondPolicyIntentSection(
            policy_binding=document.intent.policy_binding,
            budget=deepcopy(document.intent.budget) if document.intent.budget is not None else None,
            allowed_tools=document.intent.allowed_tools,
        )
    return PaybondPolicyDocumentV1(
        version=1,
        name=document.name,
        default_deny=document.default_deny,
        tools={name: _clone_tool_entry(entry) for name, entry in document.tools.items()},
        intent=intent,
        adapter=document.adapter,
    )


def merge_paybond_policies(
    base: PaybondPolicyDocumentV1 | PaybondPolicyDocumentV2,
    overlay: PaybondPolicyDocumentV2,
    *,
    options: PolicyMergeOptions | None = None,
) -> PolicyMergeResult:
    """Merge org base + tenant overlay into a flat v1 effective policy."""
    if not is_paybond_policy_overlay(overlay):
        raise PaybondPolicyValidationError(
            "merge requires a tenant overlay document with extends",
            path="extends",
        )

    denied: list[PolicyMergeDeniedWidening] = []
    overrides_applied: list[str] = []
    extends = overlay.extends
    assert extends is not None

    report = PolicyMergeReport(
        org_policy_id=extends.org_policy_id,
        org_id=extends.org_id,
        base_policy_name=base.name,
        overlay_policy_name=overlay.name,
        overrides_applied=(),
        denied_widenings=(),
    )

    effective = _base_document_to_effective_v1(base)
    default_deny_values = [base.default_deny, overlay.default_deny]
    if overlay.overrides and overlay.overrides.default_deny is not None:
        default_deny_values.append(overlay.overrides.default_deny)
        overrides_applied.append("overrides.default_deny")
    effective = PaybondPolicyDocumentV1(
        version=1,
        name=overlay.name,
        default_deny=_merge_stricter_default_deny(*default_deny_values),
        tools=dict(effective.tools),
        intent=effective.intent,
    )

    merged_tools = dict(effective.tools)
    if overlay.overrides and overlay.overrides.tools:
        for tool_name, patch in overlay.overrides.tools.items():
            existing = merged_tools.get(tool_name)
            if existing is None:
                _deny(
                    denied,
                    path=f"overrides.tools.{tool_name}",
                    code="policy.unknown_org_tool_override",
                    message=f'cannot override unknown org tool "{tool_name}"',
                )
                continue
            merged_tools[tool_name] = _merge_tool_fields(
                existing,
                patch,
                tool_name,
                report,
                denied,
                overrides_applied,
            )

    for tool_name, entry in overlay.tools.items():
        if tool_name in merged_tools:
            _deny(
                denied,
                path=f"tools.{tool_name}",
                code="policy.cannot_replace_org_tool",
                message=f'tenant tools must append new entries; "{tool_name}" already exists in org base',
            )
            continue
        merged_tools[tool_name] = _clone_tool_entry(entry)

    effective = PaybondPolicyDocumentV1(
        version=1,
        name=effective.name,
        default_deny=effective.default_deny,
        tools=merged_tools,
        intent=effective.intent,
    )

    org_allowed = base.intent.allowed_tools if base.intent else None
    tenant_allowed = None
    if overlay.overrides and overlay.overrides.intent and overlay.overrides.intent.allowed_tools:
        tenant_allowed = overlay.overrides.intent.allowed_tools
    elif overlay.intent and overlay.intent.allowed_tools:
        tenant_allowed = overlay.intent.allowed_tools

    merged_allowed = _intersect_allowed_tools(org_allowed, tenant_allowed, denied, overrides_applied)

    if overlay.intent is None and (overlay.overrides is None or overlay.overrides.intent is None):
        if base.intent is not None:
            effective_intent = PaybondPolicyIntentSection(
                policy_binding=base.intent.policy_binding,
                budget=deepcopy(base.intent.budget) if base.intent.budget is not None else None,
                allowed_tools=merged_allowed if merged_allowed is not None else base.intent.allowed_tools,
            )
            effective = PaybondPolicyDocumentV1(
                version=1,
                name=effective.name,
                default_deny=effective.default_deny,
                tools=effective.tools,
                intent=effective_intent,
            )
    else:
        merged_binding = _merge_policy_binding(
            base.intent.policy_binding if base.intent else None,
            overlay.intent.policy_binding if overlay.intent else None,
            overlay.overrides.intent.policy_binding
            if overlay.overrides and overlay.overrides.intent
            else None,
            denied,
            overrides_applied,
        )
        merged_budget = _merge_budget(
            base.intent.budget if base.intent else None,
            overlay.intent.budget if overlay.intent else None,
            overlay.overrides.intent.budget
            if overlay.overrides and overlay.overrides.intent
            else None,
            denied,
            overrides_applied,
        )
        intent_kwargs: dict[str, Any] = {}
        if merged_binding is not None:
            intent_kwargs["policy_binding"] = merged_binding
        if merged_budget is not None:
            intent_kwargs["budget"] = merged_budget
        if merged_allowed:
            intent_kwargs["allowed_tools"] = merged_allowed
        if intent_kwargs:
            effective = PaybondPolicyDocumentV1(
                version=1,
                name=effective.name,
                default_deny=effective.default_deny,
                tools=effective.tools,
                intent=PaybondPolicyIntentSection(**intent_kwargs),
            )
        elif base.intent is not None:
            effective = PaybondPolicyDocumentV1(
                version=1,
                name=effective.name,
                default_deny=effective.default_deny,
                tools=effective.tools,
                intent=PaybondPolicyIntentSection(
                    policy_binding=base.intent.policy_binding,
                    budget=deepcopy(base.intent.budget) if base.intent.budget is not None else None,
                    allowed_tools=base.intent.allowed_tools,
                ),
            )

    effective = PaybondPolicyDocumentV1(
        version=1,
        name=effective.name,
        default_deny=effective.default_deny,
        tools=effective.tools,
        intent=effective.intent,
        adapter=_merge_adapter_section(
            base.adapter,
            overlay.adapter,
            overlay.overrides.adapter if overlay.overrides else None,
            denied,
            overrides_applied,
        ),
    )

    if options and options.approved_evidence_presets:
        approved = set(options.approved_evidence_presets)
        for tool_name, entry in effective.tools.items():
            if not entry.side_effecting or not entry.evidence_preset:
                continue
            base_preset = base.tools.get(tool_name)
            base_preset_id = base_preset.evidence_preset if base_preset else None
            if (
                base_preset_id
                and entry.evidence_preset != base_preset_id
                and entry.evidence_preset not in approved
            ):
                _deny(
                    denied,
                    path=f"tools.{tool_name}.evidence_preset",
                    code="policy.evidence_preset_not_org_approved",
                    message=(
                        f'evidence preset "{entry.evidence_preset}" is not in the org-approved catalog subset'
                    ),
                )

    if denied:
        summary = "; ".join(f"{item['path']}: {item['message']}" for item in denied)
        raise PaybondPolicyValidationError(summary)

    final_report = PolicyMergeReport(
        org_policy_id=report.org_policy_id,
        org_id=report.org_id,
        base_policy_name=report.base_policy_name,
        overlay_policy_name=report.overlay_policy_name,
        overrides_applied=tuple(overrides_applied),
        denied_widenings=tuple(denied),
    )
    return PolicyMergeResult(effective=effective, report=final_report)


def to_effective_policy_document(document: PaybondPolicyDocument) -> PaybondPolicyDocumentV1:
    """Normalize a supported policy document to a flat v1 effective document."""
    if isinstance(document, PaybondPolicyDocumentV1):
        return _base_document_to_effective_v1(document)
    if is_paybond_policy_overlay(document):
        raise PaybondPolicyValidationError(
            "tenant overlay requires merge with an org base policy before use",
            path="extends",
        )
    return _base_document_to_effective_v1(document)
