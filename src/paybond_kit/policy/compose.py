"""Compose domain + guardrail policy preset layers."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from paybond_kit.policy.guardrails import PolicyGuardrailLayer, guardrail_layer_from_document
from paybond_kit.policy.layers_io import (
    LAYERED_POLICY_PRESET_IDS,
    load_bundled_default_guardrails_document,
    load_bundled_domain_document,
)
from paybond_kit.policy.parse_text import parse_policy_document_text
from paybond_kit.policy.schema import (
    PaybondPolicyDocumentV1,
    PaybondPolicyIntentSection,
    PaybondPolicyToolEntry,
    parse_paybond_policy_document_v1,
)


def _merge_stricter_default_deny(*values: bool | None) -> bool:
    return any(value is True for value in values)


def _merge_tool_entry(base: PaybondPolicyToolEntry, patch: dict[str, Any]) -> PaybondPolicyToolEntry:
    merged = replace(base)
    if "side_effecting" in patch:
        merged = replace(merged, side_effecting=bool(patch["side_effecting"]))
    if "max_spend_cents" in patch:
        patch_value = int(patch["max_spend_cents"])
        merged = replace(
            merged,
            max_spend_cents=(
                min(merged.max_spend_cents, patch_value)
                if merged.max_spend_cents is not None
                else patch_value
            ),
        )
    if "spend_from_args" in patch:
        merged = replace(merged, spend_from_args=str(patch["spend_from_args"]), max_spend_cents=None)
    if "evidence_preset" in patch:
        merged = replace(merged, evidence_preset=str(patch["evidence_preset"]))
    if "vendor_pack" in patch:
        merged = replace(merged, vendor_pack=str(patch["vendor_pack"]))
    if "operation" in patch:
        merged = replace(merged, operation=str(patch["operation"]))
    return merged


def _assert_evidence_required(document: PaybondPolicyDocumentV1) -> None:
    for name, entry in document.tools.items():
        if entry.side_effecting and not entry.evidence_preset:
            raise ValueError(f'side-effecting tool "{name}" must declare evidence_preset')


def _apply_read_only_filter(
    document: PaybondPolicyDocumentV1,
    *,
    search_only: bool,
) -> PaybondPolicyDocumentV1:
    filtered = {
        name: entry
        for name, entry in document.tools.items()
        if not entry.side_effecting and (not search_only or name.startswith("search."))
    }
    allowed_tools: tuple[str, ...] = ()
    if document.intent and document.intent.allowed_tools:
        allowed = set(filtered)
        allowed_tools = tuple(tool for tool in document.intent.allowed_tools if tool in allowed)
    intent = (
        replace(document.intent, allowed_tools=allowed_tools)
        if document.intent
        else None
    )
    return replace(document, tools=filtered, intent=intent)


def _apply_guardrail_layer(document: PaybondPolicyDocumentV1, layer: PolicyGuardrailLayer) -> PaybondPolicyDocumentV1:
    if layer.default_deny is not None:
        document = replace(
            document,
            default_deny=_merge_stricter_default_deny(document.default_deny, layer.default_deny),
        )

    if layer.tools:
        tools = dict(document.tools)
        for tool_name, patch in layer.tools.items():
            existing = tools.get(tool_name)
            if existing is not None:
                tools[tool_name] = _merge_tool_entry(existing, patch)
        document = replace(document, tools=tools)

    if layer.intent:
        intent_data = {
            "policy_binding": document.intent.policy_binding if document.intent else None,
            "budget": dict(document.intent.budget) if document.intent and document.intent.budget else None,
            "allowed_tools": document.intent.allowed_tools if document.intent else (),
        }
        if "allowed_tools" in layer.intent:
            intent_data["allowed_tools"] = tuple(layer.intent["allowed_tools"])
        if "budget" in layer.intent:
            budget = dict(intent_data["budget"] or {})
            budget.update(layer.intent["budget"])
            intent_data["budget"] = budget
        document = replace(document, intent=PaybondPolicyIntentSection(**intent_data))

    if layer.side_effecting_max_spend_cents is not None:
        cents = layer.side_effecting_max_spend_cents
        tools = {
            name: (
                _merge_tool_entry(entry, {"max_spend_cents": cents})
                if entry.side_effecting
                else entry
            )
            for name, entry in document.tools.items()
        }
        document = replace(document, tools=tools)

    if layer.budget_max_spend_usd is not None:
        budget = dict(document.intent.budget) if document.intent and document.intent.budget else {}
        current_usd = budget.get("max_spend_usd")
        next_usd = layer.budget_max_spend_usd
        budget["currency"] = budget.get("currency") or "usd"
        budget["max_spend_usd"] = min(float(current_usd), next_usd) if current_usd is not None else next_usd
        intent = replace(document.intent, budget=budget) if document.intent else PaybondPolicyIntentSection(budget=budget)
        document = replace(document, intent=intent)

    if layer.read_only or layer.read_only_search:
        document = _apply_read_only_filter(document, search_only=layer.read_only_search)

    if layer.require_evidence:
        _assert_evidence_required(document)

    return document


def compose_policy_layers(
    domain_document: PaybondPolicyDocumentV1,
    *layers: PolicyGuardrailLayer,
) -> PaybondPolicyDocumentV1:
    composed = domain_document
    for layer in layers:
        composed = _apply_guardrail_layer(composed, layer)
    _assert_evidence_required(composed)
    return composed


def is_layered_policy_preset(preset_id: str) -> bool:
    return preset_id.strip() in LAYERED_POLICY_PRESET_IDS


def _deep_merge_record(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, patch_value in patch.items():
        base_value = result.get(key)
        if isinstance(base_value, dict) and isinstance(patch_value, dict):
            result[key] = _deep_merge_record(base_value, patch_value)
        else:
            result[key] = patch_value
    return result


def compose_policy_preset_layers(domain: dict[str, Any], guardrails_doc: dict[str, Any]) -> dict[str, Any]:
    return _deep_merge_record(domain, guardrails_doc)


def bundled_default_guardrails(preset_id: str) -> list[PolicyGuardrailLayer]:
    return [guardrail_layer_from_document(load_bundled_default_guardrails_document(preset_id))]


def compose_bundled_preset_default(preset_id: str) -> PaybondPolicyDocumentV1:
    from paybond_kit.policy.domain import domain as domain_ns

    loader = getattr(domain_ns, preset_id)
    return compose_policy_layers(loader(), *bundled_default_guardrails(preset_id))


def compose_layered_policy_preset_document(preset_id: str) -> dict[str, Any]:
    domain = load_bundled_domain_document(preset_id)
    guardrails_doc = load_bundled_default_guardrails_document(preset_id)
    return compose_policy_preset_layers(domain, guardrails_doc)


def _normalize_policy_preset_document(document: dict[str, object]) -> dict[str, object]:
    tools = document.get("tools")
    normalized_tools = tools
    if isinstance(tools, dict):
        normalized_tools = {
            name: dict(sorted(entry.items())) if isinstance(entry, dict) else entry
            for name, entry in sorted(tools.items())
        }

    intent = document.get("intent")
    normalized_intent = intent
    if isinstance(intent, dict):
        normalized_intent = dict(intent)
        allowed = normalized_intent.get("allowed_tools")
        if isinstance(allowed, list):
            normalized_intent["allowed_tools"] = sorted(allowed)

    result = dict(document)
    if normalized_tools is not None:
        result["tools"] = normalized_tools
    if normalized_intent is not None:
        result["intent"] = normalized_intent
    return result


def assert_layered_preset_matches_flat(preset_id: str) -> None:
    if not is_layered_policy_preset(preset_id):
        return
    from paybond_kit.policy.presets import read_policy_preset_yaml, resolve_policy_preset_path

    composed = compose_layered_policy_preset_document(preset_id)
    flat_path = resolve_policy_preset_path(preset_id)
    flat = parse_policy_document_text(read_policy_preset_yaml(preset_id), source_label=flat_path)
    if _normalize_policy_preset_document(composed) != _normalize_policy_preset_document(flat):
        raise AssertionError(f"composed preset {preset_id} does not match flat bundled file")
