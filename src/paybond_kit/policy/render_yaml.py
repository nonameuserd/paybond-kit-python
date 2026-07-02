"""Serialize validated v1 policy documents to paybond.policy.yaml text."""

from __future__ import annotations

from paybond_kit.policy.schema import PaybondPolicyDocumentV1


def _yaml_scalar(value: str) -> str:
    if value.replace(".", "").replace("_", "").replace("-", "").isalnum():
        return value
    return json_dumps_string(value)


def json_dumps_string(value: str) -> str:
    import json

    return json.dumps(value)


def render_policy_document_yaml(document: PaybondPolicyDocumentV1) -> str:
    lines = [
        f"version: {document.version}",
        f"name: {document.name}",
        f"default_deny: {'true' if document.default_deny else 'false'}",
        "",
        "tools:",
    ]

    for tool_name, entry in document.tools.items():
        lines.append(f"  {tool_name}:")
        lines.append(f"    side_effecting: {'true' if entry.side_effecting else 'false'}")
        if entry.max_spend_cents is not None:
            lines.append(f"    max_spend_cents: {entry.max_spend_cents}")
        if entry.spend_from_args is not None:
            lines.append(f"    spend_from_args: {_yaml_scalar(entry.spend_from_args)}")
        if entry.evidence_preset is not None:
            lines.append(f"    evidence_preset: {entry.evidence_preset}")
        if entry.vendor_pack is not None:
            lines.append(f"    vendor_pack: {entry.vendor_pack}")
        if entry.operation is not None:
            lines.append(f"    operation: {_yaml_scalar(entry.operation)}")
        lines.append("")

    if document.intent is not None:
        lines.append("intent:")
        if document.intent.allowed_tools:
            lines.append("  allowed_tools:")
            for tool in document.intent.allowed_tools:
                lines.append(f"    - {tool}")
        if document.intent.budget is not None:
            lines.append("  budget:")
            budget = document.intent.budget
            if isinstance(budget, dict):
                currency = budget.get("currency")
                max_spend = budget.get("max_spend_usd")
            else:
                currency = budget.currency
                max_spend = budget.max_spend_usd
            if currency:
                lines.append(f"    currency: {currency}")
            if max_spend is not None:
                lines.append(f"    max_spend_usd: {max_spend}")
        if document.intent.policy_binding is not None:
            lines.append("  policy_binding:")
            lines.append(f"    template_id: {document.intent.policy_binding.template_id}")
            if document.intent.policy_binding.version_seq is not None:
                lines.append(f"    version_seq: {document.intent.policy_binding.version_seq}")
            if document.intent.policy_binding.head_digest is not None:
                lines.append(f"    head_digest: {document.intent.policy_binding.head_digest}")

    return f"{chr(10).join(lines).rstrip()}{chr(10)}"
