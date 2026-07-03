"""Derive sandbox bootstrap input from a validated policy document."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from paybond_kit.agent.types import PaybondRunBindingSandboxBootstrapInput
from paybond_kit.completion_catalog import get_completion_preset
from paybond_kit.policy.schema import PaybondPolicyDocumentV1, PaybondPolicyToolEntry


class PaybondPolicySandboxBootstrapError(ValueError):
    """Raised when policy cannot derive sandbox bootstrap parameters."""


@dataclass(frozen=True, slots=True)
class PaybondPolicySandboxBootstrapOptions:
    tool_name: str | None = None
    operation: str | None = None
    requested_spend_cents: int | None = None
    currency: str | None = None
    evidence_schema: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] | None = None
    idempotency_key: str | None = None


def _list_side_effecting_tools(
    document: PaybondPolicyDocumentV1,
) -> list[tuple[str, PaybondPolicyToolEntry]]:
    return [(name, entry) for name, entry in document.tools.items() if entry.side_effecting]


def _resolve_harbor_operation(tool_name: str, entry: PaybondPolicyToolEntry) -> str:
    if entry.operation and entry.operation.strip():
        return entry.operation.strip()
    return tool_name


def _resolve_side_effecting_tool(
    document: PaybondPolicyDocumentV1,
    options: PaybondPolicySandboxBootstrapOptions,
) -> tuple[str, PaybondPolicyToolEntry]:
    side_effecting = _list_side_effecting_tools(document)
    if not side_effecting:
        raise PaybondPolicySandboxBootstrapError(
            "policy has no side-effecting tools for sandbox bootstrap"
        )

    if options.tool_name and options.tool_name.strip():
        tool_name = options.tool_name.strip()
        entry = document.tools.get(tool_name)
        if entry is None or not entry.side_effecting:
            raise PaybondPolicySandboxBootstrapError(
                f'tool "{tool_name}" is not a registered side-effecting tool in policy'
            )
        return tool_name, entry

    if options.operation and options.operation.strip():
        operation = options.operation.strip()
        for tool_name, entry in side_effecting:
            harbor_operation = _resolve_harbor_operation(tool_name, entry)
            if harbor_operation == operation or tool_name == operation:
                return tool_name, entry
        raise PaybondPolicySandboxBootstrapError(
            f'operation "{operation}" does not match any side-effecting tool in policy'
        )

    return side_effecting[0]


def policy_sandbox_bootstrap(
    document: PaybondPolicyDocumentV1,
    options: PaybondPolicySandboxBootstrapOptions | None = None,
) -> PaybondRunBindingSandboxBootstrapInput:
    """Build sandbox bootstrap input for :meth:`PaybondAgentRun.bind` from policy."""
    opts = options or PaybondPolicySandboxBootstrapOptions()
    tool_name, entry = _resolve_side_effecting_tool(document, opts)
    operation = _resolve_harbor_operation(tool_name, entry)
    evidence_preset = entry.evidence_preset
    if not evidence_preset:
        raise PaybondPolicySandboxBootstrapError(
            f'side-effecting tool "{tool_name}" is missing evidence_preset'
        )

    preset = get_completion_preset(evidence_preset)
    requested_spend_cents = opts.requested_spend_cents
    if requested_spend_cents is None:
        requested_spend_cents = entry.max_spend_cents
        if requested_spend_cents is None:
            requested_spend_cents = preset.get("recommended_amount_cents", 0)

    if requested_spend_cents < 0:
        raise PaybondPolicySandboxBootstrapError(
            "requested_spend_cents must be a non-negative number"
        )

    currency = opts.currency
    if currency is None and document.intent and document.intent.budget:
        currency = document.intent.budget.get("currency")

    evidence_schema = opts.evidence_schema
    if evidence_schema is None and not evidence_preset.strip():
        evidence_schema = preset["evidence_schema"]

    bootstrap: PaybondRunBindingSandboxBootstrapInput = {
        "kind": "sandbox",
        "operation": operation,
        "requested_spend_cents": int(requested_spend_cents),
        "completion_preset": evidence_preset,
    }
    if (currency is not None):
        bootstrap["currency"] = currency
    # Gateway resolves harbor template + parameters from completion_preset.
    # completion_preset and template_id are mutually exclusive on bootstrap.
    if evidence_preset.strip():
        if opts.evidence_schema is not None:
            raise PaybondPolicySandboxBootstrapError(
                "completion_preset and evidence_schema are mutually exclusive for sandbox bootstrap"
            )
    elif evidence_schema is not None:
        bootstrap["evidence_schema"] = dict(evidence_schema)
        bootstrap["template_id"] = preset["harbor_template_id"]
        bootstrap["parameters"] = dict(preset["parameters"])
    if opts.metadata is not None:
        bootstrap["metadata"] = dict(opts.metadata)
    if opts.idempotency_key is not None:
        bootstrap["idempotency_key"] = opts.idempotency_key
    return bootstrap


__all__ = [
    "PaybondPolicySandboxBootstrapError",
    "PaybondPolicySandboxBootstrapOptions",
    "policy_sandbox_bootstrap",
]
