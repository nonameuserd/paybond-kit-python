"""Build Harbor intent create payloads from paybond.policy.yaml intent sections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from paybond_kit.agent.registry import PaybondToolRegistry
from paybond_kit.agent.types import PaybondToolRegistryValidationError
from paybond_kit.completion_resolve import resolve_completion_preset
from paybond_kit.harbor import SettlementRail
from paybond_kit.policy.registry import policy_to_tool_registry
from paybond_kit.policy.schema import PaybondPolicyDocumentV1


class PaybondPolicyIntentSpecError(ValueError):
    """Raised when policy intent fields cannot be aligned to a Harbor create payload."""


@dataclass(frozen=True)
class PaybondPolicyIntentCreateInput:
    """Keyword arguments for :meth:`PaybondIntents.create_with_policy_binding`."""

    principal_did: str
    principal_signing_seed: bytes
    payee_did: str
    payee_signing_seed: bytes
    budget: dict[str, Any]
    currency: str
    amount_cents: int
    evidence_schema: dict[str, Any]
    deadline_rfc3339: str
    allowed_tools: list[str]
    settlement_rail: SettlementRail
    policy_template_id: str
    policy_version_seq: int
    materialized_predicate: Mapping[str, Any]
    policy_content_digest_hex: str
    recognition_proof: Mapping[str, Any]
    intent_id: str | None = None
    predicate_ref: str = ""
    completion_preset_id: str | None = None


def _normalize_digest_hex(digest: str) -> str:
    trimmed = digest.strip().lower()
    if trimmed.startswith("sha256:"):
        return trimmed[len("sha256:") :]
    return trimmed.removeprefix("0x")


def _resolve_allowed_harbor_operations(
    document: PaybondPolicyDocumentV1,
    registry: PaybondToolRegistry,
    *,
    override: list[str] | None = None,
) -> list[str]:
    raw = override if override is not None else (
        list(document.intent.allowed_tools) if document.intent and document.intent.allowed_tools else None
    )
    if not raw:
        raise PaybondPolicyIntentSpecError(
            "policy intent.allowed_tools is required for to_intent_create_input"
        )

    operations = registry.side_effecting_operations()
    seen: set[str] = set()
    resolved: list[str] = []

    for name in raw:
        if registry.is_side_effecting(name):
            operation = registry.resolve_operation(name)
        elif name in operations:
            operation = name
        else:
            raise PaybondPolicyIntentSpecError(
                f'allowed_tools entry "{name}" is not a registered side-effecting tool or Harbor operation'
            )
        if operation not in seen:
            seen.add(operation)
            resolved.append(operation)

    if not resolved:
        raise PaybondPolicyIntentSpecError(
            "allowed_tools must resolve to at least one Harbor operation"
        )

    try:
        registry.validate_for_bind(resolved)
    except PaybondToolRegistryValidationError as exc:
        raise PaybondPolicyIntentSpecError(str(exc)) from exc

    return resolved


def _resolve_evidence_preset_for_operations(
    registry: PaybondToolRegistry,
    allowed_operations: list[str],
) -> str:
    presets: set[str] = set()
    for operation in allowed_operations:
        for tool_name in registry.side_effecting_tool_names():
            if registry.resolve_operation(tool_name) != operation:
                continue
            entry = registry.get_side_effecting_entry(tool_name)
            if entry is not None and entry.evidence_preset:
                presets.add(entry.evidence_preset)

    if not presets:
        raise PaybondPolicyIntentSpecError(
            "could not resolve evidence_preset from policy allowed_tools"
        )
    if len(presets) > 1:
        raise PaybondPolicyIntentSpecError(
            "allowed_tools reference multiple evidence_preset values: "
            + ", ".join(sorted(presets))
        )
    return next(iter(presets))


def _resolve_policy_binding(
    document: PaybondPolicyDocumentV1,
    *,
    template_id: str,
    version_seq: int,
    policy_content_digest_hex: str,
    policy_template_id: str | None = None,
    policy_version_seq: int | None = None,
) -> tuple[str, int]:
    policy_binding = document.intent.policy_binding if document.intent else None
    if policy_template_id is None and policy_binding is None:
        raise PaybondPolicyIntentSpecError(
            "policy intent.policy_binding is required for to_intent_create_input"
        )

    resolved_template = policy_template_id or (policy_binding.template_id if policy_binding else "")
    resolved_version = (
        policy_version_seq
        if policy_version_seq is not None
        else (
            policy_binding.version_seq
            if policy_binding is not None and policy_binding.version_seq is not None
            else version_seq
        )
    )

    if resolved_template != template_id:
        raise PaybondPolicyIntentSpecError(
            "published policy head template_id must match policy intent.policy_binding.template_id"
        )
    if resolved_version != version_seq:
        raise PaybondPolicyIntentSpecError(
            "published policy head version_seq must match policy intent.policy_binding.version_seq"
        )
    if (
        policy_binding is not None
        and policy_binding.version_seq is not None
        and policy_binding.version_seq != version_seq
    ):
        raise PaybondPolicyIntentSpecError(
            "policy intent.policy_binding.version_seq does not match published policy head version_seq"
        )

    if policy_binding is not None and policy_binding.head_digest:
        expected = _normalize_digest_hex(policy_binding.head_digest)
        actual = _normalize_digest_hex(policy_content_digest_hex)
        if expected != actual:
            raise PaybondPolicyIntentSpecError(
                "policy intent.policy_binding.head_digest does not match published policy head digest"
            )

    return resolved_template, resolved_version


def _resolve_budget_fields(
    document: PaybondPolicyDocumentV1,
    *,
    budget: Mapping[str, Any] | None = None,
    currency: str | None = None,
    amount_cents: int | None = None,
) -> tuple[dict[str, Any], str, int]:
    if budget is not None and currency is not None and amount_cents is not None:
        return dict(budget), currency, amount_cents

    intent_budget = document.intent.budget if document.intent else None
    resolved_currency = currency or (intent_budget or {}).get("currency") or "usd"

    resolved_amount = amount_cents
    if resolved_amount is None and intent_budget is not None:
        max_spend_usd = intent_budget.get("max_spend_usd")
        if isinstance(max_spend_usd, (int, float)):
            resolved_amount = int(round(float(max_spend_usd) * 100))

    if resolved_amount is None:
        raise PaybondPolicyIntentSpecError(
            "amount_cents is required when policy intent.budget.max_spend_usd is not set"
        )

    resolved_budget: dict[str, Any]
    if budget is not None:
        resolved_budget = dict(budget)
    elif intent_budget is not None:
        resolved_budget = dict(intent_budget)
    else:
        resolved_budget = {}
    resolved_budget.setdefault("max", resolved_amount)

    return resolved_budget, str(resolved_currency), resolved_amount


def policy_to_intent_create_input(
    document: PaybondPolicyDocumentV1,
    *,
    principal_did: str,
    principal_signing_seed: bytes,
    payee_did: str,
    payee_signing_seed: bytes,
    deadline_rfc3339: str,
    settlement_rail: SettlementRail,
    recognition_proof: Mapping[str, Any],
    materialized_predicate: Mapping[str, Any],
    policy_template_id: str,
    policy_version_seq: int,
    policy_content_digest_hex: str,
    intent_id: str | None = None,
    predicate_ref: str = "",
    amount_cents: int | None = None,
    currency: str | None = None,
    budget: Mapping[str, Any] | None = None,
    allowed_tools: list[str] | None = None,
    completion_preset_id: str | None = None,
    evidence_schema: Mapping[str, Any] | None = None,
) -> PaybondPolicyIntentCreateInput:
    """
    Build :meth:`PaybondIntents.create_with_policy_binding` kwargs from a validated policy document.

    Merges policy intent alignment (``allowed_tools``, ``budget``, ``policy_binding``) with caller
    signing context and a published managed-policy head fetched from the tenant registry.
    """
    registry = policy_to_tool_registry(document)
    resolved_allowed = _resolve_allowed_harbor_operations(
        document,
        registry,
        override=allowed_tools,
    )
    resolved_template, resolved_version = _resolve_policy_binding(
        document,
        template_id=policy_template_id,
        version_seq=policy_version_seq,
        policy_content_digest_hex=policy_content_digest_hex,
    )
    resolved_budget, resolved_currency, resolved_amount = _resolve_budget_fields(
        document,
        budget=budget,
        currency=currency,
        amount_cents=amount_cents,
    )

    resolved_preset_id = completion_preset_id or _resolve_evidence_preset_for_operations(
        registry,
        resolved_allowed,
    )
    resolved_preset = resolve_completion_preset(resolved_preset_id)
    resolved_evidence_schema = (
        dict(evidence_schema)
        if evidence_schema is not None
        else dict(resolved_preset["evidence_schema"])
    )

    return PaybondPolicyIntentCreateInput(
        principal_did=principal_did,
        principal_signing_seed=principal_signing_seed,
        payee_did=payee_did,
        payee_signing_seed=payee_signing_seed,
        budget=resolved_budget,
        currency=resolved_currency,
        amount_cents=resolved_amount,
        evidence_schema=resolved_evidence_schema,
        deadline_rfc3339=deadline_rfc3339,
        allowed_tools=resolved_allowed,
        settlement_rail=settlement_rail,
        policy_template_id=resolved_template,
        policy_version_seq=resolved_version,
        materialized_predicate=dict(materialized_predicate),
        policy_content_digest_hex=policy_content_digest_hex,
        recognition_proof=dict(recognition_proof),
        intent_id=intent_id,
        predicate_ref=predicate_ref,
        completion_preset_id=resolved_preset_id,
    )
