"""Programmatic guardrail layers for policy compose."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class PolicyGuardrailLayer:
    default_deny: bool | None = None
    tools: dict[str, dict[str, Any]] | None = None
    intent: dict[str, Any] | None = None
    read_only: bool = False
    read_only_search: bool = False
    side_effecting_max_spend_cents: int | None = None
    budget_max_spend_usd: float | None = None
    require_evidence: bool = False


def default_deny() -> PolicyGuardrailLayer:
    return PolicyGuardrailLayer(default_deny=True)


def max_spend(cents: int) -> PolicyGuardrailLayer:
    if not isinstance(cents, int) or cents < 0:
        raise ValueError("max_spend requires a non-negative integer cents value")
    return PolicyGuardrailLayer(side_effecting_max_spend_cents=cents)


def max_spend_usd(usd: float) -> PolicyGuardrailLayer:
    if not isinstance(usd, (int, float)) or float(usd) < 0:
        raise ValueError("max_spend_usd requires a non-negative USD value")
    return PolicyGuardrailLayer(budget_max_spend_usd=float(usd))


def read_only() -> PolicyGuardrailLayer:
    return PolicyGuardrailLayer(read_only=True)


def read_only_search() -> PolicyGuardrailLayer:
    return PolicyGuardrailLayer(read_only_search=True)


def strict() -> PolicyGuardrailLayer:
    return PolicyGuardrailLayer(
        default_deny=True,
        side_effecting_max_spend_cents=1000,
        budget_max_spend_usd=10.0,
        require_evidence=True,
    )


def require_evidence() -> PolicyGuardrailLayer:
    return PolicyGuardrailLayer(require_evidence=True)


def audit_only() -> PolicyGuardrailLayer:
    return PolicyGuardrailLayer()


def allow_dry_run() -> PolicyGuardrailLayer:
    return PolicyGuardrailLayer()


def guardrail_layer_from_document(document: dict[str, Any]) -> PolicyGuardrailLayer:
    tools = document.get("tools")
    intent = document.get("intent")
    return PolicyGuardrailLayer(
        default_deny=True if document.get("default_deny") is True else None,
        tools=dict(tools) if isinstance(tools, dict) else None,
        intent=dict(intent) if isinstance(intent, dict) else None,
    )


class GuardrailsNamespace:
    default_deny = staticmethod(default_deny)
    max_spend = staticmethod(max_spend)
    max_spend_usd = staticmethod(max_spend_usd)
    read_only = staticmethod(read_only)
    read_only_search = staticmethod(read_only_search)
    strict = staticmethod(strict)
    require_evidence = staticmethod(require_evidence)
    audit_only = staticmethod(audit_only)
    allow_dry_run = staticmethod(allow_dry_run)
    from_document = staticmethod(guardrail_layer_from_document)


guardrails = GuardrailsNamespace()
