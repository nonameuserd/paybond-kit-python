"""Parse guardrail specs for policy compose CLI."""

from __future__ import annotations

import re

from paybond_kit.policy.guardrails import (
    PolicyGuardrailLayer,
    allow_dry_run,
    audit_only,
    default_deny,
    max_spend,
    max_spend_usd,
    read_only,
    read_only_search,
    require_evidence,
    strict,
)

GUARDRAIL_CATALOG_ENTRIES: tuple[dict[str, object], ...] = (
    {
        "id": "default-deny",
        "title": "Default deny",
        "description": "Require explicit tool registration (default_deny: true)",
    },
    {
        "id": "read-only",
        "title": "Read only",
        "description": "Keep only non-side-effecting tools",
    },
    {
        "id": "read-only-search",
        "title": "Read-only search",
        "description": "Keep only non-side-effecting search.* tools",
    },
    {
        "id": "strict",
        "title": "Strict",
        "description": "Tight caps, default deny, and evidence required on side-effecting tools",
    },
    {
        "id": "require-evidence",
        "title": "Require evidence",
        "description": "Validate evidence_preset on side-effecting tools at compose time",
    },
    {
        "id": "audit-only",
        "title": "Audit only",
        "description": "Reserved governance hook (no-op layer today)",
    },
    {
        "id": "allow-dry-run",
        "title": "Allow dry run",
        "description": "Reserved governance hook (no-op layer today)",
    },
    {
        "id": "max-spend:<usd>",
        "title": "Max spend (USD)",
        "description": "Cap intent budget and side-effecting tool spend (USD parameter)",
        "parameterized": True,
    },
    {
        "id": "max-spend-cents:<cents>",
        "title": "Max spend (cents)",
        "description": "Cap side-effecting tool spend in cents",
        "parameterized": True,
    },
    {
        "id": "max-spend-usd:<usd>",
        "title": "Max spend budget (USD)",
        "description": "Cap intent budget max_spend_usd only",
        "parameterized": True,
    },
)


def _normalize_guardrail_token(token: str) -> str:
    return token.strip().lower().replace("_", "-")


def _parse_positive_number(raw: str, label: str) -> float:
    value = float(raw)
    if value < 0:
        raise ValueError(f"{label} requires a non-negative number")
    return value


def parse_guardrail_spec(spec: str) -> PolicyGuardrailLayer:
    normalized = _normalize_guardrail_token(spec)
    if not normalized:
        raise ValueError("guardrail spec must not be empty")

    max_spend_match = re.fullmatch(r"max-spend:(\d+(?:\.\d+)?)", normalized)
    if max_spend_match:
        usd = _parse_positive_number(max_spend_match.group(1), "max-spend")
        return PolicyGuardrailLayer(
            budget_max_spend_usd=usd,
            side_effecting_max_spend_cents=int(round(usd * 100)),
        )

    max_spend_usd_match = re.fullmatch(r"max-spend-usd:(\d+(?:\.\d+)?)", normalized)
    if max_spend_usd_match:
        return max_spend_usd(_parse_positive_number(max_spend_usd_match.group(1), "max-spend-usd"))

    max_spend_cents_match = re.fullmatch(r"max-spend-cents:(\d+)", normalized)
    if max_spend_cents_match:
        return max_spend(int(_parse_positive_number(max_spend_cents_match.group(1), "max-spend-cents")))

    mapping = {
        "default-deny": default_deny,
        "defaultdeny": default_deny,
        "read-only": read_only,
        "readonly": read_only,
        "read-only-search": read_only_search,
        "readonlysearch": read_only_search,
        "strict": strict,
        "require-evidence": require_evidence,
        "requireevidence": require_evidence,
        "audit-only": audit_only,
        "auditonly": audit_only,
        "allow-dry-run": allow_dry_run,
        "allowdryrun": allow_dry_run,
    }
    factory = mapping.get(normalized)
    if factory is None:
        raise ValueError(f"unknown guardrail: {spec}")
    return factory()


def parse_guardrail_specs(csv: str) -> list[PolicyGuardrailLayer]:
    tokens = [token.strip() for token in csv.split(",") if token.strip()]
    if not tokens:
        raise ValueError("guardrails list must include at least one entry")
    return [parse_guardrail_spec(token) for token in tokens]


def list_guardrail_catalog_entries() -> list[dict[str, object]]:
    return [dict(entry) for entry in GUARDRAIL_CATALOG_ENTRIES]
