"""Canonical Paybond MCP scope catalog (Python mirror).

Mirrors ``kit/mcp-scopes/catalog.json``, which is also mirrored by
``kit/ts/src/mcp/scope-catalog.ts`` and the Go gateway catalog. Parity is
enforced by tests in every runtime — do not edit one mirror without the others.

Restricted ``paybond_rk_*`` keys carry an explicit scope grant; the credential is
the permission model. Standard ``paybond_sk_*`` keys carry no MCP scopes and keep
the pre-existing env tool-policy behavior.
"""

from __future__ import annotations

from typing import Any, Literal, NamedTuple

McpScopeLevel = Literal["read", "write"]
PaybondApiKeyKind = Literal["standard", "restricted", "unknown"]

MCP_SCOPE_CATALOG_VERSION = 1
MCP_SCOPE_LEVELS: tuple[McpScopeLevel, ...] = ("read", "write")

STANDARD_API_KEY_PREFIX = "paybond_sk_"
RESTRICTED_API_KEY_PREFIX = "paybond_rk_"
# User-scoped MCP OAuth access tokens issued by ``/v1/oauth/token``.
MCP_OAUTH_ACCESS_TOKEN_PREFIX = "paybond_oat_"


class McpScope(NamedTuple):
    """One granted or required MCP scope entry. ``write`` implies ``read``."""

    scope: str
    level: McpScopeLevel


class McpScopeDefinition(NamedTuple):
    """Catalog metadata for one scope group."""

    id: str
    title: str
    max_level: McpScopeLevel
    description: str


class McpScopeRoute(NamedTuple):
    """Gateway route covered by a scope, used for defense-in-depth documentation."""

    method: str
    pattern: str
    scope: str
    level: McpScopeLevel


class McpScopePreset(NamedTuple):
    """Console/CLI starting template for a restricted key scope grant."""

    id: str
    title: str
    description: str
    scopes: tuple[McpScope, ...]


MCP_SCOPE_DEFINITIONS: tuple[McpScopeDefinition, ...] = (
    McpScopeDefinition(
        id="mcp.discovery",
        title="Discovery",
        max_level="read",
        description=(
            "Principal identity, Harbor intent reads, and side-effect-free spend policy dry-runs."
        ),
    ),
    McpScopeDefinition(
        id="mcp.signal",
        title="Signal standing",
        max_level="read",
        description="Reputation receipts, portfolio artifacts, and fraud review reads.",
    ),
    McpScopeDefinition(
        id="mcp.compliance",
        title="Compliance exports",
        max_level="read",
        description="Audit export listing and retrieval.",
    ),
    McpScopeDefinition(
        id="mcp.a2a",
        title="A2A and mandates",
        max_level="write",
        description=(
            "Agent card, task contracts, and mandate verification (read); mandate import (write)."
        ),
    ),
    McpScopeDefinition(
        id="mcp.receipts",
        title="Receipts",
        max_level="read",
        description="Settlement, protocol, and agent receipt retrieval plus verification.",
    ),
    McpScopeDefinition(
        id="mcp.evidence",
        title="Completion evidence",
        max_level="write",
        description=(
            "Local evidence validation (read); Harbor completion evidence submission (write)."
        ),
    ),
    McpScopeDefinition(
        id="mcp.spend",
        title="Spend authorization",
        max_level="write",
        description="Intent creation, capability verification, and agent spend authorization.",
    ),
    McpScopeDefinition(
        id="mcp.settlement",
        title="Settlement (live money)",
        max_level="write",
        description=(
            "Funding intents and confirming settlement. Never included in a preset; "
            "must be chosen explicitly."
        ),
    ),
    McpScopeDefinition(
        id="mcp.sandbox",
        title="Sandbox guardrails",
        max_level="write",
        description="Sandbox guardrail bootstrap and sandbox guardrail evidence.",
    ),
)

MCP_TOOL_SCOPES: dict[str, McpScope] = {
    "paybond_get_principal": McpScope("mcp.discovery", "read"),
    "paybond_list_intents": McpScope("mcp.discovery", "read"),
    "paybond_get_intent": McpScope("mcp.discovery", "read"),
    "paybond_explain_policy": McpScope("mcp.discovery", "read"),
    "paybond_get_budget_remaining": McpScope("mcp.discovery", "read"),
    "paybond_get_reputation_receipt": McpScope("mcp.signal", "read"),
    "paybond_get_portfolio_summary": McpScope("mcp.signal", "read"),
    "paybond_get_signed_portfolio_artifact": McpScope("mcp.signal", "read"),
    "paybond_get_fraud_assessment": McpScope("mcp.signal", "read"),
    "paybond_get_fraud_metrics": McpScope("mcp.signal", "read"),
    "paybond_list_audit_exports": McpScope("mcp.compliance", "read"),
    "paybond_get_audit_export": McpScope("mcp.compliance", "read"),
    "paybond_get_a2a_agent_card": McpScope("mcp.a2a", "read"),
    "paybond_list_a2a_task_contracts": McpScope("mcp.a2a", "read"),
    "paybond_get_a2a_task_contract": McpScope("mcp.a2a", "read"),
    "paybond_verify_agent_mandate_v1": McpScope("mcp.a2a", "read"),
    "paybond_verify_agent_recognition_proof_v1": McpScope("mcp.a2a", "read"),
    "paybond_import_agent_mandate_v1": McpScope("mcp.a2a", "write"),
    "paybond_get_settlement_receipt_v1": McpScope("mcp.receipts", "read"),
    "paybond_get_agent_receipt_v1": McpScope("mcp.receipts", "read"),
    "paybond_verify_agent_receipt_v1": McpScope("mcp.receipts", "read"),
    "paybond_verify_protocol_receipt_v1": McpScope("mcp.receipts", "read"),
    "paybond_validate_completion_evidence": McpScope("mcp.evidence", "read"),
    "paybond_submit_evidence": McpScope("mcp.evidence", "write"),
    "paybond_submit_spend_evidence": McpScope("mcp.evidence", "write"),
    "paybond_create_intent": McpScope("mcp.spend", "write"),
    "paybond_create_spend_intent": McpScope("mcp.spend", "write"),
    "paybond_authorize_agent_spend": McpScope("mcp.spend", "write"),
    "paybond_verify_capability": McpScope("mcp.spend", "write"),
    "paybond_fund_intent": McpScope("mcp.settlement", "write"),
    "paybond_confirm_settlement": McpScope("mcp.settlement", "write"),
    "paybond_bootstrap_sandbox_guardrail": McpScope("mcp.sandbox", "write"),
    "paybond_submit_sandbox_guardrail_evidence": McpScope("mcp.sandbox", "write"),
}

MCP_RESOURCE_SCOPES: dict[str, McpScope] = {
    "paybond-agent-receipt": McpScope("mcp.receipts", "read"),
}

MCP_SCOPE_ROUTES: tuple[McpScopeRoute, ...] = (
    McpScopeRoute("GET", "/v1/auth/principal", "mcp.discovery", "read"),
    McpScopeRoute("GET", "/harbor/operator/v1/intents", "mcp.discovery", "read"),
    McpScopeRoute("GET", "/harbor/operator/v1/intents/{intent_id}", "mcp.discovery", "read"),
    McpScopeRoute("POST", "/v1/spend/preflight", "mcp.discovery", "read"),
    McpScopeRoute("GET", "/reputation/{operator_did}", "mcp.signal", "read"),
    McpScopeRoute("GET", "/signal/v1/portfolio/summary", "mcp.signal", "read"),
    McpScopeRoute("GET", "/signal/v1/portfolio/signed-export", "mcp.signal", "read"),
    McpScopeRoute("GET", "/signal/v1/operators/{operator_did}/review-status", "mcp.signal", "read"),
    McpScopeRoute("GET", "/signal/v1/fraud/metrics", "mcp.signal", "read"),
    McpScopeRoute("GET", "/v1/compliance/audit-exports", "mcp.compliance", "read"),
    McpScopeRoute("GET", "/v1/compliance/audit-exports/{job_id}", "mcp.compliance", "read"),
    McpScopeRoute("GET", "/.well-known/agent-card.json", "mcp.a2a", "read"),
    McpScopeRoute("GET", "/protocol/v2/a2a/task-contracts", "mcp.a2a", "read"),
    McpScopeRoute("GET", "/protocol/v2/a2a/task-contracts/{contract_id}", "mcp.a2a", "read"),
    McpScopeRoute("POST", "/protocol/v2/mandates/verify", "mcp.a2a", "read"),
    McpScopeRoute("POST", "/protocol/v2/recognition/verify", "mcp.a2a", "read"),
    McpScopeRoute("POST", "/protocol/v2/mandates", "mcp.a2a", "write"),
    McpScopeRoute("GET", "/protocol/v2/receipts/{receipt_id}", "mcp.receipts", "read"),
    McpScopeRoute("POST", "/protocol/v2/receipts/verify", "mcp.receipts", "read"),
    McpScopeRoute("GET", "/protocol/v2/agent-receipts", "mcp.receipts", "read"),
    McpScopeRoute("GET", "/protocol/v2/agent-receipts/{receipt_id}", "mcp.receipts", "read"),
    McpScopeRoute("POST", "/protocol/v2/agent-receipts/verify", "mcp.receipts", "read"),
    McpScopeRoute("POST", "/harbor/intents/{intent_id}/evidence", "mcp.evidence", "write"),
    McpScopeRoute("POST", "/verify", "mcp.spend", "write"),
    McpScopeRoute("POST", "/harbor/intents", "mcp.spend", "write"),
    McpScopeRoute("POST", "/harbor/intents/{intent_id}/fund", "mcp.settlement", "write"),
    McpScopeRoute(
        "POST", "/harbor/intents/{intent_id}/settlement/confirm", "mcp.settlement", "write"
    ),
    McpScopeRoute("POST", "/v1/sandbox/guardrails/bootstrap", "mcp.sandbox", "write"),
    McpScopeRoute("POST", "/v1/sandbox/guardrails/{intent_id}/evidence", "mcp.sandbox", "write"),
)

MCP_SCOPE_PRESETS: tuple[McpScopePreset, ...] = (
    McpScopePreset(
        id="mcp-readonly",
        title="MCP Readonly Discovery",
        description=(
            "Identity, Harbor intent reads, Signal standing, compliance exports, "
            "and receipts. No writes."
        ),
        scopes=(
            McpScope("mcp.discovery", "read"),
            McpScope("mcp.signal", "read"),
            McpScope("mcp.compliance", "read"),
            McpScope("mcp.receipts", "read"),
        ),
    ),
    McpScopePreset(
        id="mcp-spend-operator",
        title="MCP Spend Operator",
        description=(
            "Readonly discovery plus intent creation, spend authorization, "
            "and completion evidence. No settlement."
        ),
        scopes=(
            McpScope("mcp.discovery", "read"),
            McpScope("mcp.signal", "read"),
            McpScope("mcp.compliance", "read"),
            McpScope("mcp.receipts", "read"),
            McpScope("mcp.spend", "write"),
            McpScope("mcp.evidence", "write"),
        ),
    ),
    McpScopePreset(
        id="mcp-sandbox-agent",
        title="MCP Sandbox Agent",
        description=(
            "Sandbox guardrail bootstrap and evidence plus the discovery and "
            "spend authorization path."
        ),
        scopes=(
            McpScope("mcp.discovery", "read"),
            McpScope("mcp.sandbox", "write"),
            McpScope("mcp.spend", "write"),
        ),
    ),
)

_SCOPE_DEFINITION_BY_ID: dict[str, McpScopeDefinition] = {
    definition.id: definition for definition in MCP_SCOPE_DEFINITIONS
}
_PRESET_BY_ID: dict[str, McpScopePreset] = {preset.id: preset for preset in MCP_SCOPE_PRESETS}


def _level_rank(level: str) -> int:
    return 1 if level == "write" else 0


def _normalize_level(raw: Any) -> McpScopeLevel | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    if value in ("read", "write"):
        return value  # type: ignore[return-value]
    return None


def format_mcp_scope(scope: McpScope) -> str:
    """Render a scope as its canonical ``mcp.spend:write`` wire/CLI token."""

    return f"{scope.scope}:{scope.level}"


def mcp_scope_definition(scope_id: str) -> McpScopeDefinition | None:
    """Return the catalog definition for a scope id, or None when unknown."""

    return _SCOPE_DEFINITION_BY_ID.get((scope_id or "").strip())


def tools_for_mcp_scope(scope_id: str) -> list[str]:
    """Return the sorted tool names unlocked by one scope id (empty when unknown)."""

    target = (scope_id or "").strip()
    return sorted(name for name, required in MCP_TOOL_SCOPES.items() if required.scope == target)


def parse_mcp_scopes(raw: Any) -> list[McpScope]:
    """Parse the ``mcp_scopes`` value from a ``GET /v1/auth/principal`` response.

    Deliberately tolerant so a gateway that ships new scope ids ahead of Kit does
    not break existing hosts: unknown scope ids, unknown levels, and malformed
    entries are dropped rather than raising. Duplicate scope ids collapse to the
    highest granted level. Accepts both the object wire form
    (``{"scope": "mcp.spend", "level": "write"}``) and the ``mcp.spend:write``
    string form.
    """

    if not isinstance(raw, (list, tuple)):
        return []
    by_scope: dict[str, McpScopeLevel] = {}
    for entry in raw:
        scope_id: str | None = None
        level: McpScopeLevel | None = None
        if isinstance(entry, str):
            head, _, tail = entry.partition(":")
            scope_id = head.strip()
            level = _normalize_level(tail)
        elif isinstance(entry, McpScope):
            scope_id = entry.scope.strip()
            level = _normalize_level(entry.level)
        elif isinstance(entry, dict):
            candidate = entry.get("scope")
            scope_id = candidate.strip() if isinstance(candidate, str) else None
            level = _normalize_level(entry.get("level"))
        if not scope_id or level is None or scope_id not in _SCOPE_DEFINITION_BY_ID:
            continue
        existing = by_scope.get(scope_id)
        if existing is None or _level_rank(level) > _level_rank(existing):
            by_scope[scope_id] = level
    return [
        McpScope(definition.id, by_scope[definition.id])
        for definition in MCP_SCOPE_DEFINITIONS
        if definition.id in by_scope
    ]


def parse_mcp_scope_token(raw: str) -> McpScope:
    """Parse one ``mcp.spend:write`` CLI/config token.

    Raises ``ValueError`` with an actionable message listing the catalog scope ids
    so callers can fail before a gateway round-trip.
    """

    value = (raw or "").strip()
    if not value:
        raise ValueError("invalid MCP scope (expected <scope-id>:read|write)")
    separator = value.rfind(":")
    if separator <= 0 or separator == len(value) - 1:
        raise ValueError(
            f"invalid MCP scope {value} (expected <scope-id>:read|write, e.g. mcp.spend:write)"
        )
    scope_id = value[:separator].strip()
    level = _normalize_level(value[separator + 1 :])
    if level is None:
        raise ValueError(f"invalid MCP scope level in {value} (expected read or write)")
    definition = _SCOPE_DEFINITION_BY_ID.get(scope_id)
    if definition is None:
        known = ", ".join(candidate.id for candidate in MCP_SCOPE_DEFINITIONS)
        raise ValueError(f"unknown MCP scope {scope_id} (expected one of {known})")
    if _level_rank(level) > _level_rank(definition.max_level):
        raise ValueError(
            f"MCP scope {scope_id} supports at most level {definition.max_level}; got {level}"
        )
    return McpScope(definition.id, level)


def normalize_mcp_scopes(scopes: list[McpScope] | tuple[McpScope, ...]) -> list[McpScope]:
    """Deduplicate scopes in catalog order, keeping the highest granted level."""

    return parse_mcp_scopes(list(scopes))


def scope_satisfies(granted: list[McpScope] | tuple[McpScope, ...], required: McpScope) -> bool:
    """Return True when ``granted`` covers ``required``; ``write`` satisfies ``read``."""

    return any(
        entry.scope == required.scope and _level_rank(entry.level) >= _level_rank(required.level)
        for entry in granted
    )


def required_scope_for_tool(name: str) -> McpScope | None:
    """Return the required scope for an MCP tool name, or None when unmapped."""

    return MCP_TOOL_SCOPES.get((name or "").strip())


def required_scope_for_resource(name: str) -> McpScope | None:
    """Return the required scope for an MCP resource name, or None when unmapped."""

    return MCP_RESOURCE_SCOPES.get((name or "").strip())


def tool_allowed_by_scope(name: str, granted: list[McpScope] | tuple[McpScope, ...]) -> bool:
    """Scope decision for one tool under a restricted-key grant.

    Fails closed: a tool name absent from the catalog is denied, so a newly added
    tool cannot be exposed to a restricted key before it is mapped to a scope.
    """

    required = required_scope_for_tool(name)
    if required is None:
        return False
    return scope_satisfies(granted, required)


def preset_scopes(preset_id: str) -> list[McpScope] | None:
    """Return the scopes granted by a preset id, or None when the preset is unknown."""

    preset = _PRESET_BY_ID.get((preset_id or "").strip())
    if preset is None:
        return None
    return list(preset.scopes)


def mcp_scope_preset(preset_id: str) -> McpScopePreset | None:
    """Return preset metadata for a preset id, or None when the preset is unknown."""

    return _PRESET_BY_ID.get((preset_id or "").strip())


def classify_paybond_api_key(api_key: str) -> PaybondApiKeyKind:
    """Classify a Paybond API key by prefix only.

    Never parses, hashes, or logs secret material — only the public prefix is
    inspected so callers can pick the right permission model.
    """

    value = (api_key or "").strip()
    if value.startswith(RESTRICTED_API_KEY_PREFIX):
        return "restricted"
    # MCP OAuth access tokens are always scope-capped (gateway wires
    # key_kind=restricted for wire compatibility). Classify them the same so
    # principal-resolution failures fail closed.
    if value.startswith(MCP_OAUTH_ACCESS_TOKEN_PREFIX):
        return "restricted"
    if value.startswith(STANDARD_API_KEY_PREFIX):
        return "standard"
    return "unknown"


def is_restricted_paybond_api_key(api_key: str) -> bool:
    """Return True when the key string carries the restricted ``paybond_rk_`` prefix."""

    return classify_paybond_api_key(api_key) == "restricted"


__all__ = [
    "MCP_RESOURCE_SCOPES",
    "MCP_SCOPE_CATALOG_VERSION",
    "MCP_SCOPE_DEFINITIONS",
    "MCP_SCOPE_LEVELS",
    "MCP_SCOPE_PRESETS",
    "MCP_SCOPE_ROUTES",
    "MCP_TOOL_SCOPES",
    "RESTRICTED_API_KEY_PREFIX",
    "STANDARD_API_KEY_PREFIX",
    "McpScope",
    "McpScopeDefinition",
    "McpScopeLevel",
    "McpScopePreset",
    "McpScopeRoute",
    "PaybondApiKeyKind",
    "classify_paybond_api_key",
    "format_mcp_scope",
    "is_restricted_paybond_api_key",
    "mcp_scope_definition",
    "mcp_scope_preset",
    "normalize_mcp_scopes",
    "parse_mcp_scope_token",
    "parse_mcp_scopes",
    "preset_scopes",
    "required_scope_for_resource",
    "required_scope_for_tool",
    "scope_satisfies",
    "tool_allowed_by_scope",
    "tools_for_mcp_scope",
]
