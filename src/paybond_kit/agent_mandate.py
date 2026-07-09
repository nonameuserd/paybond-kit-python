"""Local verification for protocol-v2 signed AgentMandateV1 envelopes.

Canonical JSON matches Go gateway ``marshalCanonicalAgentMandate`` (fixed struct field
order and HTML-safe ``\\u`` escapes), not Kit's generic JCS-style ``normalize_json``.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

AGENT_MANDATE_SCHEMA_VERSION = 1
AGENT_MANDATE_KIND_V1 = "paybond.agent_mandate_v1"
AGENT_MANDATE_SIGNING_ALGORITHM_ED25519_SHA256 = "ed25519-sha256-json-v1"

AGENT_AUTHORIZATION_KIND_PRINCIPAL = "principal"
AGENT_AUTHORIZATION_KIND_TENANT = "tenant"

HUMAN_PRESENCE_MODE_HUMAN_PRESENT = "human_present"
HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT = "human_not_present"

CONSTRAINT_REFERENCE_KIND_PREDICATE = "predicate"
CONSTRAINT_REFERENCE_KIND_POLICY = "policy"

SCOPE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,127}$")
CURRENCY_RE = re.compile(r"^[a-z0-9_]{3,16}$")
HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
MAX_TENANT_ID_LEN = 256

SETTLEMENT_RAILS = frozenset(
    {
        "stripe_connect",
        "stripe_ach_debit",
        "stripe_mpp",
        "x402_usdc_base",
    }
)


class AgentMandateAuthorization(TypedDict):
    kind: str
    tenant_id: str
    principal_subject: str
    principal_type: str


class AgentMandateAgentIdentity(TypedDict):
    subject: str
    issuer: str
    key_id: str
    display_name: str


class AgentMandateSpendCeiling(TypedDict):
    amount_minor: int
    currency: str


class AgentMandateSettlementRailPolicy(TypedDict):
    default_rail: str
    allowed_rails: list[str]


class AgentMandateConstraintReference(TypedDict):
    kind: str
    id: str
    version: str
    digest_sha256_hex: str
    uri: str


class AgentMandateV1(TypedDict):
    schema_version: int
    kind: str
    authorization: AgentMandateAuthorization
    agent: AgentMandateAgentIdentity
    allowed_actions: list[str]
    allowed_tools: list[str]
    spend_ceiling: AgentMandateSpendCeiling
    settlement: AgentMandateSettlementRailPolicy
    constraint: AgentMandateConstraintReference
    expires_at: str
    nonce: str
    human_presence_mode: str


class SignedAgentMandateV1(AgentMandateV1):
    signing_algorithm: str
    message_digest_sha256_hex: str
    signing_public_key_ed25519_hex: str
    ed25519_signature_hex: str


def _read_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _read_string(value: Any, fallback: str = "") -> str:
    return value if isinstance(value, str) else fallback


def _read_number(value: Any, fallback: int = 0) -> int:
    if isinstance(value, bool):
        return fallback
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return fallback


def _read_string_array(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def go_json_escape(text: str) -> str:
    """Match Go ``encoding/json`` HTML-safe escaping on top of standard JSON encoding."""
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def round_utc_to_seconds(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(microsecond=0)


def format_rfc3339_nano_utc(value: datetime) -> str:
    """Format UTC timestamps like Go ``time.RFC3339Nano`` with zero sub-second precision omitted."""
    rounded = round_utc_to_seconds(value)
    iso = rounded.isoformat().replace("+00:00", "Z")
    if iso.endswith(".000Z"):
        return f"{iso[:-5]}Z"
    return iso


def _parse_timestamp(value: Any, err_msg: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value
    if isinstance(value, str):
        trimmed = value.strip()
        if not trimmed:
            raise ValueError(err_msg)
        normalized = trimmed.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(err_msg) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    raise ValueError(err_msg)


def _parse_tenant_id(raw: str, label: str) -> str:
    trimmed = raw.strip()
    if not trimmed:
        raise ValueError(f"{label}: tenant: id is missing")
    if len(trimmed) > MAX_TENANT_ID_LEN:
        raise ValueError(f"{label}: tenant: id exceeds max length ({MAX_TENANT_ID_LEN})")
    if not TENANT_ID_RE.fullmatch(trimmed):
        raise ValueError(
            f"{label}: tenant: id must match [a-z0-9][a-z0-9._-]* "
            "(lowercase alphanumeric, dots, underscores, hyphens)"
        )
    return trimmed


def _normalize_scope_set(raw: list[str], field: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        value = item.strip().lower()
        if value == "":
            raise ValueError(f"agent mandate: {field} contains an empty value")
        if not SCOPE_TOKEN_RE.fullmatch(value):
            raise ValueError(f"agent mandate: {field} value {value!r} is not canonical")
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    out.sort()
    return out


def _normalize_allowed_rails(raw: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        rail = item.strip().lower()
        if rail not in SETTLEMENT_RAILS:
            raise ValueError(f"agent mandate: settlement.allowed_rails: unknown settlement rail {item!r}")
        if rail in seen:
            continue
        seen.add(rail)
        out.append(rail)
    out.sort()
    return out


def _read_agent_mandate_fields(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": _read_number(raw.get("schema_version")),
        "kind": _read_string(raw.get("kind")),
        "authorization": _read_object(raw.get("authorization")) or {},
        "agent": _read_object(raw.get("agent")) or {},
        "allowed_actions": _read_string_array(raw.get("allowed_actions")),
        "allowed_tools": _read_string_array(raw.get("allowed_tools")),
        "spend_ceiling": _read_object(raw.get("spend_ceiling")) or {},
        "settlement": _read_object(raw.get("settlement")) or {},
        "constraint": _read_object(raw.get("constraint")) or {},
        "expires_at": raw.get("expires_at"),
        "nonce": _read_string(raw.get("nonce")),
        "human_presence_mode": _read_string(raw.get("human_presence_mode")),
    }


def normalize_agent_mandate_v1(mandate: dict[str, Any] | AgentMandateV1) -> AgentMandateV1:
    """Validate and canonicalize mandate fields for hashing and signing."""
    raw = _read_agent_mandate_fields(_read_object(mandate) or {})

    schema_version = raw["schema_version"]
    if schema_version in (0, AGENT_MANDATE_SCHEMA_VERSION):
        schema_version = AGENT_MANDATE_SCHEMA_VERSION
    else:
        raise ValueError(f"agent mandate: unsupported schema_version {schema_version}")

    kind = raw["kind"].strip()
    if kind in ("", AGENT_MANDATE_KIND_V1):
        kind = AGENT_MANDATE_KIND_V1
    else:
        raise ValueError(f"agent mandate: unsupported kind {kind!r}")

    authorization_raw = raw["authorization"]
    authorization_kind = _read_string(authorization_raw.get("kind")).strip().lower()
    if authorization_kind not in (AGENT_AUTHORIZATION_KIND_PRINCIPAL, AGENT_AUTHORIZATION_KIND_TENANT):
        raise ValueError(
            f"agent mandate: authorization.kind must be {AGENT_AUTHORIZATION_KIND_PRINCIPAL!r} "
            f"or {AGENT_AUTHORIZATION_KIND_TENANT!r}"
        )

    tenant_id = _parse_tenant_id(
        _read_string(authorization_raw.get("tenant_id")),
        "agent mandate: authorization.tenant_id",
    )
    principal_subject = _read_string(authorization_raw.get("principal_subject")).strip()
    principal_type = _read_string(authorization_raw.get("principal_type")).strip().lower()

    if authorization_kind == AGENT_AUTHORIZATION_KIND_PRINCIPAL:
        if not principal_subject:
            raise ValueError(
                "agent mandate: authorization.principal_subject is required for principal-scoped mandates"
            )
        if principal_type and not SCOPE_TOKEN_RE.fullmatch(principal_type):
            raise ValueError(f"agent mandate: authorization.principal_type {principal_type!r} is not canonical")
    elif principal_subject or principal_type:
        raise ValueError("agent mandate: tenant-scoped mandates must not set principal_subject or principal_type")

    agent_raw = raw["agent"]
    agent_subject = _read_string(agent_raw.get("subject")).strip()
    if not agent_subject:
        raise ValueError("agent mandate: agent.subject is required")

    allowed_actions = _normalize_scope_set(raw["allowed_actions"], "allowed_actions")
    allowed_tools = _normalize_scope_set(raw["allowed_tools"], "allowed_tools")
    if not allowed_actions and not allowed_tools:
        raise ValueError("agent mandate: at least one allowed action or allowed tool is required")

    spend_ceiling_raw = raw["spend_ceiling"]
    amount_minor = _read_number(spend_ceiling_raw.get("amount_minor"))
    if amount_minor <= 0:
        raise ValueError("agent mandate: spend_ceiling.amount_minor must be greater than zero")
    currency = _read_string(spend_ceiling_raw.get("currency")).strip().lower()
    if not CURRENCY_RE.fullmatch(currency):
        raise ValueError(f"agent mandate: spend_ceiling.currency {currency!r} is not canonical")

    settlement_raw = raw["settlement"]
    default_rail = _read_string(settlement_raw.get("default_rail")).strip().lower()
    allowed_rails = _normalize_allowed_rails(_read_string_array(settlement_raw.get("allowed_rails")))
    if not default_rail:
        raise ValueError("agent mandate: settlement.default_rail is required")
    if not allowed_rails:
        raise ValueError("agent mandate: settlement.allowed_rails must contain at least one rail")
    if default_rail not in allowed_rails:
        raise ValueError("agent mandate: settlement.default_rail must be present in settlement.allowed_rails")

    constraint_raw = raw["constraint"]
    constraint_kind = _read_string(constraint_raw.get("kind")).strip().lower()
    if constraint_kind not in (CONSTRAINT_REFERENCE_KIND_PREDICATE, CONSTRAINT_REFERENCE_KIND_POLICY):
        raise ValueError(
            f"agent mandate: constraint.kind must be {CONSTRAINT_REFERENCE_KIND_PREDICATE!r} "
            f"or {CONSTRAINT_REFERENCE_KIND_POLICY!r}"
        )
    constraint_id = _read_string(constraint_raw.get("id")).strip()
    constraint_version = _read_string(constraint_raw.get("version")).strip()
    constraint_digest = _read_string(constraint_raw.get("digest_sha256_hex")).strip().lower()
    constraint_uri = _read_string(constraint_raw.get("uri")).strip()
    if constraint_digest and not HEX64_RE.fullmatch(constraint_digest):
        raise ValueError("agent mandate: constraint.digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest")
    if not constraint_id and not constraint_uri and not constraint_digest:
        raise ValueError("agent mandate: constraint must set id, uri, or digest_sha256_hex")

    nonce = raw["nonce"].strip()
    if not nonce:
        raise ValueError("agent mandate: nonce is required")
    if len(nonce) > 256:
        raise ValueError("agent mandate: nonce must be 256 bytes or fewer")

    human_presence_mode = raw["human_presence_mode"].strip().lower()
    if human_presence_mode not in (HUMAN_PRESENCE_MODE_HUMAN_PRESENT, HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT):
        raise ValueError(
            f"agent mandate: human_presence_mode must be {HUMAN_PRESENCE_MODE_HUMAN_PRESENT!r} "
            f"or {HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT!r}"
        )

    expires_at = format_rfc3339_nano_utc(_parse_timestamp(raw["expires_at"], "agent mandate: expires_at is required"))

    return {
        "schema_version": schema_version,
        "kind": kind,
        "authorization": {
            "kind": authorization_kind,
            "tenant_id": tenant_id,
            "principal_subject": principal_subject,
            "principal_type": principal_type,
        },
        "agent": {
            "subject": agent_subject,
            "issuer": _read_string(agent_raw.get("issuer")).strip(),
            "key_id": _read_string(agent_raw.get("key_id")).strip(),
            "display_name": _read_string(agent_raw.get("display_name")).strip(),
        },
        "allowed_actions": allowed_actions,
        "allowed_tools": allowed_tools,
        "spend_ceiling": {
            "amount_minor": amount_minor,
            "currency": currency,
        },
        "settlement": {
            "default_rail": default_rail,
            "allowed_rails": allowed_rails,
        },
        "constraint": {
            "kind": constraint_kind,
            "id": constraint_id,
            "version": constraint_version,
            "digest_sha256_hex": constraint_digest,
            "uri": constraint_uri,
        },
        "expires_at": expires_at,
        "nonce": nonce,
        "human_presence_mode": human_presence_mode,
    }


def _marshal_canonical_agent_mandate(mandate: AgentMandateV1) -> bytes:
    payload = {
        "schema_version": mandate["schema_version"],
        "kind": mandate["kind"],
        "authorization": {
            "kind": mandate["authorization"]["kind"],
            "tenant_id": mandate["authorization"]["tenant_id"],
            "principal_subject": mandate["authorization"]["principal_subject"],
            "principal_type": mandate["authorization"]["principal_type"],
        },
        "agent": {
            "subject": mandate["agent"]["subject"],
            "issuer": mandate["agent"]["issuer"],
            "key_id": mandate["agent"]["key_id"],
            "display_name": mandate["agent"]["display_name"],
        },
        "allowed_actions": list(mandate["allowed_actions"]),
        "allowed_tools": list(mandate["allowed_tools"]),
        "spend_ceiling": {
            "amount_minor": mandate["spend_ceiling"]["amount_minor"],
            "currency": mandate["spend_ceiling"]["currency"],
        },
        "settlement": {
            "default_rail": mandate["settlement"]["default_rail"],
            "allowed_rails": list(mandate["settlement"]["allowed_rails"]),
        },
        "constraint": {
            "kind": mandate["constraint"]["kind"],
            "id": mandate["constraint"]["id"],
            "version": mandate["constraint"]["version"],
            "digest_sha256_hex": mandate["constraint"]["digest_sha256_hex"],
            "uri": mandate["constraint"]["uri"],
        },
        "expires_at": mandate["expires_at"],
        "nonce": mandate["nonce"],
        "human_presence_mode": mandate["human_presence_mode"],
    }
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return go_json_escape(text).encode("utf-8")


def canonical_agent_mandate_json_bytes(mandate: dict[str, Any] | AgentMandateV1) -> bytes:
    """Return canonical mandate bytes used for digesting and Ed25519 signing."""
    return _marshal_canonical_agent_mandate(normalize_agent_mandate_v1(mandate))


def agent_mandate_digest_sha256_hex(mandate: dict[str, Any] | AgentMandateV1) -> str:
    """Return the portable SHA-256 digest over canonical mandate JSON as lowercase hex."""
    return hashlib.sha256(canonical_agent_mandate_json_bytes(mandate)).hexdigest()


def sign_agent_mandate_v1(signing_seed: bytes, mandate: dict[str, Any] | AgentMandateV1) -> SignedAgentMandateV1:
    """Validate, canonicalize, and sign a mandate with Ed25519-over-SHA-256(canonical JSON)."""
    if len(signing_seed) != 32:
        raise ValueError("agent mandate: signing key must be an ed25519 private key")

    normalized = normalize_agent_mandate_v1(mandate)
    body = _marshal_canonical_agent_mandate(normalized)
    digest = hashlib.sha256(body).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(signing_seed)
    signature = private_key.sign(digest)
    public_key = private_key.public_key().public_bytes_raw()

    return {
        **normalized,
        "signing_algorithm": AGENT_MANDATE_SIGNING_ALGORITHM_ED25519_SHA256,
        "message_digest_sha256_hex": digest.hex(),
        "signing_public_key_ed25519_hex": public_key.hex(),
        "ed25519_signature_hex": signature.hex(),
    }


def verify_signed_agent_mandate_v1(
    signed: dict[str, Any] | SignedAgentMandateV1,
    now: datetime | None = None,
) -> None:
    """Check structure, expiry, digest recompute, and detached Ed25519 signature."""
    raw = _read_object(signed) or {}
    mandate_fields = _read_agent_mandate_fields(raw)
    normalized = normalize_agent_mandate_v1(mandate_fields)

    now_utc = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    expires_at = _parse_timestamp(normalized["expires_at"], "agent mandate: expires_at is required")
    if expires_at <= now_utc:
        raise ValueError(f"agent mandate: expired at {normalized['expires_at']}")

    signing_algorithm = _read_string(raw.get("signing_algorithm")).strip()
    if signing_algorithm != AGENT_MANDATE_SIGNING_ALGORITHM_ED25519_SHA256:
        raise ValueError(
            f"agent mandate: signing_algorithm must be {AGENT_MANDATE_SIGNING_ALGORITHM_ED25519_SHA256!r}"
        )

    body = _marshal_canonical_agent_mandate(normalized)
    digest = hashlib.sha256(body).digest()
    message_digest = _read_string(raw.get("message_digest_sha256_hex")).strip().lower()
    if not HEX64_RE.fullmatch(message_digest):
        raise ValueError("agent mandate: message_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest")
    if message_digest != digest.hex():
        raise ValueError("agent mandate: message digest mismatch")

    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(_read_string(raw.get("signing_public_key_ed25519_hex"))))
        signature = bytes.fromhex(_read_string(raw.get("ed25519_signature_hex")))
    except ValueError as exc:
        raise ValueError("agent mandate: invalid signing_public_key_ed25519_hex") from exc

    if len(public_key.public_bytes_raw()) != 32:
        raise ValueError("agent mandate: invalid signing_public_key_ed25519_hex")
    if len(signature) != 64:
        raise ValueError("agent mandate: invalid ed25519_signature_hex")

    try:
        public_key.verify(signature, digest)
    except InvalidSignature as exc:
        raise ValueError("agent mandate: ed25519 signature verification failed") from exc
