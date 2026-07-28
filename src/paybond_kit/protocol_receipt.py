"""Local verification for protocol-v2 authorization and settlement receipts.

Canonical JSON matches the Go gateway protocol receipt marshalers (fixed struct field
order, signing fields stripped, RFC3339Nano UTC timestamps, HTML-safe ``\\u`` escapes).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, NotRequired, TypedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from paybond_kit.agent_mandate import (
    AGENT_AUTHORIZATION_KIND_PRINCIPAL,
    AGENT_AUTHORIZATION_KIND_TENANT,
    CURRENCY_RE,
    HEX64_RE,
    HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT,
    HUMAN_PRESENCE_MODE_HUMAN_PRESENT,
    AgentMandateAgentIdentity,
    AgentMandateAuthorization,
    AgentMandateConstraintReference,
    AgentMandateSettlementRailPolicy,
    AgentMandateSpendCeiling,
    _parse_tenant_id,
    _parse_timestamp,
    _read_number,
    _read_object,
    _read_string,
    _read_string_array,
    format_rfc3339_nano_utc,
    go_json_escape,
)

PROTOCOL_RECEIPT_SCHEMA_VERSION = 1
PROTOCOL_RECEIPT_VERSION_V1 = "1"
PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256 = "ed25519-sha256-json-v1"

PROTOCOL_AUTHORIZATION_RECEIPT_KIND_V1 = "paybond.protocol_authorization_receipt_v1"
PROTOCOL_SETTLEMENT_RECEIPT_KIND_V1 = "paybond.protocol_settlement_receipt_v1"

PROTOCOL_RECEIPT_STATUS_AUTHORIZED = "authorized"

# Partner transport metadata `source_protocol` constants for imported mandates and exported receipts.
PROTOCOL_SOURCE_AP2 = "ap2"
PROTOCOL_SOURCE_ACP = "acp"
PROTOCOL_SOURCE_UCP = "ucp"

PROTOCOL_SETTLEMENT_TERMINAL_STATES = frozenset(
    {
        "released",
        "refunded",
        "resolved_split",
        "escalated_external",
    }
)

SCOPE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,127}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


class ProtocolTransportBindingV1(TypedDict):
    source_protocol: str
    partner_platform: NotRequired[str]
    external_authorization_id: NotRequired[str]
    request_id: NotRequired[str]


class ProtocolAuthorizationReceiptV1(TypedDict):
    schema_version: int
    kind: str
    receipt_version: str
    receipt_id: str
    issued_at: str
    status: str
    intent_id: str
    tenant_id: str
    verifier_id: str
    transport_binding: ProtocolTransportBindingV1
    mandate_digest_sha256_hex: str
    imported_mandate_signing_public_key_ed25519_hex: str
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
    signing_algorithm: str
    message_digest_sha256_hex: str
    signing_public_key_ed25519_hex: str
    ed25519_signature_hex: str


class ProtocolSettlementReceiptV1(TypedDict):
    schema_version: int
    kind: str
    receipt_version: str
    receipt_id: str
    issued_at: str
    intent_id: str
    tenant_id: str
    verifier_id: str
    transport_binding: ProtocolTransportBindingV1
    authorization_receipt_id: str
    mandate_digest_sha256_hex: str
    harbor_state: str
    predicate_passed: NotRequired[bool]
    settlement_rail: str
    settlement_mode: str
    principal_did: str
    payee_did: str
    currency: str
    amount_cents: int
    terminal_observed_at: str
    signing_algorithm: str
    message_digest_sha256_hex: str
    signing_public_key_ed25519_hex: str
    ed25519_signature_hex: str


def _normalize_scope_set(raw: list[str], field: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        value = item.strip().lower()
        if value == "":
            raise ValueError(f"{field} contains an empty value")
        if not SCOPE_TOKEN_RE.fullmatch(value):
            raise ValueError(f"{field} value {value!r} is not canonical")
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    out.sort()
    return out


def _normalize_timestamp(value: Any, err_msg: str) -> str:
    return format_rfc3339_nano_utc(_parse_timestamp(value, err_msg))


def _normalize_transport_binding(raw: dict[str, Any], label: str) -> ProtocolTransportBindingV1:
    source_protocol = _read_string(raw.get("source_protocol")).strip().lower()
    if source_protocol == "":
        source_protocol = PROTOCOL_SOURCE_AP2
    if not SCOPE_TOKEN_RE.fullmatch(source_protocol):
        raise ValueError(f"{label}: source_protocol {source_protocol!r} is not canonical")

    partner_platform = _read_string(raw.get("partner_platform")).strip()
    external_authorization_id = _read_string(raw.get("external_authorization_id")).strip()
    request_id = _read_string(raw.get("request_id")).strip()
    for field, value in (
        ("partner_platform", partner_platform),
        ("external_authorization_id", external_authorization_id),
        ("request_id", request_id),
    ):
        if len(value) > 256:
            raise ValueError(f"{label}: {field} must be 256 bytes or fewer")

    binding: ProtocolTransportBindingV1 = {"source_protocol": source_protocol}
    if partner_platform:
        binding["partner_platform"] = partner_platform
    if external_authorization_id:
        binding["external_authorization_id"] = external_authorization_id
    if request_id:
        binding["request_id"] = request_id
    return binding


def _canonical_transport_binding(binding: ProtocolTransportBindingV1) -> dict[str, Any]:
    out: dict[str, Any] = {"source_protocol": binding["source_protocol"]}
    partner_platform = binding.get("partner_platform")
    if partner_platform:
        out["partner_platform"] = partner_platform
    external_authorization_id = binding.get("external_authorization_id")
    if external_authorization_id:
        out["external_authorization_id"] = external_authorization_id
    request_id = binding.get("request_id")
    if request_id:
        out["request_id"] = request_id
    return out


def normalize_protocol_authorization_receipt_v1(
    receipt: dict[str, Any] | ProtocolAuthorizationReceiptV1,
) -> ProtocolAuthorizationReceiptV1:
    """Validate and canonicalize an authorization receipt for hashing and signing."""
    raw = _read_object(receipt) or {}
    label = "protocol authorization receipt"

    schema_version = _read_number(raw.get("schema_version"))
    if schema_version in (0, PROTOCOL_RECEIPT_SCHEMA_VERSION):
        schema_version = PROTOCOL_RECEIPT_SCHEMA_VERSION
    else:
        raise ValueError(f"{label}: unsupported schema_version {schema_version}")

    kind = _read_string(raw.get("kind")).strip()
    if kind in ("", PROTOCOL_AUTHORIZATION_RECEIPT_KIND_V1):
        kind = PROTOCOL_AUTHORIZATION_RECEIPT_KIND_V1
    else:
        raise ValueError(f"{label}: unsupported kind {kind!r}")

    receipt_version = _read_string(raw.get("receipt_version")).strip()
    if receipt_version in ("", PROTOCOL_RECEIPT_VERSION_V1):
        receipt_version = PROTOCOL_RECEIPT_VERSION_V1
    else:
        raise ValueError(f"{label}: unsupported receipt_version {receipt_version!r}")

    receipt_id = _read_string(raw.get("receipt_id")).strip().lower()
    if receipt_id == "":
        raise ValueError(f"{label}: receipt_id is required")
    if not SCOPE_TOKEN_RE.fullmatch(receipt_id):
        raise ValueError(f"{label}: receipt_id {receipt_id!r} is not canonical")

    intent_id_trimmed = _read_string(raw.get("intent_id")).strip()
    if not UUID_RE.fullmatch(intent_id_trimmed):
        raise ValueError(f"{label}: intent_id must be a canonical UUID")
    intent_id = intent_id_trimmed.lower()

    issued_at = _normalize_timestamp(raw.get("issued_at"), f"{label}: issued_at is required")

    status = _read_string(raw.get("status")).strip().lower()
    if status in ("", PROTOCOL_RECEIPT_STATUS_AUTHORIZED):
        status = PROTOCOL_RECEIPT_STATUS_AUTHORIZED
    else:
        raise ValueError(f"{label}: unsupported status {status!r}")

    tenant_id = _parse_tenant_id(_read_string(raw.get("tenant_id")), f"{label}: tenant_id")

    verifier_id = _read_string(raw.get("verifier_id")).strip().lower()
    if verifier_id == "":
        raise ValueError(f"{label}: verifier_id is required")
    if not SCOPE_TOKEN_RE.fullmatch(verifier_id):
        raise ValueError(f"{label}: verifier_id {verifier_id!r} is not canonical")

    transport_binding = _normalize_transport_binding(
        _read_object(raw.get("transport_binding")) or {},
        f"{label}: transport_binding",
    )

    mandate_digest = _read_string(raw.get("mandate_digest_sha256_hex")).strip().lower()
    if not HEX64_RE.fullmatch(mandate_digest):
        raise ValueError(f"{label}: mandate_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest")

    imported_mandate_pub_key = (
        _read_string(raw.get("imported_mandate_signing_public_key_ed25519_hex")).strip().lower()
    )
    try:
        imported_pub_key_bytes = bytes.fromhex(imported_mandate_pub_key)
    except ValueError as exc:
        raise ValueError(f"{label}: imported_mandate_signing_public_key_ed25519_hex is invalid") from exc
    if len(imported_pub_key_bytes) != 32:
        raise ValueError(f"{label}: imported_mandate_signing_public_key_ed25519_hex is invalid")

    authorization_raw = _read_object(raw.get("authorization")) or {}
    authorization_kind = _read_string(authorization_raw.get("kind")).strip().lower()
    if authorization_kind not in (AGENT_AUTHORIZATION_KIND_PRINCIPAL, AGENT_AUTHORIZATION_KIND_TENANT):
        raise ValueError(
            f"{label}: authorization.kind must be {AGENT_AUTHORIZATION_KIND_PRINCIPAL!r} "
            f"or {AGENT_AUTHORIZATION_KIND_TENANT!r}"
        )
    authorization_tenant_id = _parse_tenant_id(
        _read_string(authorization_raw.get("tenant_id")),
        f"{label}: authorization.tenant_id",
    )
    if authorization_tenant_id != tenant_id:
        raise ValueError(f"{label}: authorization.tenant_id must match tenant_id")

    agent_raw = _read_object(raw.get("agent")) or {}
    agent_subject = _read_string(agent_raw.get("subject")).strip()
    if agent_subject == "":
        raise ValueError(f"{label}: agent.subject is required")

    allowed_actions = _normalize_scope_set(_read_string_array(raw.get("allowed_actions")), f"{label}: allowed_actions")
    allowed_tools = _normalize_scope_set(_read_string_array(raw.get("allowed_tools")), f"{label}: allowed_tools")
    if not allowed_actions and not allowed_tools:
        raise ValueError(f"{label}: at least one allowed action or allowed tool is required")

    spend_ceiling_raw = _read_object(raw.get("spend_ceiling")) or {}
    amount_minor = _read_number(spend_ceiling_raw.get("amount_minor"))
    if amount_minor <= 0:
        raise ValueError(f"{label}: spend_ceiling.amount_minor must be greater than zero")
    currency = _read_string(spend_ceiling_raw.get("currency")).strip().lower()
    if not CURRENCY_RE.fullmatch(currency):
        raise ValueError(f"{label}: spend_ceiling.currency {currency!r} is not canonical")

    settlement_raw = _read_object(raw.get("settlement")) or {}
    default_rail = _read_string(settlement_raw.get("default_rail")).strip().lower()
    if default_rail == "":
        raise ValueError(f"{label}: settlement.default_rail is required")
    allowed_rails = _normalize_scope_set(
        _read_string_array(settlement_raw.get("allowed_rails")),
        f"{label}: settlement.allowed_rails",
    )

    constraint_raw = _read_object(raw.get("constraint")) or {}
    constraint_kind = _read_string(constraint_raw.get("kind")).strip().lower()
    if constraint_kind == "":
        raise ValueError(f"{label}: constraint.kind is required")

    expires_at = _normalize_timestamp(raw.get("expires_at"), f"{label}: expires_at is required")

    nonce = _read_string(raw.get("nonce")).strip()
    if nonce == "":
        raise ValueError(f"{label}: nonce is required")

    human_presence_mode = _read_string(raw.get("human_presence_mode")).strip().lower()
    if human_presence_mode not in (HUMAN_PRESENCE_MODE_HUMAN_PRESENT, HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT):
        raise ValueError(
            f"{label}: human_presence_mode must be {HUMAN_PRESENCE_MODE_HUMAN_PRESENT!r} "
            f"or {HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT!r}"
        )

    signing_algorithm = _read_string(raw.get("signing_algorithm")).strip().lower()
    if signing_algorithm == "":
        signing_algorithm = PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256

    return {
        "schema_version": schema_version,
        "kind": kind,
        "receipt_version": receipt_version,
        "receipt_id": receipt_id,
        "issued_at": issued_at,
        "status": status,
        "intent_id": intent_id,
        "tenant_id": tenant_id,
        "verifier_id": verifier_id,
        "transport_binding": transport_binding,
        "mandate_digest_sha256_hex": mandate_digest,
        "imported_mandate_signing_public_key_ed25519_hex": imported_mandate_pub_key,
        "authorization": {
            "kind": authorization_kind,
            "tenant_id": authorization_tenant_id,
            "principal_subject": _read_string(authorization_raw.get("principal_subject")).strip(),
            "principal_type": _read_string(authorization_raw.get("principal_type")).strip().lower(),
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
            "id": _read_string(constraint_raw.get("id")).strip(),
            "version": _read_string(constraint_raw.get("version")).strip(),
            "digest_sha256_hex": _read_string(constraint_raw.get("digest_sha256_hex")).strip().lower(),
            "uri": _read_string(constraint_raw.get("uri")).strip(),
        },
        "expires_at": expires_at,
        "nonce": nonce,
        "human_presence_mode": human_presence_mode,
        "signing_algorithm": signing_algorithm,
        "message_digest_sha256_hex": _read_string(raw.get("message_digest_sha256_hex")).strip().lower(),
        "signing_public_key_ed25519_hex": _read_string(raw.get("signing_public_key_ed25519_hex")).strip().lower(),
        "ed25519_signature_hex": _read_string(raw.get("ed25519_signature_hex")).strip().lower(),
    }


def normalize_protocol_settlement_receipt_v1(
    receipt: dict[str, Any] | ProtocolSettlementReceiptV1,
) -> ProtocolSettlementReceiptV1:
    """Validate and canonicalize a settlement receipt for hashing and signing."""
    raw = _read_object(receipt) or {}
    label = "protocol settlement receipt"

    schema_version = _read_number(raw.get("schema_version"))
    if schema_version in (0, PROTOCOL_RECEIPT_SCHEMA_VERSION):
        schema_version = PROTOCOL_RECEIPT_SCHEMA_VERSION
    else:
        raise ValueError(f"{label}: unsupported schema_version {schema_version}")

    kind = _read_string(raw.get("kind")).strip()
    if kind in ("", PROTOCOL_SETTLEMENT_RECEIPT_KIND_V1):
        kind = PROTOCOL_SETTLEMENT_RECEIPT_KIND_V1
    else:
        raise ValueError(f"{label}: unsupported kind {kind!r}")

    receipt_version = _read_string(raw.get("receipt_version")).strip()
    if receipt_version in ("", PROTOCOL_RECEIPT_VERSION_V1):
        receipt_version = PROTOCOL_RECEIPT_VERSION_V1
    else:
        raise ValueError(f"{label}: unsupported receipt_version {receipt_version!r}")

    receipt_id = _read_string(raw.get("receipt_id")).strip().lower()
    if receipt_id == "":
        raise ValueError(f"{label}: receipt_id is required")
    if not SCOPE_TOKEN_RE.fullmatch(receipt_id):
        raise ValueError(f"{label}: receipt_id {receipt_id!r} is not canonical")

    intent_id_trimmed = _read_string(raw.get("intent_id")).strip()
    if not UUID_RE.fullmatch(intent_id_trimmed):
        raise ValueError(f"{label}: intent_id must be a canonical UUID")
    intent_id = intent_id_trimmed.lower()
    if receipt_id != intent_id:
        raise ValueError(f"{label}: receipt_id must equal intent_id for Harbor-backed receipts")

    issued_at = _normalize_timestamp(raw.get("issued_at"), f"{label}: issued_at is required")

    tenant_id = _parse_tenant_id(_read_string(raw.get("tenant_id")), f"{label}: tenant_id")

    verifier_id = _read_string(raw.get("verifier_id")).strip().lower()
    if verifier_id == "":
        raise ValueError(f"{label}: verifier_id is required")
    if not SCOPE_TOKEN_RE.fullmatch(verifier_id):
        raise ValueError(f"{label}: verifier_id {verifier_id!r} is not canonical")

    transport_binding = _normalize_transport_binding(
        _read_object(raw.get("transport_binding")) or {},
        f"{label}: transport_binding",
    )

    authorization_receipt_id = _read_string(raw.get("authorization_receipt_id")).strip().lower()
    if authorization_receipt_id == "":
        raise ValueError(f"{label}: authorization_receipt_id is required")
    if not SCOPE_TOKEN_RE.fullmatch(authorization_receipt_id):
        raise ValueError(f"{label}: authorization_receipt_id {authorization_receipt_id!r} is not canonical")

    mandate_digest = _read_string(raw.get("mandate_digest_sha256_hex")).strip().lower()
    if not HEX64_RE.fullmatch(mandate_digest):
        raise ValueError(f"{label}: mandate_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest")

    harbor_state = _read_string(raw.get("harbor_state")).strip().lower()
    if harbor_state not in PROTOCOL_SETTLEMENT_TERMINAL_STATES:
        raise ValueError(
            f"{label}: harbor_state must be released, refunded, resolved_split, or escalated_external"
        )

    predicate_passed = raw.get("predicate_passed") if isinstance(raw.get("predicate_passed"), bool) else None

    settlement_rail = _read_string(raw.get("settlement_rail")).strip().lower()
    if settlement_rail == "":
        raise ValueError(f"{label}: settlement_rail is required")
    settlement_mode = _read_string(raw.get("settlement_mode")).strip()
    if settlement_mode == "":
        raise ValueError(f"{label}: settlement_mode is required")
    principal_did = _read_string(raw.get("principal_did")).strip()
    payee_did = _read_string(raw.get("payee_did")).strip()
    currency = _read_string(raw.get("currency")).strip().lower()
    if currency == "":
        raise ValueError(f"{label}: currency is required")
    amount_cents = _read_number(raw.get("amount_cents"))
    if amount_cents <= 0:
        raise ValueError(f"{label}: amount_cents must be greater than zero")

    terminal_observed_at = _normalize_timestamp(
        raw.get("terminal_observed_at"),
        f"{label}: terminal_observed_at is required",
    )

    signing_algorithm = _read_string(raw.get("signing_algorithm")).strip().lower()
    if signing_algorithm == "":
        signing_algorithm = PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256

    normalized: ProtocolSettlementReceiptV1 = {
        "schema_version": schema_version,
        "kind": kind,
        "receipt_version": receipt_version,
        "receipt_id": receipt_id,
        "issued_at": issued_at,
        "intent_id": intent_id,
        "tenant_id": tenant_id,
        "verifier_id": verifier_id,
        "transport_binding": transport_binding,
        "authorization_receipt_id": authorization_receipt_id,
        "mandate_digest_sha256_hex": mandate_digest,
        "harbor_state": harbor_state,
        "settlement_rail": settlement_rail,
        "settlement_mode": settlement_mode,
        "principal_did": principal_did,
        "payee_did": payee_did,
        "currency": currency,
        "amount_cents": amount_cents,
        "terminal_observed_at": terminal_observed_at,
        "signing_algorithm": signing_algorithm,
        "message_digest_sha256_hex": _read_string(raw.get("message_digest_sha256_hex")).strip().lower(),
        "signing_public_key_ed25519_hex": _read_string(raw.get("signing_public_key_ed25519_hex")).strip().lower(),
        "ed25519_signature_hex": _read_string(raw.get("ed25519_signature_hex")).strip().lower(),
    }
    if predicate_passed is not None:
        normalized["predicate_passed"] = predicate_passed
    return normalized


def _marshal_canonical_authorization_receipt(receipt: ProtocolAuthorizationReceiptV1) -> bytes:
    payload = {
        "schema_version": receipt["schema_version"],
        "kind": receipt["kind"],
        "receipt_version": receipt["receipt_version"],
        "receipt_id": receipt["receipt_id"],
        "issued_at": receipt["issued_at"],
        "status": receipt["status"],
        "intent_id": receipt["intent_id"],
        "tenant_id": receipt["tenant_id"],
        "verifier_id": receipt["verifier_id"],
        "transport_binding": _canonical_transport_binding(receipt["transport_binding"]),
        "mandate_digest_sha256_hex": receipt["mandate_digest_sha256_hex"],
        "imported_mandate_signing_public_key_ed25519_hex": receipt[
            "imported_mandate_signing_public_key_ed25519_hex"
        ],
        "authorization": {
            "kind": receipt["authorization"]["kind"],
            "tenant_id": receipt["authorization"]["tenant_id"],
            "principal_subject": receipt["authorization"].get("principal_subject", ""),
            "principal_type": receipt["authorization"].get("principal_type", ""),
        },
        "agent": {
            "subject": receipt["agent"]["subject"],
            "issuer": receipt["agent"].get("issuer", ""),
            "key_id": receipt["agent"].get("key_id", ""),
            "display_name": receipt["agent"].get("display_name", ""),
        },
        "allowed_actions": list(receipt["allowed_actions"]),
        "allowed_tools": list(receipt["allowed_tools"]),
        "spend_ceiling": {
            "amount_minor": receipt["spend_ceiling"]["amount_minor"],
            "currency": receipt["spend_ceiling"]["currency"],
        },
        "settlement": {
            "default_rail": receipt["settlement"]["default_rail"],
            "allowed_rails": list(receipt["settlement"]["allowed_rails"]),
        },
        "constraint": {
            "kind": receipt["constraint"]["kind"],
            "id": receipt["constraint"].get("id", ""),
            "version": receipt["constraint"].get("version", ""),
            "digest_sha256_hex": receipt["constraint"].get("digest_sha256_hex", ""),
            "uri": receipt["constraint"].get("uri", ""),
        },
        "expires_at": receipt["expires_at"],
        "nonce": receipt["nonce"],
        "human_presence_mode": receipt["human_presence_mode"],
    }
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return go_json_escape(text).encode("utf-8")


def _marshal_canonical_settlement_receipt(receipt: ProtocolSettlementReceiptV1) -> bytes:
    payload: dict[str, Any] = {
        "schema_version": receipt["schema_version"],
        "kind": receipt["kind"],
        "receipt_version": receipt["receipt_version"],
        "receipt_id": receipt["receipt_id"],
        "issued_at": receipt["issued_at"],
        "intent_id": receipt["intent_id"],
        "tenant_id": receipt["tenant_id"],
        "verifier_id": receipt["verifier_id"],
        "transport_binding": _canonical_transport_binding(receipt["transport_binding"]),
        "authorization_receipt_id": receipt["authorization_receipt_id"],
        "mandate_digest_sha256_hex": receipt["mandate_digest_sha256_hex"],
        "harbor_state": receipt["harbor_state"],
    }
    if "predicate_passed" in receipt:
        payload["predicate_passed"] = receipt["predicate_passed"]
    payload.update(
        {
            "settlement_rail": receipt["settlement_rail"],
            "settlement_mode": receipt["settlement_mode"],
            "principal_did": receipt["principal_did"],
            "payee_did": receipt["payee_did"],
            "currency": receipt["currency"],
            "amount_cents": receipt["amount_cents"],
            "terminal_observed_at": receipt["terminal_observed_at"],
        }
    )
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return go_json_escape(text).encode("utf-8")


def _authorization_message_digest(receipt: ProtocolAuthorizationReceiptV1) -> bytes:
    return hashlib.sha256(_marshal_canonical_authorization_receipt(receipt)).digest()


def _settlement_message_digest(receipt: ProtocolSettlementReceiptV1) -> bytes:
    return hashlib.sha256(_marshal_canonical_settlement_receipt(receipt)).digest()


def _verify_signed_digest(
    kind: str,
    signing_algorithm: str,
    message_digest_hex: str,
    public_key_hex: str,
    signature_hex: str,
    expected_digest: bytes,
) -> None:
    if signing_algorithm != PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256:
        raise ValueError(
            f"{kind}: signing_algorithm must be {PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256!r}"
        )
    if not HEX64_RE.fullmatch(message_digest_hex):
        raise ValueError(f"{kind}: message_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest")
    if message_digest_hex != expected_digest.hex():
        raise ValueError(f"{kind}: message digest mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ValueError(f"{kind}: invalid signing_public_key_ed25519_hex") from exc
    if len(public_key.public_bytes_raw()) != 32:
        raise ValueError(f"{kind}: invalid signing_public_key_ed25519_hex")
    if len(signature) != 64:
        raise ValueError(f"{kind}: invalid ed25519_signature_hex")
    try:
        public_key.verify(signature, expected_digest)
    except InvalidSignature as exc:
        raise ValueError(f"{kind}: ed25519 signature verification failed") from exc


def sign_protocol_authorization_receipt_v1(
    signing_seed: bytes,
    receipt: dict[str, Any] | ProtocolAuthorizationReceiptV1,
) -> ProtocolAuthorizationReceiptV1:
    """Validate, canonicalize, and sign an authorization receipt."""
    if len(signing_seed) != 32:
        raise ValueError("protocol authorization receipt: signing key must be an ed25519 private key")
    normalized = normalize_protocol_authorization_receipt_v1(receipt)
    digest = _authorization_message_digest(normalized)
    private_key = Ed25519PrivateKey.from_private_bytes(signing_seed)
    signature = private_key.sign(digest)
    public_key = private_key.public_key().public_bytes_raw()
    signed = dict(normalized)
    signed.update(
        {
            "signing_algorithm": PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256,
            "message_digest_sha256_hex": digest.hex(),
            "signing_public_key_ed25519_hex": public_key.hex(),
            "ed25519_signature_hex": signature.hex(),
        }
    )
    return signed  # type: ignore[return-value]


def sign_protocol_settlement_receipt_v1(
    signing_seed: bytes,
    receipt: dict[str, Any] | ProtocolSettlementReceiptV1,
) -> ProtocolSettlementReceiptV1:
    """Validate, canonicalize, and sign a settlement receipt."""
    if len(signing_seed) != 32:
        raise ValueError("protocol settlement receipt: signing key must be an ed25519 private key")
    normalized = normalize_protocol_settlement_receipt_v1(receipt)
    digest = _settlement_message_digest(normalized)
    private_key = Ed25519PrivateKey.from_private_bytes(signing_seed)
    signature = private_key.sign(digest)
    public_key = private_key.public_key().public_bytes_raw()
    signed = dict(normalized)
    signed.update(
        {
            "signing_algorithm": PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256,
            "message_digest_sha256_hex": digest.hex(),
            "signing_public_key_ed25519_hex": public_key.hex(),
            "ed25519_signature_hex": signature.hex(),
        }
    )
    return signed  # type: ignore[return-value]


def verify_protocol_authorization_receipt_v1(
    receipt: dict[str, Any] | ProtocolAuthorizationReceiptV1,
) -> ProtocolAuthorizationReceiptV1:
    """Check structure, canonical digest recompute, and detached Ed25519 signature."""
    normalized = normalize_protocol_authorization_receipt_v1(receipt)
    digest = _authorization_message_digest(normalized)
    _verify_signed_digest(
        "protocol authorization receipt",
        normalized["signing_algorithm"],
        normalized["message_digest_sha256_hex"],
        normalized["signing_public_key_ed25519_hex"],
        normalized["ed25519_signature_hex"],
        digest,
    )
    return normalized


def verify_protocol_settlement_receipt_v1(
    receipt: dict[str, Any] | ProtocolSettlementReceiptV1,
) -> ProtocolSettlementReceiptV1:
    """Check structure, canonical digest recompute, and detached Ed25519 signature."""
    normalized = normalize_protocol_settlement_receipt_v1(receipt)
    digest = _settlement_message_digest(normalized)
    _verify_signed_digest(
        "protocol settlement receipt",
        normalized["signing_algorithm"],
        normalized["message_digest_sha256_hex"],
        normalized["signing_public_key_ed25519_hex"],
        normalized["ed25519_signature_hex"],
        digest,
    )
    return normalized
