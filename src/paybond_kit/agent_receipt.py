"""Paybond Agent Receipt v1 — verify-only reference implementation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence, TypedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

AGENT_RECEIPT_SCHEMA_VERSION = 1
AGENT_RECEIPT_KIND_V1 = "paybond.agent_receipt_v1"
AGENT_RECEIPT_VERSION_V1 = "1"
AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519 = "ed25519-sha256-json-v1"
AGENT_RECEIPT_SCOPE_ACTION = "action"
AGENT_RECEIPT_SCOPE_INTENT_TERMINAL = "intent_terminal"
AGENT_RECEIPT_WELL_KNOWN_PATH = "/.well-known/agent-receipt-v1.json"
AGENT_RECEIPT_SIGNING_KEYS_WELL_KNOWN_PATH = "/.well-known/agent-receipt-signing-keys.json"

FORBIDDEN_AGENT_RECEIPT_FIELDS: tuple[str, ...] = (
    "user_prompt",
    "system_prompt",
    "tool_arguments",
    "tool_results",
    "evidence_payload",
    "payee_signature",
)

_AGENT_RECEIPT_DIR = Path(__file__).resolve().parents[3] / "agent-receipt"
_AGENT_RECEIPT_SCHEMA: dict[str, Any] | None = None

_SCOPE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_CURRENCY_RE = re.compile(r"^[a-z]{3}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class AgentReceiptExternalAttestationV1(TypedDict, total=False):
    """Partner or protocol attestation digest attached to an agent receipt."""

    source: str
    kind: str
    digest_sha256_hex: str
    reference_id: str


@dataclass(frozen=True, slots=True)
class ConfigHashInput:
    system_prompt: str
    tools_manifest: Any
    policy_snapshot_id: str


def _agent_receipt_schema() -> dict[str, Any]:
    global _AGENT_RECEIPT_SCHEMA
    if _AGENT_RECEIPT_SCHEMA is None:
        import jsonschema

        raw = (_AGENT_RECEIPT_DIR / "schema.json").read_text(encoding="utf-8")
        _AGENT_RECEIPT_SCHEMA = json.loads(raw)
    return _AGENT_RECEIPT_SCHEMA


def _reject_forbidden_agent_receipt_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_AGENT_RECEIPT_FIELDS:
                raise ValueError(f"agent receipt: forbidden field {key!r}")
            _reject_forbidden_agent_receipt_fields(child)
        return
    if isinstance(value, list):
        for item in value:
            _reject_forbidden_agent_receipt_fields(item)


def validate_agent_receipt_json(raw: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    """Reject forbidden privacy fields and validate against the published Draft 2020-12 schema."""
    import jsonschema

    if isinstance(raw, Mapping):
        doc: Any = dict(raw)
    else:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"agent receipt: invalid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("agent receipt: root value must be a JSON object")
    _reject_forbidden_agent_receipt_fields(doc)
    jsonschema.validate(instance=doc, schema=_agent_receipt_schema())
    return doc


def verify_agent_receipt_v1_from_json(
    raw: bytes | str | Mapping[str, Any],
    *,
    expected_signing_public_keys: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Validate raw JSON (schema + forbidden fields) then verify signature."""
    doc = validate_agent_receipt_json(raw)
    return verify_agent_receipt_v1(doc, expected_signing_public_keys=expected_signing_public_keys)


def _format_rfc3339_seconds(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return parsed.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonicalize_json(value: Any) -> Any:
    if isinstance(value, list):
        return [_canonicalize_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonicalize_json(value[key]) for key in sorted(value)}
    return value


def _jcs_bytes(value: Any) -> bytes:
    return json.dumps(_canonicalize_json(value), separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def config_hash_sha256_hex(input_value: ConfigHashInput) -> str:
    """Return sha256(JCS({ system_prompt, tools_manifest, policy_snapshot_id }))."""
    payload = {
        "system_prompt": input_value.system_prompt,
        "tools_manifest": input_value.tools_manifest,
        "policy_snapshot_id": input_value.policy_snapshot_id,
    }
    return hashlib.sha256(_jcs_bytes(payload)).hexdigest()


def prompt_hash_sha256_hex(normalized_user_prompt: str) -> str:
    """Return sha256(normalized_user_prompt)."""
    return hashlib.sha256(normalized_user_prompt.encode("utf-8")).hexdigest()


def value_digest_sha256_hex(value: Any) -> str:
    """Return sha256(JCS(value))."""
    return hashlib.sha256(_jcs_bytes(value)).hexdigest()


def action_receipt_id(intent_id: str, tool_call_id: str) -> str:
    """Return sha256(intent_id + '\\x00' + tool_call_id) as lowercase hex."""
    payload = f"{intent_id}\x00{tool_call_id}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalize_scope_token(value: str, field: str) -> str:
    normalized = value.strip().lower()
    if not normalized:
        raise ValueError(f"agent receipt: {field} is required")
    if not _SCOPE_TOKEN_RE.fullmatch(normalized):
        raise ValueError(f"agent receipt: {field} {normalized!r} is not canonical")
    return normalized


def _require_hex64(value: str, field: str) -> None:
    if not _HEX64_RE.fullmatch(value):
        raise ValueError(f"agent receipt: {field} must be a lowercase 64-byte hex SHA-256 digest")


def _parse_uuid(value: str, field: str) -> str:
    normalized = value.strip().lower()
    if not _UUID_RE.fullmatch(normalized):
        raise ValueError(f"agent receipt: {field} must be a canonical UUID")
    return normalized


def _normalize_scope_set(values: Sequence[str] | None, field: str) -> list[str]:
    if not values:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        normalized = _normalize_scope_token(value, field)
        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def _normalize_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    schema_version = receipt.get("schema_version", AGENT_RECEIPT_SCHEMA_VERSION)
    if schema_version in (0, AGENT_RECEIPT_SCHEMA_VERSION):
        schema_version = AGENT_RECEIPT_SCHEMA_VERSION
    else:
        raise ValueError(f"agent receipt: unsupported schema_version {schema_version}")

    kind = str(receipt.get("kind", AGENT_RECEIPT_KIND_V1)).strip() or AGENT_RECEIPT_KIND_V1
    if kind != AGENT_RECEIPT_KIND_V1:
        raise ValueError(f"agent receipt: unsupported kind {kind!r}")

    receipt_version = str(receipt.get("receipt_version", AGENT_RECEIPT_VERSION_V1)).strip() or AGENT_RECEIPT_VERSION_V1
    if receipt_version != AGENT_RECEIPT_VERSION_V1:
        raise ValueError(f"agent receipt: unsupported receipt_version {receipt_version!r}")

    scope = str(receipt["scope"]).strip().lower()
    if scope not in (AGENT_RECEIPT_SCOPE_ACTION, AGENT_RECEIPT_SCOPE_INTENT_TERMINAL):
        raise ValueError(
            f"agent receipt: scope must be {AGENT_RECEIPT_SCOPE_ACTION!r} or "
            f"{AGENT_RECEIPT_SCOPE_INTENT_TERMINAL!r}"
        )

    receipt_id = str(receipt["receipt_id"]).strip().lower()
    if not receipt_id:
        raise ValueError("agent receipt: receipt_id is required")

    tenant_id = str(receipt["tenant_id"]).strip()
    if not tenant_id:
        raise ValueError("agent receipt: tenant_id is required")

    authorization = _normalize_authorization(receipt["authorization"])
    outcome = _normalize_outcome(receipt["outcome"])
    references = _normalize_references(receipt["references"])
    external_attestations = _normalize_external_attestations(
        receipt.get("external_attestations") or []
    )

    execution: dict[str, Any] | None = None
    if scope == AGENT_RECEIPT_SCOPE_ACTION:
        if "execution" not in receipt or receipt["execution"] is None:
            raise ValueError("agent receipt: execution is required for action scope")
        execution = _normalize_execution(receipt["execution"])

    normalized: dict[str, Any] = {
        "schema_version": schema_version,
        "kind": AGENT_RECEIPT_KIND_V1,
        "receipt_version": AGENT_RECEIPT_VERSION_V1,
        "scope": scope,
        "receipt_id": receipt_id,
        "issued_at": _format_rfc3339_seconds(str(receipt["issued_at"])),
        "tenant_id": tenant_id,
        "authorization": authorization,
        "outcome": outcome,
        "references": references,
        "external_attestations": external_attestations,
        "signing_algorithm": str(receipt.get("signing_algorithm", AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519))
        .strip()
        .lower()
        or AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
        "message_digest_sha256_hex": str(receipt["message_digest_sha256_hex"]).strip().lower(),
        "signing_public_key_ed25519_hex": str(receipt["signing_public_key_ed25519_hex"]).strip().lower(),
        "ed25519_signature_hex": str(receipt["ed25519_signature_hex"]).strip().lower(),
    }
    if execution is not None:
        normalized["execution"] = execution
    if receipt.get("merchant") is not None:
        normalized["merchant"] = _normalize_merchant(receipt["merchant"])
    if receipt.get("evidence") is not None:
        normalized["evidence"] = _normalize_evidence(receipt["evidence"])
    if receipt.get("payment") is not None:
        normalized["payment"] = _normalize_payment(receipt["payment"])
    if receipt.get("operator_attestation") is not None:
        normalized["operator_attestation"] = _normalize_operator_attestation(
            receipt["operator_attestation"]
        )

    _verify_receipt_id(normalized)
    return normalized


def _normalize_operator_attestation(value: Mapping[str, Any]) -> dict[str, Any]:
    operator_did = str(value["operator_did"]).strip()
    if not operator_did:
        raise ValueError("agent receipt: operator_attestation.operator_did is required")
    message_digest = str(value["message_digest_sha256_hex"]).strip().lower()
    public_key = str(value["signing_public_key_ed25519_hex"]).strip().lower()
    signature = str(value["ed25519_signature_hex"]).strip().lower()
    _require_hex64(message_digest, "operator_attestation.message_digest_sha256_hex")
    _require_hex64(public_key, "operator_attestation.signing_public_key_ed25519_hex")
    if len(signature) != 128:
        raise ValueError("agent receipt: operator_attestation.ed25519_signature_hex must be 128 hex chars")
    return {
        "operator_did": operator_did,
        "signing_public_key_ed25519_hex": public_key,
        "message_digest_sha256_hex": message_digest,
        "ed25519_signature_hex": signature,
    }


def _normalize_authorization(value: Mapping[str, Any]) -> dict[str, Any]:
    principal_did = str(value["principal_did"]).strip()
    actor_subject = str(value["actor_subject"]).strip()
    if not principal_did:
        raise ValueError("agent receipt: principal_did is required")
    if not actor_subject:
        raise ValueError("agent receipt: actor_subject is required")
    currency = str(value["currency"]).strip().lower()
    if not _CURRENCY_RE.fullmatch(currency):
        raise ValueError(f"agent receipt: currency {currency!r} is not canonical")
    requested_spend_cents = int(value["requested_spend_cents"])
    if requested_spend_cents < 0:
        raise ValueError("agent receipt: requested_spend_cents must be non-negative")
    out: dict[str, Any] = {
        "principal_did": principal_did,
        "actor_subject": actor_subject,
        "agent": _normalize_agent(value["agent"]),
        "decision_id": _parse_uuid(str(value["decision_id"]), "decision_id"),
        "policy": _normalize_policy(value["policy"]),
        "authorized_at": _format_rfc3339_seconds(str(value["authorized_at"])),
        "requested_spend_cents": requested_spend_cents,
        "currency": currency,
        "reason_codes": _normalize_scope_set(value.get("reason_codes"), "reason_codes"),
    }
    if value.get("audit_id"):
        out["audit_id"] = _parse_uuid(str(value["audit_id"]), "audit_id")
    return out


def _normalize_agent(value: Mapping[str, Any]) -> dict[str, Any]:
    operator_did = str(value["operator_did"]).strip()
    if not operator_did:
        raise ValueError("agent receipt: agent.operator_did is required")
    config_hash = str(value["config_hash_sha256_hex"]).strip().lower()
    prompt_hash = str(value["prompt_hash_sha256_hex"]).strip().lower()
    _require_hex64(config_hash, "agent.config_hash_sha256_hex")
    _require_hex64(prompt_hash, "agent.prompt_hash_sha256_hex")
    out: dict[str, Any] = {
        "operator_did": operator_did,
        "model_family": _normalize_scope_token(str(value["model_family"]), "agent.model_family"),
        "config_hash_sha256_hex": config_hash,
        "prompt_hash_sha256_hex": prompt_hash,
    }
    if value.get("model_instance_id"):
        out["model_instance_id"] = str(value["model_instance_id"]).strip()
    if value.get("deployment_epoch") is not None:
        out["deployment_epoch"] = int(value["deployment_epoch"])
    return out


def _normalize_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    template_id = str(value["template_id"]).strip()
    digest = str(value["content_digest_sha256_hex"]).strip().lower()
    if not template_id:
        raise ValueError("agent receipt: policy.template_id is required")
    _require_hex64(digest, "policy.content_digest_sha256_hex")
    out: dict[str, Any] = {
        "template_id": template_id,
        "content_digest_sha256_hex": digest,
    }
    if value.get("version_seq") is not None:
        out["version_seq"] = int(value["version_seq"])
    if value.get("spend_policy_version") is not None:
        out["spend_policy_version"] = int(value["spend_policy_version"])
    return out


def _normalize_execution(value: Mapping[str, Any]) -> dict[str, Any]:
    tool_call_id = str(value["tool_call_id"]).strip()
    if not tool_call_id:
        raise ValueError("agent receipt: tool_call_id is required")
    arguments_digest = str(value["arguments_digest_sha256_hex"]).strip().lower()
    _require_hex64(arguments_digest, "arguments_digest_sha256_hex")
    outcome = str(value["outcome"]).strip().lower()
    if outcome not in {"executed", "denied", "skipped", "failed"}:
        raise ValueError("agent receipt: outcome must be executed, denied, skipped, or failed")
    out: dict[str, Any] = {
        "run_id": _parse_uuid(str(value["run_id"]), "run_id"),
        "tool_call_id": tool_call_id,
        "tool_name": _normalize_scope_token(str(value["tool_name"]), "tool_name"),
        "operation": _normalize_scope_token(str(value["operation"]), "operation"),
        "arguments_digest_sha256_hex": arguments_digest,
        "outcome": outcome,
        "started_at": _format_rfc3339_seconds(str(value["started_at"])),
        "completed_at": _format_rfc3339_seconds(str(value["completed_at"])),
    }
    if value.get("result_digest_sha256_hex"):
        result_digest = str(value["result_digest_sha256_hex"]).strip().lower()
        _require_hex64(result_digest, "result_digest_sha256_hex")
        out["result_digest_sha256_hex"] = result_digest
    if value.get("duration_ms") is not None:
        duration_ms = int(value["duration_ms"])
        if duration_ms < 0:
            raise ValueError("agent receipt: duration_ms must be non-negative")
        out["duration_ms"] = duration_ms
    return out


def _normalize_merchant(value: Mapping[str, Any]) -> dict[str, Any]:
    payee_did = str(value["payee_did"]).strip()
    if not payee_did:
        raise ValueError("agent receipt: payee_did is required")
    out: dict[str, Any] = {"payee_did": payee_did}
    if value.get("vendor_id"):
        out["vendor_id"] = _normalize_scope_token(str(value["vendor_id"]), "vendor_id")
    if value.get("vendor_ref_id"):
        out["vendor_ref_id"] = str(value["vendor_ref_id"]).strip()
    return out


def _normalize_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    payload_digest = str(value["payload_digest_sha256_hex"]).strip().lower()
    _require_hex64(payload_digest, "payload_digest_sha256_hex")
    payee_did = str(value["payee_did"]).strip()
    if not payee_did:
        raise ValueError("agent receipt: payee_did is required")
    out: dict[str, Any] = {
        "completion_preset_id": _normalize_scope_token(
            str(value["completion_preset_id"]), "completion_preset_id"
        ),
        "payload_digest_sha256_hex": payload_digest,
        "predicate_passed": bool(value["predicate_passed"]),
        "payee_did": payee_did,
    }
    if value.get("artifacts_digest_sha256_hex"):
        artifacts_digest = str(value["artifacts_digest_sha256_hex"]).strip().lower()
        _require_hex64(artifacts_digest, "artifacts_digest_sha256_hex")
        out["artifacts_digest_sha256_hex"] = artifacts_digest
    if value.get("payee_signature_digest_sha256_hex"):
        payee_sig = str(value["payee_signature_digest_sha256_hex"]).strip().lower()
        _require_hex64(payee_sig, "payee_signature_digest_sha256_hex")
        out["payee_signature_digest_sha256_hex"] = payee_sig
    return out


def _normalize_payment(value: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "intent_id": _parse_uuid(str(value["intent_id"]), "intent_id"),
        "settlement_rail": _normalize_scope_token(str(value["settlement_rail"]), "settlement_rail"),
    }
    if value.get("funding_method"):
        out["funding_method"] = _normalize_scope_token(str(value["funding_method"]), "funding_method")
    if value.get("funding_reference"):
        out["funding_reference"] = str(value["funding_reference"]).strip()
    if value.get("funding_receipt_digest_sha256_hex"):
        funding_digest = str(value["funding_receipt_digest_sha256_hex"]).strip().lower()
        _require_hex64(funding_digest, "funding_receipt_digest_sha256_hex")
        out["funding_receipt_digest_sha256_hex"] = funding_digest
    return out


def _normalize_outcome(value: Mapping[str, Any]) -> dict[str, Any]:
    harbor_state = _normalize_scope_token(str(value["harbor_state"]), "harbor_state")
    out: dict[str, Any] = {"harbor_state": harbor_state}
    if value.get("spend_reservation_outcome"):
        spend_outcome = str(value["spend_reservation_outcome"]).strip().lower()
        if spend_outcome not in {"consumed", "released", "pending", "none"}:
            raise ValueError(
                "agent receipt: spend_reservation_outcome must be consumed, released, pending, or none"
            )
        out["spend_reservation_outcome"] = spend_outcome
    if "predicate_passed" in value and value["predicate_passed"] is not None:
        out["predicate_passed"] = bool(value["predicate_passed"])
    return out


def _normalize_references(value: Mapping[str, Any]) -> dict[str, Any]:
    ledger_seq = int(value.get("ledger_seq") or 0)
    if ledger_seq < 0:
        raise ValueError("agent receipt: ledger_seq must be non-negative")
    out: dict[str, Any] = {
        "intent_id": _parse_uuid(str(value["intent_id"]), "intent_id"),
        "settlement_receipt_id": value.get("settlement_receipt_id"),
    }
    if ledger_seq:
        out["ledger_seq"] = ledger_seq
    settlement_receipt_id = out.get("settlement_receipt_id")
    if settlement_receipt_id:
        trimmed = str(settlement_receipt_id).strip().lower()
        if not trimmed:
            out["settlement_receipt_id"] = None
        elif not _UUID_RE.fullmatch(trimmed) and not _HEX64_RE.fullmatch(trimmed):
            raise ValueError(
                "agent receipt: settlement_receipt_id must be a canonical UUID or lowercase 64-byte hex digest"
            )
        else:
            out["settlement_receipt_id"] = trimmed
    return out


def _normalize_external_attestations(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for value in values:
        digest = str(value["digest_sha256_hex"]).strip().lower()
        _require_hex64(digest, "digest_sha256_hex")
        kind = str(value["kind"]).strip()
        if not kind:
            raise ValueError("agent receipt: kind is required")
        item: dict[str, Any] = {
            "source": _normalize_scope_token(str(value["source"]), "source"),
            "kind": kind,
            "digest_sha256_hex": digest,
        }
        if value.get("reference_id"):
            item["reference_id"] = str(value["reference_id"]).strip()
        out.append(item)
    return out


def _verify_receipt_id(receipt: Mapping[str, Any]) -> None:
    scope = str(receipt["scope"])
    references = receipt["references"]
    intent_id = str(references["intent_id"])
    receipt_id = str(receipt["receipt_id"])
    if scope == AGENT_RECEIPT_SCOPE_ACTION:
        execution = receipt.get("execution")
        if not isinstance(execution, Mapping):
            raise ValueError("agent receipt: execution is required to verify action receipt_id")
        expected = action_receipt_id(intent_id, str(execution["tool_call_id"]))
        if receipt_id != expected:
            raise ValueError("agent receipt: receipt_id does not match action scope derivation")
        _require_hex64(receipt_id, "receipt_id")
        return
    if receipt_id != intent_id:
        raise ValueError("agent receipt: receipt_id must equal intent_id for intent_terminal scope")
    _parse_uuid(receipt_id, "receipt_id")


def _marshal_canonical_agent_receipt(receipt: Mapping[str, Any]) -> bytes:
    authorization = receipt["authorization"]
    agent = authorization["agent"]
    policy = authorization["policy"]

    authorization_payload: dict[str, Any] = {
        "principal_did": authorization["principal_did"],
        "actor_subject": authorization["actor_subject"],
        "agent": {
            "operator_did": agent["operator_did"],
            "model_family": agent["model_family"],
            **(
                {"model_instance_id": agent["model_instance_id"]}
                if agent.get("model_instance_id")
                else {}
            ),
            "config_hash_sha256_hex": agent["config_hash_sha256_hex"],
            "prompt_hash_sha256_hex": agent["prompt_hash_sha256_hex"],
            **(
                {"deployment_epoch": agent["deployment_epoch"]}
                if agent.get("deployment_epoch")
                else {}
            ),
        },
        "decision_id": authorization["decision_id"],
        **({"audit_id": authorization["audit_id"]} if authorization.get("audit_id") else {}),
        "policy": {
            "template_id": policy["template_id"],
            **({"version_seq": policy["version_seq"]} if policy.get("version_seq") else {}),
            "content_digest_sha256_hex": policy["content_digest_sha256_hex"],
            **(
                {"spend_policy_version": policy["spend_policy_version"]}
                if policy.get("spend_policy_version")
                else {}
            ),
        },
        "authorized_at": authorization["authorized_at"],
        "requested_spend_cents": authorization["requested_spend_cents"],
        "currency": authorization["currency"],
        **(
            {"reason_codes": authorization["reason_codes"]}
            if authorization.get("reason_codes")
            else {}
        ),
    }

    payload: dict[str, Any] = {
        "schema_version": receipt["schema_version"],
        "kind": receipt["kind"],
        "receipt_version": receipt["receipt_version"],
        "scope": receipt["scope"],
        "receipt_id": receipt["receipt_id"],
        "issued_at": receipt["issued_at"],
        "tenant_id": receipt["tenant_id"],
        "authorization": authorization_payload,
    }

    execution = receipt.get("execution")
    if isinstance(execution, Mapping):
        payload["execution"] = {
            "run_id": execution["run_id"],
            "tool_call_id": execution["tool_call_id"],
            "tool_name": execution["tool_name"],
            "operation": execution["operation"],
            "arguments_digest_sha256_hex": execution["arguments_digest_sha256_hex"],
            **(
                {"result_digest_sha256_hex": execution["result_digest_sha256_hex"]}
                if execution.get("result_digest_sha256_hex")
                else {}
            ),
            "outcome": execution["outcome"],
            "started_at": execution["started_at"],
            "completed_at": execution["completed_at"],
            **({"duration_ms": execution["duration_ms"]} if execution.get("duration_ms") else {}),
        }

    merchant = receipt.get("merchant")
    if isinstance(merchant, Mapping):
        payload["merchant"] = {
            "payee_did": merchant["payee_did"],
            **({"vendor_id": merchant["vendor_id"]} if merchant.get("vendor_id") else {}),
            **({"vendor_ref_id": merchant["vendor_ref_id"]} if merchant.get("vendor_ref_id") else {}),
        }

    evidence = receipt.get("evidence")
    if isinstance(evidence, Mapping):
        payload["evidence"] = {
            "completion_preset_id": evidence["completion_preset_id"],
            "payload_digest_sha256_hex": evidence["payload_digest_sha256_hex"],
            **(
                {"artifacts_digest_sha256_hex": evidence["artifacts_digest_sha256_hex"]}
                if evidence.get("artifacts_digest_sha256_hex")
                else {}
            ),
            "predicate_passed": evidence["predicate_passed"],
            "payee_did": evidence["payee_did"],
            **(
                {"payee_signature_digest_sha256_hex": evidence["payee_signature_digest_sha256_hex"]}
                if evidence.get("payee_signature_digest_sha256_hex")
                else {}
            ),
        }

    payment = receipt.get("payment")
    if isinstance(payment, Mapping):
        payload["payment"] = {
            "intent_id": payment["intent_id"],
            "settlement_rail": payment["settlement_rail"],
            **({"funding_method": payment["funding_method"]} if payment.get("funding_method") else {}),
            **(
                {"funding_reference": payment["funding_reference"]}
                if payment.get("funding_reference")
                else {}
            ),
            **(
                {"funding_receipt_digest_sha256_hex": payment["funding_receipt_digest_sha256_hex"]}
                if payment.get("funding_receipt_digest_sha256_hex")
                else {}
            ),
        }

    outcome = receipt["outcome"]
    payload["outcome"] = {
        "harbor_state": outcome["harbor_state"],
        **(
            {"spend_reservation_outcome": outcome["spend_reservation_outcome"]}
            if outcome.get("spend_reservation_outcome")
            else {}
        ),
        **(
            {"predicate_passed": outcome["predicate_passed"]}
            if outcome.get("predicate_passed") is not None
            else {}
        ),
    }

    references = receipt["references"]
    payload["references"] = {
        "intent_id": references["intent_id"],
        **({"ledger_seq": references["ledger_seq"]} if references.get("ledger_seq") else {}),
        "settlement_receipt_id": references.get("settlement_receipt_id"),
    }

    external_attestations = receipt.get("external_attestations") or []
    payload["external_attestations"] = external_attestations if external_attestations else None

    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_agent_receipt_bytes(receipt: Mapping[str, Any]) -> bytes:
    """Return canonical signing bytes for a normalized receipt body."""
    return _marshal_canonical_agent_receipt(_normalize_receipt(receipt))


def agent_receipt_message_digest_sha256_hex(receipt: Mapping[str, Any]) -> str:
    """Return sha256(canonical receipt bytes) as lowercase hex, ignoring any existing
    ``message_digest_sha256_hex`` on the input. Used to compose unsigned receipt drafts
    (Agent Receipt Standard Phase 1) and to compute the digest signers must sign over.
    """
    return hashlib.sha256(canonical_agent_receipt_bytes(receipt)).hexdigest()


def _allows_signing_public_key_hex(
    signing_public_key_hex: str,
    expected_signing_public_keys: Sequence[str] | None,
) -> bool:
    if not expected_signing_public_keys:
        return True
    normalized = signing_public_key_hex.strip().lower()
    return any(value.strip().lower() == normalized for value in expected_signing_public_keys)


def verify_agent_receipt_v1(
    receipt: Mapping[str, Any],
    *,
    expected_signing_public_keys: Sequence[str] | None = None,
    verify_operator_against_registry: bool = False,
    trusted_operator_public_keys: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Validate structure, receipt_id derivation, digest, and detached Ed25519 signature.

    The ``operator_did`` binding to ``authorization.agent.operator_did`` is always enforced
    when an ``operator_attestation`` is present. When ``verify_operator_against_registry`` is
    ``True``, the operator signing key must additionally appear in ``trusted_operator_public_keys``.
    """
    normalized = _normalize_receipt(receipt)
    if not _allows_signing_public_key_hex(
        str(normalized["signing_public_key_ed25519_hex"]),
        expected_signing_public_keys,
    ):
        raise ValueError(
            "agent receipt: signing_public_key_ed25519_hex is not in the configured trusted key set"
        )
    canonical = _marshal_canonical_agent_receipt(normalized)
    digest = hashlib.sha256(canonical).digest()
    digest_hex = digest.hex()

    signing_algorithm = str(normalized["signing_algorithm"])
    if signing_algorithm != AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519:
        raise ValueError(
            f"agent receipt: signing_algorithm must be {AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519!r}"
        )
    message_digest_hex = str(normalized["message_digest_sha256_hex"])
    _require_hex64(message_digest_hex, "message_digest_sha256_hex")
    if message_digest_hex != digest_hex:
        raise ValueError("agent receipt: message digest mismatch")

    public_key = bytes.fromhex(str(normalized["signing_public_key_ed25519_hex"]))
    signature = bytes.fromhex(str(normalized["ed25519_signature_hex"]))
    if len(public_key) != 32 or len(signature) != 64:
        raise ValueError("agent receipt: invalid signing material")
    verifier = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        verifier.verify(signature, digest)
    except InvalidSignature as exc:
        raise ValueError("agent receipt: ed25519 signature verification failed") from exc
    _verify_operator_attestation(
        normalized,
        digest,
        verify_operator_against_registry=verify_operator_against_registry,
        trusted_operator_public_keys=trusted_operator_public_keys,
    )
    return normalized


def _allows_operator_public_key_hex(
    operator_public_key_hex: str,
    trusted_operator_public_keys: Sequence[str] | None,
) -> bool:
    if not trusted_operator_public_keys:
        return False
    normalized = operator_public_key_hex.strip().lower()
    return any(value.strip().lower() == normalized for value in trusted_operator_public_keys)


def _verify_operator_attestation(
    normalized: Mapping[str, Any],
    digest: bytes,
    *,
    verify_operator_against_registry: bool = False,
    trusted_operator_public_keys: Sequence[str] | None = None,
) -> None:
    attestation = normalized.get("operator_attestation")
    if not attestation:
        return
    agent = normalized["authorization"]["agent"]
    if str(attestation["operator_did"]).strip() != str(agent["operator_did"]).strip():
        raise ValueError(
            "agent receipt: operator_attestation.operator_did must match authorization.agent.operator_did"
        )
    if str(attestation["message_digest_sha256_hex"]) != str(normalized["message_digest_sha256_hex"]):
        raise ValueError(
            "agent receipt: operator_attestation message_digest_sha256_hex must match gateway digest"
        )
    if verify_operator_against_registry and not _allows_operator_public_key_hex(
        str(attestation["signing_public_key_ed25519_hex"]),
        trusted_operator_public_keys,
    ):
        raise ValueError(
            "agent receipt: operator_attestation signing key is not in the configured tenant operator registry"
        )
    public_key = bytes.fromhex(str(attestation["signing_public_key_ed25519_hex"]))
    signature = bytes.fromhex(str(attestation["ed25519_signature_hex"]))
    if len(public_key) != 32 or len(signature) != 64:
        raise ValueError("agent receipt: invalid operator attestation signing material")
    verifier = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        verifier.verify(signature, digest)
    except InvalidSignature as exc:
        raise ValueError(
            "agent receipt: operator attestation ed25519 signature verification failed"
        ) from exc


def attach_operator_attestation_v1(
    receipt: Mapping[str, Any],
    *,
    operator_private_key_seed: bytes,
    operator_did: str,
) -> dict[str, Any]:
    """Attach an optional operator counter-signature over the Gateway message digest."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    verified = verify_agent_receipt_v1(receipt)
    normalized_operator_did = operator_did.strip()
    if not normalized_operator_did:
        raise ValueError("agent receipt: operator_did is required")
    if normalized_operator_did != str(verified["authorization"]["agent"]["operator_did"]).strip():
        raise ValueError(
            "agent receipt: operator_did must match authorization.agent.operator_did"
        )
    digest = bytes.fromhex(str(verified["message_digest_sha256_hex"]))
    private_key = Ed25519PrivateKey.from_private_bytes(operator_private_key_seed[:32])
    signature = private_key.sign(digest)
    public_key = private_key.public_key().public_bytes_raw()
    verified = dict(verified)
    verified["operator_attestation"] = {
        "operator_did": normalized_operator_did,
        "signing_public_key_ed25519_hex": public_key.hex(),
        "message_digest_sha256_hex": verified["message_digest_sha256_hex"],
        "ed25519_signature_hex": signature.hex(),
    }
    return verified
