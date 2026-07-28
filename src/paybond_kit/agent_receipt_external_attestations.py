"""Map partner attestation artifacts into Agent Receipt external_attestations entries."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, NotRequired, TypedDict, cast

from paybond_kit.agent_mandate import verify_signed_agent_mandate_v1
from paybond_kit.agent_receipt import AgentReceiptExternalAttestationV1
from paybond_kit.json_digest import normalize_json
from paybond_kit.mcp_sep2828_evidence import strip_digest_prefix
from paybond_kit.protocol_receipt import (
    verify_protocol_authorization_receipt_v1,
    verify_protocol_settlement_receipt_v1,
)
from paybond_kit.sep2828_signature import verify_sep2828_receipt_pair
from paybond_kit.x402_receipt_evidence import build_x402_receipt_digest_payload
from paybond_kit.x402_receipt_signature import extract_signed_x402_receipt, verify_signed_x402_receipt

AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828 = "sep2828_mcp"
AGENT_RECEIPT_EXTERNAL_SOURCE_X402 = "x402"
AGENT_RECEIPT_EXTERNAL_SOURCE_AP2 = "ap2"

_SEP2828_SIGNATURE_KEYS = frozenset(
    {
        "signature",
        "ed25519_signature_hex",
        "message_digest_sha256_hex",
        "signing_public_key_ed25519_hex",
    }
)
_SEP2828_ASSERTED_BLOCKS = ("issuerAsserted", "receiptAsserted")


def partner_record_digest_sha256_hex(record: dict[str, Any]) -> str:
    normalized = normalize_json(record)
    payload = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _strip_sep2828_signature_fields(record: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in record.items():
        if key in _SEP2828_SIGNATURE_KEYS:
            continue
        if key in _SEP2828_ASSERTED_BLOCKS and isinstance(value, dict):
            stripped = {
                inner_key: inner_value
                for inner_key, inner_value in value.items()
                if inner_key not in _SEP2828_SIGNATURE_KEYS
            }
            if stripped:
                out[key] = stripped
            continue
        out[key] = value
    return out


def sep2828_records_to_external_attestations(
    decision: dict[str, Any],
    outcome: dict[str, Any],
) -> list[AgentReceiptExternalAttestationV1]:
    verify_sep2828_receipt_pair(decision, outcome)
    back_link = decision.get("backLink")
    reference_id: str | None = None
    if isinstance(back_link, dict):
        digest = back_link.get("attestationDigest")
        if isinstance(digest, str) and digest:
            reference_id = strip_digest_prefix(digest)
    decision_digest = partner_record_digest_sha256_hex(_strip_sep2828_signature_fields(decision))
    outcome_digest = partner_record_digest_sha256_hex(_strip_sep2828_signature_fields(outcome))
    decision_attestation: AgentReceiptExternalAttestationV1 = {
        "source": AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828,
        "kind": "decision_record",
        "digest_sha256_hex": decision_digest,
    }
    outcome_attestation: AgentReceiptExternalAttestationV1 = {
        "source": AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828,
        "kind": "outcome_record",
        "digest_sha256_hex": outcome_digest,
    }
    if reference_id:
        decision_attestation["reference_id"] = reference_id
        outcome_attestation["reference_id"] = reference_id
    return [decision_attestation, outcome_attestation]


def signed_mandate_to_external_attestations(
    signed: dict[str, Any],
    transport_binding: dict[str, Any] | None = None,
) -> list[AgentReceiptExternalAttestationV1]:
    verify_signed_agent_mandate_v1(signed)
    digest = str(signed.get("message_digest_sha256_hex", "")).strip().lower()
    external_authorization_id = ""
    if transport_binding is not None:
        external_authorization_id = str(transport_binding.get("external_authorization_id", "")).strip()
    nonce = str(signed.get("nonce", "")).strip()
    reference_id = external_authorization_id or nonce or None
    attestation: AgentReceiptExternalAttestationV1 = {
        "source": AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
        "kind": "agent_mandate_v1",
        "digest_sha256_hex": digest,
    }
    if reference_id:
        attestation["reference_id"] = reference_id
    return [attestation]


def protocol_authorization_receipt_to_external_attestations(
    receipt: dict[str, Any],
) -> list[AgentReceiptExternalAttestationV1]:
    verified = verify_protocol_authorization_receipt_v1(receipt)
    return [
        {
            "source": AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
            "kind": "protocol_authorization_receipt_v1",
            "digest_sha256_hex": verified["message_digest_sha256_hex"],
            "reference_id": verified["intent_id"],
        }
    ]


def protocol_settlement_receipt_to_external_attestations(
    receipt: dict[str, Any],
) -> list[AgentReceiptExternalAttestationV1]:
    verified = verify_protocol_settlement_receipt_v1(receipt)
    return [
        {
            "source": AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
            "kind": "protocol_settlement_receipt_v1",
            "digest_sha256_hex": verified["message_digest_sha256_hex"],
            "reference_id": verified["intent_id"],
        }
    ]


def x402_receipt_to_external_attestations(
    receipt_input: dict[str, Any],
    *,
    expected_signer: str,
) -> list[AgentReceiptExternalAttestationV1]:
    """
    Convert a verified x402 signed delivery receipt into one external attestation entry.

    SECURITY: ``expected_signer`` is **required** and pins the receipt to a known
    issuer key. An x402 receipt embeds its own verification key, so a valid
    signature only proves self-consistency; without a pin an attacker could forge
    a self-consistent "delivery receipt" attestation. Fails closed when
    ``expected_signer`` is missing or empty (see :func:`verify_signed_x402_receipt`).

    :param receipt_input: Wire envelope or receipt containing the signed x402 artifact.
    :param expected_signer: Non-empty issuer pin (EIP-712 address, or JWS RFC 7638
        thumbprint / OKP raw ``x``).
    :returns: One external attestation entry for the verified receipt.
    :raises ValueError: If ``expected_signer`` is missing/empty or verification fails.
    """
    signed = extract_signed_x402_receipt(receipt_input)
    verified_payload = verify_signed_x402_receipt(signed, expected_signer=expected_signer)
    payload = build_x402_receipt_digest_payload(verified_payload)
    digest = partner_record_digest_sha256_hex(cast(dict[str, Any], payload))
    return [
        {
            "source": AGENT_RECEIPT_EXTERNAL_SOURCE_X402,
            "kind": "delivery_receipt_v1",
            "digest_sha256_hex": digest,
            "reference_id": str(payload["resourceUrl"]),
        }
    ]


class Sep2828ExternalAttestationInput(TypedDict):
    kind: Literal["sep2828"]
    decision: dict[str, Any]
    outcome: dict[str, Any]


class X402ExternalAttestationInput(TypedDict):
    kind: Literal["x402"]
    receipt: dict[str, Any]
    expected_signer: str


class Ap2MandateExternalAttestationInput(TypedDict):
    kind: Literal["ap2_mandate"]
    signed_mandate: dict[str, Any]
    transport_binding: NotRequired[dict[str, Any]]


class Ap2AuthorizationReceiptExternalAttestationInput(TypedDict):
    kind: Literal["ap2_authorization_receipt"]
    receipt: dict[str, Any]


class Ap2SettlementReceiptExternalAttestationInput(TypedDict):
    kind: Literal["ap2_settlement_receipt"]
    receipt: dict[str, Any]


PaybondExternalAttestationInput = (
    Sep2828ExternalAttestationInput
    | X402ExternalAttestationInput
    | Ap2MandateExternalAttestationInput
    | Ap2AuthorizationReceiptExternalAttestationInput
    | Ap2SettlementReceiptExternalAttestationInput
    | AgentReceiptExternalAttestationV1
)


def resolve_external_attestations(
    inputs: list[PaybondExternalAttestationInput],
) -> list[AgentReceiptExternalAttestationV1]:
    out: list[AgentReceiptExternalAttestationV1] = []
    for item in inputs:
        if "source" in item and "digest_sha256_hex" in item:
            out.append(cast(AgentReceiptExternalAttestationV1, item))
            continue
        kind = item.get("kind")
        if kind == "sep2828":
            sep = cast(Sep2828ExternalAttestationInput, item)
            out.extend(sep2828_records_to_external_attestations(sep["decision"], sep["outcome"]))
            continue
        if kind == "x402":
            x402 = cast(X402ExternalAttestationInput, item)
            out.extend(
                x402_receipt_to_external_attestations(
                    x402["receipt"], expected_signer=x402["expected_signer"]
                )
            )
            continue
        if kind == "ap2_mandate":
            ap2_mandate = cast(Ap2MandateExternalAttestationInput, item)
            out.extend(
                signed_mandate_to_external_attestations(
                    ap2_mandate["signed_mandate"],
                    ap2_mandate.get("transport_binding"),
                )
            )
            continue
        if kind == "ap2_authorization_receipt":
            ap2_auth = cast(Ap2AuthorizationReceiptExternalAttestationInput, item)
            out.extend(protocol_authorization_receipt_to_external_attestations(ap2_auth["receipt"]))
            continue
        if kind == "ap2_settlement_receipt":
            ap2_settle = cast(Ap2SettlementReceiptExternalAttestationInput, item)
            out.extend(protocol_settlement_receipt_to_external_attestations(ap2_settle["receipt"]))
    return out
