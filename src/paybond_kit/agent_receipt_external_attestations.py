"""Map partner attestation artifacts into Agent Receipt external_attestations entries."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, TypedDict, cast

from paybond_kit.agent_receipt import AgentReceiptExternalAttestationV1
from paybond_kit.json_digest import normalize_json
from paybond_kit.mcp_sep2828_evidence import strip_digest_prefix
from paybond_kit.sep2828_signature import verify_sep2828_receipt_pair
from paybond_kit.x402_receipt_evidence import build_x402_receipt_digest_payload
from paybond_kit.x402_receipt_signature import extract_signed_x402_receipt, verify_signed_x402_receipt

AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828 = "sep2828_mcp"
AGENT_RECEIPT_EXTERNAL_SOURCE_X402 = "x402"

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
    return [
        {
            "source": AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828,
            "kind": "decision_record",
            "digest_sha256_hex": decision_digest,
            **({"reference_id": reference_id} if reference_id else {}),
        },
        {
            "source": AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828,
            "kind": "outcome_record",
            "digest_sha256_hex": outcome_digest,
            **({"reference_id": reference_id} if reference_id else {}),
        },
    ]


def x402_receipt_to_external_attestations(
    receipt_input: dict[str, Any],
) -> list[AgentReceiptExternalAttestationV1]:
    signed = extract_signed_x402_receipt(receipt_input)
    verified_payload = verify_signed_x402_receipt(signed)
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


PaybondExternalAttestationInput = (
    Sep2828ExternalAttestationInput | X402ExternalAttestationInput | AgentReceiptExternalAttestationV1
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
            out.extend(x402_receipt_to_external_attestations(x402["receipt"]))
    return out
