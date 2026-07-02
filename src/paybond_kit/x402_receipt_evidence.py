"""Map x402 Signed Offer & Receipt extension payloads into artifact_attested evidence."""

from __future__ import annotations

from typing import Any, TypedDict

from paybond_kit.json_digest import json_value_digest
from paybond_kit.x402_receipt_signature import extract_signed_x402_receipt, verify_signed_x402_receipt

X402_RECEIPT_MAPPER_VERSION = "x402_receipt_v1"

FUNDING_EVIDENCE_FIELDS = (
    "payment_session_id",
    "authorization_id",
    "capture_id",
    "void_id",
    "x402_payment_session_id",
    "onchain_transaction_hashes",
)


class _X402ReceiptPayloadRequired(TypedDict):
    resourceUrl: str
    payer: str
    network: str
    issuedAt: int


class X402ReceiptPayloadV1(_X402ReceiptPayloadRequired, total=False):
    transaction: str


class ArtifactAttestedEvidence(TypedDict):
    artifact_blake3_hex: list[str]
    operation: str
    vendor_ref_id: str


def _read_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _read_string(record: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _read_number(record: dict[str, Any], *keys: str) -> int | float | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
    return None


def assert_not_x402_funding_artifact(input_record: dict[str, Any]) -> None:
    event_type = _read_string(input_record, "event_type", "eventType", "type")
    if event_type == "authorization_succeeded":
        raise ValueError(
            "authorization_succeeded webhooks are funding signals, not x402 delivery receipt evidence"
        )
    for field in FUNDING_EVIDENCE_FIELDS:
        if field in input_record:
            raise ValueError(f"funding field {field} must not be submitted as tool-completion evidence")


def _has_receipt_shape(record: dict[str, Any]) -> bool:
    return (
        _read_string(record, "resourceUrl", "resource_url") is not None
        and _read_string(record, "payer") is not None
        and _read_string(record, "network") is not None
        and _read_number(record, "issuedAt", "issued_at") is not None
    )


def _unwrap_receipt_record(input_record: dict[str, Any]) -> dict[str, Any]:
    assert_not_x402_funding_artifact(input_record)

    signed = extract_signed_x402_receipt(input_record)
    verified_payload = verify_signed_x402_receipt(signed)
    if _has_receipt_shape(verified_payload):
        return verified_payload

    raise ValueError(
        "x402 receipt payload missing required fields (resourceUrl, payer, network, issuedAt)"
    )


def build_x402_receipt_digest_payload(raw: dict[str, Any]) -> X402ReceiptPayloadV1:
    resource_url = _read_string(raw, "resourceUrl", "resource_url")
    payer = _read_string(raw, "payer")
    network = _read_string(raw, "network")
    issued_at = _read_number(raw, "issuedAt", "issued_at")
    transaction = _read_string(raw, "transaction", "txHash", "tx_hash")

    if not resource_url or not payer or not network or issued_at is None:
        raise ValueError(
            "x402 receipt payload missing required fields (resourceUrl, payer, network, issuedAt)"
        )

    payload: X402ReceiptPayloadV1 = {
        "resourceUrl": resource_url,
        "payer": payer,
        "network": network,
        "issuedAt": int(issued_at),
    }
    if transaction:
        payload["transaction"] = transaction
    return payload


def x402_receipt_payload_digest_hex(payload: X402ReceiptPayloadV1) -> str:
    return json_value_digest(payload).hex()


def map_x402_receipt_to_artifact_attested_evidence(
    receipt_input: dict[str, Any],
) -> ArtifactAttestedEvidence:
    raw = _unwrap_receipt_record(receipt_input)
    payload = build_x402_receipt_digest_payload(raw)
    return {
        "artifact_blake3_hex": [x402_receipt_payload_digest_hex(payload)],
        "operation": "attested",
        "vendor_ref_id": payload["resourceUrl"],
    }
