from __future__ import annotations

import hashlib
import json
from pathlib import Path

from paybond_kit.agent_receipt_acta import project_agent_receipt_to_acta_decision_receipt
from paybond_kit.agent_receipt_pef import (
    build_agent_receipt_pef_frame,
    verify_agent_receipt_pef_frame_id,
)
from paybond_kit.agent_receipt_scitt import (
    build_agent_receipt_scitt_export,
    verify_agent_receipt_scitt_export,
)

CONFORMANCE = Path(__file__).resolve().parents[2] / "agent-receipt" / "conformance"


def test_acta_projection_matches_golden() -> None:
    receipt = json.loads((CONFORMANCE / "signed-action-receipt-v1.json").read_text())
    golden = json.loads((CONFORMANCE / "acta-projection-v1.json").read_text())
    assert project_agent_receipt_to_acta_decision_receipt(receipt) == golden["expected"]


def test_pef_frame_id_matches_golden() -> None:
    receipt = json.loads((CONFORMANCE / "signed-action-receipt-v1.json").read_text())
    golden = json.loads((CONFORMANCE / "pef-frame-id-v1.json").read_text())
    frame = build_agent_receipt_pef_frame(
        receipt=receipt,
        frame_provider_did=golden["frame_provider_did"],
        frame_timestamp_ms=golden["frame_timestamp_ms"],
    )
    assert frame["receipt_hash"] == golden["expected_receipt_hash"]
    assert frame["frame_id"] == golden["expected_frame_id"]
    assert frame["claim_type"] == golden["expected_claim_type"]
    verify_agent_receipt_pef_frame_id(frame)
    again = build_agent_receipt_pef_frame(
        receipt=receipt,
        frame_provider_did=golden["frame_provider_did"],
        frame_timestamp_ms=golden["frame_timestamp_ms"],
    )
    assert again["frame_id"] == frame["frame_id"]


def test_scitt_export_matches_golden_and_verifies() -> None:
    golden = json.loads((CONFORMANCE / "scitt-cose-export-v1.json").read_text())
    seed = hashlib.sha256(
        golden["signing_private_key_seed_sha256_of"].encode("utf-8")
    ).hexdigest()
    assert seed == golden["signing_private_key_seed_hex"]
    export_doc = build_agent_receipt_scitt_export(
        receipt_id=golden["expected"]["receipt_id"],
        message_digest_sha256_hex=golden["expected"]["message_digest_sha256_hex"],
        signing_private_key_seed_hex=seed,
        issuer=golden["issuer"],
        kid=golden["kid"],
    )
    assert export_doc == golden["expected"]
    verify_agent_receipt_scitt_export(export_doc)
