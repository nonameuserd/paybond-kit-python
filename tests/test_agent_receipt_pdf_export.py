import hashlib
import json
from pathlib import Path

import pytest

from paybond_kit.agent_receipt_pdf_export import (
    gate_agent_receipt_pdf_export,
    validate_agent_receipt_pdf_export_manifest_json,
)

CONFORMANCE_DIR = Path(__file__).resolve().parents[2] / "agent-receipt" / "conformance"


def test_validate_manifest_conformance_vector() -> None:
    raw = (CONFORMANCE_DIR / "pdf-export-manifest-v1.json").read_text(encoding="utf-8")
    manifest = validate_agent_receipt_pdf_export_manifest_json(raw)
    assert manifest.kind == "paybond.agent_receipt_pdf_export_manifest_v1"


def test_validate_rejects_embedded_receipt_json() -> None:
    doc = json.loads((CONFORMANCE_DIR / "pdf-export-manifest-v1.json").read_text(encoding="utf-8"))
    doc["embedded_receipt_json"] = {"receipt_id": "forged"}
    with pytest.raises(ValueError, match="forbidden field"):
        validate_agent_receipt_pdf_export_manifest_json(json.dumps(doc))


def test_gate_binds_manifest_to_verified_receipt() -> None:
    receipt = (CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_bytes()
    manifest = (CONFORMANCE_DIR / "pdf-export-manifest-v1.json").read_bytes()
    verified_receipt, verified_manifest = gate_agent_receipt_pdf_export(receipt, manifest)
    assert verified_manifest.receipt_id == verified_receipt["receipt_id"]
    assert (
        verified_manifest.message_digest_sha256_hex
        == verified_receipt["message_digest_sha256_hex"]
    )


def test_gate_verifies_pdf_hash_when_bytes_supplied() -> None:
    receipt = (CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_bytes()
    doc = json.loads((CONFORMANCE_DIR / "pdf-export-manifest-v1.json").read_text(encoding="utf-8"))
    pdf_bytes = b"%PDF-1.4 conformance test bytes"
    doc["pdf_sha256_hex"] = hashlib.sha256(pdf_bytes).hexdigest()
    gate_agent_receipt_pdf_export(receipt, json.dumps(doc), pdf_bytes=pdf_bytes)
    with pytest.raises(ValueError, match="pdf_sha256_hex mismatch"):
        gate_agent_receipt_pdf_export(receipt, json.dumps(doc), pdf_bytes=b"tampered")
