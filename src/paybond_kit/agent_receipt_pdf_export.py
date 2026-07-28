"""Agent Receipt PDF export manifest validation and verification gate."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from paybond_kit.agent_receipt import verify_agent_receipt_v1_from_json

AGENT_RECEIPT_PDF_EXPORT_MANIFEST_SCHEMA_VERSION = 1
AGENT_RECEIPT_PDF_EXPORT_MANIFEST_KIND = "paybond.agent_receipt_pdf_export_manifest_v1"
AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL = "Derived from paybond.agent_receipt_v1"

FORBIDDEN_PDF_EXPORT_MANIFEST_FIELDS: tuple[str, ...] = (
    "embedded_receipt_json",
    "receipt_json",
    "unsigned_receipt",
    "canonical_receipt",
    "user_prompt",
    "system_prompt",
    "tool_arguments",
    "tool_results",
    "evidence_payload",
    "payee_signature",
)

_AGENT_RECEIPT_DIR = Path(__file__).resolve().parents[3] / "agent-receipt"
_PDF_EXPORT_MANIFEST_SCHEMA: dict[str, Any] | None = None
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class AgentReceiptPDFExportFooterStamp:
    label: str
    receipt_id: str
    message_digest_sha256_hex: str
    verify_endpoint: str | None = None


@dataclass(frozen=True)
class AgentReceiptPDFExportManifest:
    schema_version: int
    kind: str
    receipt_id: str
    message_digest_sha256_hex: str
    source_kind: str
    generated_at_rfc3339: str
    derived_view_label: str
    footer_stamp: AgentReceiptPDFExportFooterStamp
    source_artifact: str | None = None
    renderer_id: str | None = None
    pdf_sha256_hex: str | None = None
    pdf_page_count: int | None = None


def _load_pdf_export_manifest_schema() -> dict[str, Any]:
    global _PDF_EXPORT_MANIFEST_SCHEMA
    if _PDF_EXPORT_MANIFEST_SCHEMA is None:
        raw = (_AGENT_RECEIPT_DIR / "pdf-export-manifest-schema.json").read_text(encoding="utf-8")
        _PDF_EXPORT_MANIFEST_SCHEMA = json.loads(raw)
    schema = _PDF_EXPORT_MANIFEST_SCHEMA
    assert schema is not None
    return schema


def _reject_forbidden_pdf_export_manifest_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in FORBIDDEN_PDF_EXPORT_MANIFEST_FIELDS:
                raise ValueError(f"agent receipt pdf export manifest: forbidden field {key!r}")
            _reject_forbidden_pdf_export_manifest_fields(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _reject_forbidden_pdf_export_manifest_fields(item)


def _validate_manifest_shape(doc: Mapping[str, Any]) -> None:
    if doc.get("schema_version") != AGENT_RECEIPT_PDF_EXPORT_MANIFEST_SCHEMA_VERSION:
        raise ValueError("agent receipt pdf export manifest: unsupported schema_version")
    if doc.get("kind") != AGENT_RECEIPT_PDF_EXPORT_MANIFEST_KIND:
        raise ValueError("agent receipt pdf export manifest: unsupported kind")
    for field in (
        "receipt_id",
        "message_digest_sha256_hex",
        "source_kind",
        "generated_at_rfc3339",
        "derived_view_label",
        "footer_stamp",
    ):
        if field not in doc:
            raise ValueError(f"agent receipt pdf export manifest: missing {field}")
    digest = str(doc["message_digest_sha256_hex"])
    if not _HEX64_RE.fullmatch(digest):
        raise ValueError("agent receipt pdf export manifest: invalid message_digest_sha256_hex")
    if doc["derived_view_label"] != AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL:
        raise ValueError("agent receipt pdf export manifest: invalid derived_view_label")
    footer = doc["footer_stamp"]
    if not isinstance(footer, Mapping):
        raise ValueError("agent receipt pdf export manifest: footer_stamp must be object")
    for field in ("label", "receipt_id", "message_digest_sha256_hex"):
        if field not in footer:
            raise ValueError(f"agent receipt pdf export manifest: footer_stamp missing {field}")
    if footer.get("label") != AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL:
        raise ValueError("agent receipt pdf export manifest: invalid footer_stamp label")


def validate_agent_receipt_pdf_export_manifest_json(raw: bytes | str) -> AgentReceiptPDFExportManifest:
    """Reject authority-embedding fields and validate manifest shape."""
    text = raw if isinstance(raw, str) else raw.decode("utf-8")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("agent receipt pdf export manifest: invalid JSON") from exc
    if not isinstance(doc, Mapping):
        raise ValueError("agent receipt pdf export manifest: root must be object")
    _reject_forbidden_pdf_export_manifest_fields(doc)
    _validate_manifest_shape(doc)
    _ = _load_pdf_export_manifest_schema()
    footer_raw = doc["footer_stamp"]
    assert isinstance(footer_raw, Mapping)
    footer = AgentReceiptPDFExportFooterStamp(
        label=str(footer_raw["label"]),
        receipt_id=str(footer_raw["receipt_id"]),
        message_digest_sha256_hex=str(footer_raw["message_digest_sha256_hex"]),
        verify_endpoint=(
            str(footer_raw["verify_endpoint"]) if footer_raw.get("verify_endpoint") else None
        ),
    )
    return AgentReceiptPDFExportManifest(
        schema_version=int(doc["schema_version"]),
        kind=str(doc["kind"]),
        receipt_id=str(doc["receipt_id"]),
        message_digest_sha256_hex=str(doc["message_digest_sha256_hex"]),
        source_kind=str(doc["source_kind"]),
        generated_at_rfc3339=str(doc["generated_at_rfc3339"]),
        derived_view_label=str(doc["derived_view_label"]),
        footer_stamp=footer,
        source_artifact=str(doc["source_artifact"]) if doc.get("source_artifact") else None,
        renderer_id=str(doc["renderer_id"]) if doc.get("renderer_id") else None,
        pdf_sha256_hex=str(doc["pdf_sha256_hex"]) if doc.get("pdf_sha256_hex") else None,
        pdf_page_count=int(doc["pdf_page_count"]) if doc.get("pdf_page_count") is not None else None,
    )


def _assert_manifest_matches_receipt(
    manifest: AgentReceiptPDFExportManifest, receipt: Mapping[str, Any]
) -> None:
    receipt_id = receipt["receipt_id"].strip().lower()
    digest = receipt["message_digest_sha256_hex"].strip().lower()
    if manifest.receipt_id.strip().lower() != receipt_id:
        raise ValueError(
            "agent receipt pdf export gate: manifest receipt_id does not match verified receipt"
        )
    if manifest.message_digest_sha256_hex.strip().lower() != digest:
        raise ValueError(
            "agent receipt pdf export gate: manifest message_digest_sha256_hex does not match verified receipt"
        )
    stamp = manifest.footer_stamp
    if stamp.receipt_id.strip().lower() != receipt_id:
        raise ValueError(
            "agent receipt pdf export gate: footer_stamp receipt_id does not match verified receipt"
        )
    if stamp.message_digest_sha256_hex.strip().lower() != digest:
        raise ValueError(
            "agent receipt pdf export gate: footer_stamp message_digest_sha256_hex does not match verified receipt"
        )


def gate_agent_receipt_pdf_export(
    receipt_json: bytes | str,
    manifest_json: bytes | str,
    pdf_bytes: bytes | None = None,
) -> tuple[dict[str, Any], AgentReceiptPDFExportManifest]:
    """Enforce the PDF export verification gate before rendering or accepting a derived PDF."""
    receipt = verify_agent_receipt_v1_from_json(receipt_json)
    manifest = validate_agent_receipt_pdf_export_manifest_json(manifest_json)
    _assert_manifest_matches_receipt(manifest, receipt)
    if pdf_bytes is not None and manifest.pdf_sha256_hex:
        actual = hashlib.sha256(pdf_bytes).hexdigest()
        if actual != manifest.pdf_sha256_hex.strip().lower():
            raise ValueError("agent receipt pdf export gate: pdf_sha256_hex mismatch")
    return receipt, manifest
