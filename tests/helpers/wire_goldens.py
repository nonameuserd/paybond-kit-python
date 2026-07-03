"""Shared wire-format golden vectors for cross-language parity tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypedDict


class EvidenceSignV1GoldenExpected(TypedDict):
    evidence_sign_version: int
    payload_digest_hex: str
    artifacts_digest_hex: str
    sign_bytes_hex: str


class EvidenceSignV1GoldenInput(TypedDict):
    tenant_id: str
    intent_id: str
    payee_did: str
    payload: dict[str, Any]
    artifacts_blake3_hex: list[str]
    submitted_at_rfc3339: str


class EvidenceSignV1Golden(TypedDict):
    input: EvidenceSignV1GoldenInput
    expected: EvidenceSignV1GoldenExpected


def repo_root() -> Path:
    path = Path(__file__).resolve()
    for parent in path.parents:
        candidate = parent / "kit" / "wire-goldens" / "evidence_sign_v1.json"
        if candidate.is_file():
            return parent
    raise FileNotFoundError("kit/wire-goldens/evidence_sign_v1.json not found")


def load_evidence_sign_v1_golden() -> EvidenceSignV1Golden:
    path = repo_root() / "kit" / "wire-goldens" / "evidence_sign_v1.json"
    return json.loads(path.read_text(encoding="utf-8"))
