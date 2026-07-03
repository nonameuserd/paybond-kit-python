from __future__ import annotations

import json

import pytest

from paybond_kit.json_digest import json_value_digest
from tests.helpers.wire_goldens import load_evidence_sign_v1_golden

pytest.importorskip("paybond_kit._native")

from paybond_kit._native import encode_evidence_sign_v1_hex  # type: ignore[attr-defined]


def test_evidence_sign_v1_payload_digest_matches_wire_golden() -> None:
    golden = load_evidence_sign_v1_golden()
    digest = json_value_digest(golden["input"]["payload"]).hex()
    assert digest == golden["expected"]["payload_digest_hex"]


def test_evidence_sign_v1_sign_bytes_match_wire_golden() -> None:
    golden = load_evidence_sign_v1_golden()
    payload = golden["input"]["payload"]
    got = encode_evidence_sign_v1_hex(
        golden["input"]["tenant_id"],
        golden["input"]["intent_id"],
        golden["input"]["payee_did"],
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
        golden["input"]["artifacts_blake3_hex"],
        golden["input"]["submitted_at_rfc3339"],
    )
    assert got == golden["expected"]["sign_bytes_hex"]
