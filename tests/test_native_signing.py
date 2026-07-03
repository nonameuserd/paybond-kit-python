from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

pytest.importorskip("paybond_kit._native")

from paybond_kit.signing import sign_payee_evidence_binding


def test_sign_payee_evidence_binding_produces_harbor_shaped_json() -> None:
    intent_id = uuid.uuid4()
    seed = b"\x05" * 32
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    body = sign_payee_evidence_binding(
        tenant_id="tenant-a",
        intent_id=intent_id,
        payee_did="did:payee:1",
        payload={"ok": True},
        artifacts_blake3_hex=[],
        submitted_at_rfc3339=now,
        payee_signing_seed=seed,
    )
    assert set(body.keys()) == {
        "payload",
        "artifacts",
        "payee_did",
        "payee_pubkey",
        "payee_signature",
        "submitted_at",
    }
    assert body["payee_did"] == "did:payee:1"
    assert body["artifacts"] == []
    assert isinstance(body["payee_pubkey"], str)
    assert isinstance(body["payee_signature"], str)
    json.dumps(body)
