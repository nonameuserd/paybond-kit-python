from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from paybond_kit.agent_receipt import (
    action_receipt_id,
    config_hash_sha256_hex,
    value_digest_sha256_hex,
    verify_agent_receipt_v1,
    ConfigHashInput,
)

CONFORMANCE_DIR = Path(__file__).resolve().parents[2] / "agent-receipt" / "conformance"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "agent-receipt" / "schema.json"


def test_signed_conformance_vector_verifies() -> None:
    receipt = json.loads((CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_text(encoding="utf-8"))
    verified = verify_agent_receipt_v1(receipt)
    assert verified["receipt_id"] == "0ab0f1c2b58543f4753b23fec340f16c931e43d102898606a08acbee37a1e484"


def test_action_receipt_id_derivation() -> None:
    assert (
        action_receipt_id("550e8400-e29b-41d4-a716-446655440000", "call_test_action_001")
        == "0ab0f1c2b58543f4753b23fec340f16c931e43d102898606a08acbee37a1e484"
    )


def test_jcs_hash_vectors() -> None:
    vectors = json.loads((CONFORMANCE_DIR / "jcs-hash-vectors.json").read_text(encoding="utf-8"))
    by_name = {vector["name"]: vector for vector in vectors["vectors"]}
    mpp = by_name["mpp_sorted_object"]
    assert value_digest_sha256_hex(mpp["value"]) == mpp["jcs_sha256_hex"]
    config = by_name["config_hash_input"]
    assert (
        config_hash_sha256_hex(
            ConfigHashInput(
                system_prompt=config["value"]["system_prompt"],
                tools_manifest=config["value"]["tools_manifest"],
                policy_snapshot_id=config["value"]["policy_snapshot_id"],
            )
        )
        == config["jcs_sha256_hex"]
    )


def test_signed_vector_matches_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    receipt = json.loads((CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=receipt, schema=schema)


def test_tampered_receipt_rejected() -> None:
    receipt = json.loads((CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_text(encoding="utf-8"))
    receipt["outcome"]["harbor_state"] = "released"
    with pytest.raises(ValueError, match="message digest mismatch"):
        verify_agent_receipt_v1(receipt)
