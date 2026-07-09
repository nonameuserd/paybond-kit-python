from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from paybond_kit.agent_receipt import (
    action_receipt_id,
    attach_operator_attestation_v1,
    config_hash_sha256_hex,
    value_digest_sha256_hex,
    verify_agent_receipt_v1,
    verify_agent_receipt_v1_from_json,
    ConfigHashInput,
)

CONFORMANCE_DIR = Path(__file__).resolve().parents[2] / "agent-receipt" / "conformance"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "agent-receipt" / "schema.json"


def test_signed_conformance_vector_verifies() -> None:
    receipt = json.loads((CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_text(encoding="utf-8"))
    verified = verify_agent_receipt_v1(receipt)
    assert verified["receipt_id"] == "0ab0f1c2b58543f4753b23fec340f16c931e43d102898606a08acbee37a1e484"


def test_signed_intent_terminal_conformance_vector_verifies() -> None:
    receipt = json.loads(
        (CONFORMANCE_DIR / "signed-intent-terminal-receipt-v1.json").read_text(encoding="utf-8")
    )
    verified = verify_agent_receipt_v1(receipt)
    assert verified["receipt_id"] == "660e8400-e29b-41d4-a716-446655440001"
    assert verified["scope"] == "intent_terminal"
    assert "execution" not in receipt


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


def test_unknown_top_level_key_rejected_from_json() -> None:
    receipt = json.loads((CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_text(encoding="utf-8"))
    receipt["extra_field"] = "leak"
    with pytest.raises(jsonschema.ValidationError):
        verify_agent_receipt_v1_from_json(receipt)


def test_forbidden_field_rejected_from_json() -> None:
    receipt = json.loads((CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_text(encoding="utf-8"))
    receipt["authorization"]["user_prompt"] = "secret prompt"
    with pytest.raises(ValueError, match="forbidden field"):
        verify_agent_receipt_v1_from_json(receipt)


def test_signed_conformance_vector_verifies_from_json() -> None:
    raw = (CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_bytes()
    verified = verify_agent_receipt_v1_from_json(raw)
    assert verified["receipt_id"] == "0ab0f1c2b58543f4753b23fec340f16c931e43d102898606a08acbee37a1e484"


def test_rejects_receipts_outside_expected_signing_public_keys() -> None:
    receipt = json.loads((CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="trusted key set"):
        verify_agent_receipt_v1(receipt, expected_signing_public_keys=["00" * 32])


OPERATOR_SEED = bytes.fromhex("11" * 32)


def _load_conformance_receipt() -> dict:
    return json.loads(
        (CONFORMANCE_DIR / "signed-action-receipt-v1.json").read_text(encoding="utf-8")
    )


def test_attach_and_verify_operator_attestation_bound_to_agent() -> None:
    receipt = _load_conformance_receipt()
    operator_did = receipt["authorization"]["agent"]["operator_did"]
    attested = attach_operator_attestation_v1(
        receipt, operator_private_key_seed=OPERATOR_SEED, operator_did=operator_did
    )
    assert attested["operator_attestation"]["operator_did"] == operator_did
    verified = verify_agent_receipt_v1(attested)
    assert verified["operator_attestation"]["operator_did"] == operator_did


def test_attach_rejects_operator_did_mismatch() -> None:
    receipt = _load_conformance_receipt()
    with pytest.raises(ValueError, match="operator_did must match authorization.agent.operator_did"):
        attach_operator_attestation_v1(
            receipt,
            operator_private_key_seed=OPERATOR_SEED,
            operator_did="did:web:operator.other",
        )


def test_verify_rejects_swapped_operator_did() -> None:
    receipt = _load_conformance_receipt()
    operator_did = receipt["authorization"]["agent"]["operator_did"]
    attested = attach_operator_attestation_v1(
        receipt, operator_private_key_seed=OPERATOR_SEED, operator_did=operator_did
    )
    attested["operator_attestation"]["operator_did"] = "did:web:operator.other"
    with pytest.raises(
        ValueError,
        match="operator_attestation.operator_did must match authorization.agent.operator_did",
    ):
        verify_agent_receipt_v1(attested)


def test_operator_registry_enforced_when_enabled() -> None:
    receipt = _load_conformance_receipt()
    operator_did = receipt["authorization"]["agent"]["operator_did"]
    attested = attach_operator_attestation_v1(
        receipt, operator_private_key_seed=OPERATOR_SEED, operator_did=operator_did
    )
    operator_pub_hex = attested["operator_attestation"]["signing_public_key_ed25519_hex"]

    verify_agent_receipt_v1(
        attested,
        verify_operator_against_registry=True,
        trusted_operator_public_keys=[operator_pub_hex],
    )

    with pytest.raises(ValueError, match="tenant operator registry"):
        verify_agent_receipt_v1(
            attested,
            verify_operator_against_registry=True,
            trusted_operator_public_keys=["00" * 32],
        )
