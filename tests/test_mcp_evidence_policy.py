from __future__ import annotations

import pytest

from paybond_kit.mcp_evidence_policy import (
    McpEvidencePolicyError,
    McpEvidenceValidationGate,
    completion_evidence_validation_ok,
    evidence_validation_gate_key,
    parse_mcp_evidence_policy,
)


def test_parse_mcp_evidence_policy_defaults_to_strict() -> None:
    assert parse_mcp_evidence_policy(None) == "strict"


def test_parse_mcp_evidence_policy_accepts_off() -> None:
    assert parse_mcp_evidence_policy("off") == "off"


def test_evidence_gate_requires_prior_validate_pass() -> None:
    gate = McpEvidenceValidationGate(policy="strict")
    canonical_payload = {
        "http_status": 200,
        "vendor_ref_id": "job-123",
        "response_digest": "blake3:abc",
    }
    gate_key = evidence_validation_gate_key(
        preset_id="api_response_ok",
        canonical_payload=canonical_payload,
    )
    gate.record_pass(gate_key)
    gate.require_pass(
        preset_id="api_response_ok",
        canonical_payload=canonical_payload,
    )


def test_evidence_gate_blocks_submit_without_validate_pass() -> None:
    gate = McpEvidenceValidationGate(policy="strict")
    canonical_payload = {
        "http_status": 200,
        "vendor_ref_id": "job-123",
        "response_digest": "blake3:abc",
    }
    with pytest.raises(McpEvidencePolicyError, match="not pre-validated"):
        gate.require_pass(
            preset_id="api_response_ok",
            canonical_payload=canonical_payload,
        )


def test_validate_and_record_marks_ok_reports() -> None:
    gate = McpEvidenceValidationGate(policy="strict")
    canonical_payload = {
        "http_status": 200,
        "vendor_ref_id": "job-123",
        "response_digest": "blake3:abc",
    }
    report = gate.validate_and_record(
        preset_id="api_response_ok",
        canonical_payload=canonical_payload,
    )
    assert completion_evidence_validation_ok(report)
    gate.require_pass(
        preset_id="api_response_ok",
        canonical_payload=canonical_payload,
    )
