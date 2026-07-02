"""MCP completion-evidence validation gate (signal-only; Harbor remains authoritative)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from paybond_kit.completion_validate_evidence import (
    CompletionEvidenceValidationReport,
    validate_completion_evidence,
)
from paybond_kit.json_digest import json_value_digest

McpEvidencePolicy = Literal["strict", "off"]
MCP_EVIDENCE_POLICY_ENV = "PAYBOND_MCP_EVIDENCE_POLICY"
DEFAULT_MCP_EVIDENCE_POLICY: McpEvidencePolicy = "strict"

EVIDENCE_SUBMIT_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "paybond_submit_evidence",
        "paybond_submit_spend_evidence",
        "paybond_submit_sandbox_guardrail_evidence",
    }
)


class McpEvidencePolicyError(RuntimeError):
    """Raised when MCP evidence submit is blocked by the local validation gate."""


def parse_mcp_evidence_policy(raw: str | None) -> McpEvidencePolicy:
    value = (raw or "").strip().lower()
    if not value:
        return DEFAULT_MCP_EVIDENCE_POLICY
    if value in ("strict", "off"):
        return value  # type: ignore[return-value]
    raise ValueError("invalid PAYBOND_MCP_EVIDENCE_POLICY (expected strict|off)")


def completion_evidence_validation_ok(report: CompletionEvidenceValidationReport) -> bool:
    return len(report.get("drift_kinds", [])) == 0


def evidence_validation_gate_key(
    *,
    preset_id: str,
    vendor_payload: dict[str, Any] | None = None,
    canonical_payload: dict[str, Any] | None = None,
) -> str:
    preset = preset_id.strip()
    if not preset:
        raise ValueError("completion preset id is required for evidence validation")
    digest = json_value_digest(
        {
            "preset_id": preset,
            "vendor_payload": vendor_payload,
            "canonical_payload": canonical_payload,
        }
    )
    return digest.hex()


def extract_harbor_evidence_validation_input(
    body: dict[str, Any],
    *,
    completion_preset_id: str | None = None,
) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
    preset = (completion_preset_id or "").strip()
    if not preset:
        for key in ("completion_preset_id", "completion_preset"):
            raw = body.get(key)
            if isinstance(raw, str) and raw.strip():
                preset = raw.strip()
                break
    vendor_payload = body.get("vendor_payload")
    if not isinstance(vendor_payload, dict):
        vendor_payload = None
    payload = body.get("payload")
    if not isinstance(payload, dict):
        payload = None
    canonical_payload = payload
    return preset, vendor_payload, canonical_payload


def extract_sandbox_guardrail_validation_input(
    *,
    payload: dict[str, Any] | None = None,
    completion_preset_id: str | None = None,
) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
    preset = (completion_preset_id or "").strip()
    vendor_payload = payload
    canonical_payload = payload
    return preset, vendor_payload, canonical_payload


@dataclass
class McpEvidenceValidationGate:
    """In-memory validation passes for the lifetime of one MCP server process."""

    policy: McpEvidencePolicy = DEFAULT_MCP_EVIDENCE_POLICY
    _passes: set[str] = field(default_factory=set)

    def record_pass(self, gate_key: str) -> None:
        self._passes.add(gate_key)

    def has_pass(self, gate_key: str) -> bool:
        return gate_key in self._passes

    def require_pass(
        self,
        *,
        preset_id: str,
        vendor_payload: dict[str, Any] | None = None,
        canonical_payload: dict[str, Any] | None = None,
    ) -> None:
        if self.policy == "off":
            return
        preset = preset_id.strip()
        if not preset:
            return
        gate_key = evidence_validation_gate_key(
            preset_id=preset,
            vendor_payload=vendor_payload,
            canonical_payload=canonical_payload,
        )
        if not self.has_pass(gate_key):
            raise McpEvidencePolicyError(
                "completion evidence was not pre-validated; call "
                "paybond_validate_completion_evidence with the same preset and payload "
                "before submit (Harbor remains authoritative at submit time)"
            )

    def validate_and_record(
        self,
        *,
        preset_id: str,
        vendor_payload: dict[str, Any] | None = None,
        canonical_payload: dict[str, Any] | None = None,
        frozen_vendor_api_version: str | None = None,
        frozen_vendor_schema_digest_hex: str | None = None,
        frozen_canonical_schema_digest_hex: str | None = None,
    ) -> CompletionEvidenceValidationReport:
        report = validate_completion_evidence(
            preset_id=preset_id,
            vendor_payload=vendor_payload,
            canonical_payload=canonical_payload,
            frozen_vendor_api_version=frozen_vendor_api_version,
            frozen_vendor_schema_digest_hex=frozen_vendor_schema_digest_hex,
            frozen_canonical_schema_digest_hex=frozen_canonical_schema_digest_hex,
        )
        if completion_evidence_validation_ok(report):
            self.record_pass(
                evidence_validation_gate_key(
                    preset_id=preset_id,
                    vendor_payload=vendor_payload,
                    canonical_payload=canonical_payload,
                )
            )
        return report
