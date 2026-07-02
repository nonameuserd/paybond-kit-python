"""Resolve production auto-evidence credentials for agent run attach binds."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TypedDict

from paybond_kit.agent.types import PaybondRunProductionEvidenceCredentials
from paybond_kit.cli.core import CliError, read_env_file_value

_SEED_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class PersistedProductionEvidence(TypedDict):
    payee_did: str
    agent_recognition_key_id: str


def _resolve_env_path(cwd: Path, env_file: str) -> Path:
    path = Path(env_file)
    return path if path.is_absolute() else cwd / path


def _read_configured_env_value(cwd: Path, env_file: str, key: str) -> str | None:
    from_process = os.environ.get(key, "").strip()
    if from_process:
        return from_process
    env_path = _resolve_env_path(cwd, env_file)
    try:
        body = env_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return read_env_file_value(body, key)


def _parse_seed32_hex(raw: str, field: str) -> bytes:
    hex_value = raw.strip().removeprefix("0x").removeprefix("0X")
    if not _SEED_HEX_RE.fullmatch(hex_value):
        raise CliError(
            f"{field} must be a 32-byte Ed25519 seed (64 hex characters)",
            category="usage",
            code="cli.agent.invalid_signing_seed",
            details={"field": field},
        )
    return bytes.fromhex(hex_value)


def resolve_production_evidence_from_cli(
    *,
    cwd: Path,
    env_file: str,
    payee_did: str | None = None,
    payee_signing_seed_hex: str | None = None,
    agent_recognition_key_id: str | None = None,
    agent_recognition_signing_seed_hex: str | None = None,
) -> PaybondRunProductionEvidenceCredentials:
    resolved_payee_did = (payee_did or "").strip() or _read_configured_env_value(cwd, env_file, "APP_PAYEE_DID")
    resolved_payee_seed_hex = (payee_signing_seed_hex or "").strip() or _read_configured_env_value(
        cwd,
        env_file,
        "APP_PAYEE_SEED_HEX",
    )
    resolved_key_id = (agent_recognition_key_id or "").strip() or _read_configured_env_value(
        cwd,
        env_file,
        "APP_AGENT_RECOGNITION_KEY_ID",
    )
    resolved_agent_seed_hex = (agent_recognition_signing_seed_hex or "").strip() or _read_configured_env_value(
        cwd,
        env_file,
        "APP_AGENT_RECOGNITION_SEED_HEX",
    )

    if not resolved_payee_did:
        raise CliError(
            "production attach requires --payee-did or APP_PAYEE_DID",
            category="usage",
            code="cli.agent.production_evidence_incomplete",
        )
    if not resolved_payee_seed_hex:
        raise CliError(
            "production attach requires --payee-signing-seed-hex or APP_PAYEE_SEED_HEX",
            category="usage",
            code="cli.agent.production_evidence_incomplete",
        )
    if not resolved_key_id:
        raise CliError(
            "production attach requires --agent-recognition-key-id or APP_AGENT_RECOGNITION_KEY_ID",
            category="usage",
            code="cli.agent.production_evidence_incomplete",
        )
    if not resolved_agent_seed_hex:
        raise CliError(
            "production attach requires --agent-recognition-signing-seed-hex or "
            "APP_AGENT_RECOGNITION_SEED_HEX",
            category="usage",
            code="cli.agent.production_evidence_incomplete",
        )

    return {
        "payee_did": resolved_payee_did,
        "payee_signing_seed": _parse_seed32_hex(resolved_payee_seed_hex, "--payee-signing-seed-hex"),
        "agent_recognition_key_id": resolved_key_id,
        "agent_recognition_signing_seed": _parse_seed32_hex(
            resolved_agent_seed_hex,
            "--agent-recognition-signing-seed-hex",
        ),
    }


def production_evidence_to_persisted(
    credentials: PaybondRunProductionEvidenceCredentials,
) -> PersistedProductionEvidence:
    return {
        "payee_did": credentials["payee_did"],
        "agent_recognition_key_id": credentials["agent_recognition_key_id"],
    }


def resolve_production_evidence_for_reattach(
    *,
    cwd: Path,
    env_file: str,
    persisted: PersistedProductionEvidence,
    payee_signing_seed_hex: str | None = None,
    agent_recognition_signing_seed_hex: str | None = None,
    command: str = "agent tool execute",
) -> PaybondRunProductionEvidenceCredentials:
    payee_did = str(persisted.get("payee_did", "")).strip()
    key_id = str(persisted.get("agent_recognition_key_id", "")).strip()
    if not payee_did or not key_id:
        raise CliError(
            f"run is missing production_evidence metadata; re-bind with production attach flags",
            category="validation",
            code="cli.agent.missing_production_evidence",
        )

    resolved_payee_seed_hex = (payee_signing_seed_hex or "").strip() or _read_configured_env_value(
        cwd,
        env_file,
        "APP_PAYEE_SEED_HEX",
    )
    resolved_agent_seed_hex = (agent_recognition_signing_seed_hex or "").strip() or _read_configured_env_value(
        cwd,
        env_file,
        "APP_AGENT_RECOGNITION_SEED_HEX",
    )
    if not resolved_payee_seed_hex:
        raise CliError(
            f"{command} requires --payee-signing-seed-hex or APP_PAYEE_SEED_HEX for production runs",
            category="usage",
            code="cli.agent.production_signing_seed_required",
        )
    if not resolved_agent_seed_hex:
        raise CliError(
            f"{command} requires --agent-recognition-signing-seed-hex or "
            "APP_AGENT_RECOGNITION_SEED_HEX for production runs",
            category="usage",
            code="cli.agent.production_signing_seed_required",
        )

    return {
        "payee_did": payee_did,
        "payee_signing_seed": _parse_seed32_hex(resolved_payee_seed_hex, "--payee-signing-seed-hex"),
        "agent_recognition_key_id": key_id,
        "agent_recognition_signing_seed": _parse_seed32_hex(
            resolved_agent_seed_hex,
            "--agent-recognition-signing-seed-hex",
        ),
    }
