from __future__ import annotations

from pathlib import Path

import pytest

from paybond_kit.agent.types import PaybondRunProductionEvidenceCredentials
from paybond_kit.cli.agent_production_evidence import (
    PersistedProductionEvidence,
    production_evidence_to_persisted,
    resolve_production_evidence_for_reattach,
    resolve_production_evidence_from_cli,
)
from paybond_kit.cli.core import CliError

PAYEE_SEED_HEX = "01" * 32
AGENT_SEED_HEX = "02" * 32


def test_resolve_production_evidence_from_cli_flags(tmp_path: Path) -> None:
    credentials = resolve_production_evidence_from_cli(
        cwd=tmp_path,
        env_file=".env.local",
        payee_did="did:web:vendor.example",
        payee_signing_seed_hex=PAYEE_SEED_HEX,
        agent_recognition_key_id="kid-1",
        agent_recognition_signing_seed_hex=AGENT_SEED_HEX,
    )
    assert credentials["payee_did"] == "did:web:vendor.example"
    assert credentials["agent_recognition_key_id"] == "kid-1"
    assert len(credentials["payee_signing_seed"]) == 32
    assert len(credentials["agent_recognition_signing_seed"]) == 32


def test_resolve_production_evidence_from_cli_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env.local").write_text(
        "\n".join(
            [
                "APP_PAYEE_DID=did:web:vendor.example",
                f"APP_PAYEE_SEED_HEX={PAYEE_SEED_HEX}",
                "APP_AGENT_RECOGNITION_KEY_ID=kid-1",
                f"APP_AGENT_RECOGNITION_SEED_HEX={AGENT_SEED_HEX}",
            ]
        ),
        encoding="utf-8",
    )
    credentials = resolve_production_evidence_from_cli(cwd=tmp_path, env_file=".env.local")
    assert credentials["payee_did"] == "did:web:vendor.example"
    assert credentials["agent_recognition_key_id"] == "kid-1"


def test_resolve_production_evidence_from_cli_rejects_incomplete(tmp_path: Path) -> None:
    with pytest.raises(CliError, match="production attach requires") as exc_info:
        resolve_production_evidence_from_cli(
            cwd=tmp_path,
            env_file=".env.local",
            payee_did="did:web:vendor.example",
        )
    assert exc_info.value.code == "cli.agent.production_evidence_incomplete"


def test_production_evidence_to_persisted_stores_metadata_only() -> None:
    credentials: PaybondRunProductionEvidenceCredentials = {
        "payee_did": "did:web:vendor.example",
        "payee_signing_seed": bytes(range(1, 33)),
        "agent_recognition_key_id": "kid-1",
        "agent_recognition_signing_seed": bytes(range(33, 65)),
    }
    persisted = production_evidence_to_persisted(credentials)
    assert persisted == {
        "payee_did": "did:web:vendor.example",
        "agent_recognition_key_id": "kid-1",
    }
    assert "payee_signing_seed_hex" not in persisted
    assert "agent_recognition_signing_seed_hex" not in persisted


def test_resolve_production_evidence_for_reattach_requires_fresh_seeds(tmp_path: Path) -> None:
    persisted: PersistedProductionEvidence = {
        "payee_did": "did:web:vendor.example",
        "agent_recognition_key_id": "kid-1",
    }
    with pytest.raises(CliError, match="requires --payee-signing-seed-file") as exc_info:
        resolve_production_evidence_for_reattach(
            cwd=tmp_path,
            env_file=".env.local",
            persisted=persisted,
        )
    assert exc_info.value.code == "cli.agent.production_signing_seed_required"


def test_resolve_production_evidence_for_reattach_merges_metadata_and_seeds(tmp_path: Path) -> None:
    persisted: PersistedProductionEvidence = {
        "payee_did": "did:web:vendor.example",
        "agent_recognition_key_id": "kid-1",
    }
    credentials = resolve_production_evidence_for_reattach(
        cwd=tmp_path,
        env_file=".env.local",
        persisted=persisted,
        payee_signing_seed_hex=PAYEE_SEED_HEX,
        agent_recognition_signing_seed_hex=AGENT_SEED_HEX,
    )
    assert credentials["payee_did"] == "did:web:vendor.example"
    assert credentials["agent_recognition_key_id"] == "kid-1"
    assert credentials["payee_signing_seed"] == bytes.fromhex(PAYEE_SEED_HEX)
    assert credentials["agent_recognition_signing_seed"] == bytes.fromhex(AGENT_SEED_HEX)
