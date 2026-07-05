from __future__ import annotations

import io
from pathlib import Path

import pytest

from paybond_kit.cli.core import CliContext, CliError, default_globals
from paybond_kit.cli.intents_harbor_mutation import (
    fund_body_shim_used,
    parse_harbor_mutation_flags,
    resolve_fund_payment_signature_from_body,
    resolve_harbor_recognition,
)

AGENT_SEED_HEX = "02" * 32


def _make_ctx(tmp_path: Path) -> CliContext:
    return CliContext(
        globals=default_globals(),
        cwd=tmp_path,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )


def test_parse_harbor_mutation_flags_extracts_recognition_and_idempotency() -> None:
    flags = parse_harbor_mutation_flags(
        [
            "--agent-recognition-key-id",
            "kid-1",
            "--agent-recognition-signing-seed-hex",
            AGENT_SEED_HEX,
            "--idempotency-key",
            "idem-1",
            "--body",
            "payload.json",
        ]
    )
    assert flags.recognition_key_id == "kid-1"
    assert flags.recognition_seed_hex == AGENT_SEED_HEX
    assert flags.idempotency_key == "idem-1"
    assert flags.rest_argv == ["--body", "payload.json"]


def test_parse_harbor_mutation_flags_leaves_unrecognized_args_in_rest_argv() -> None:
    flags = parse_harbor_mutation_flags(["intent-123", "--body", "payload.json"])
    assert flags.recognition_key_id is None
    assert flags.recognition_seed_hex is None
    assert flags.idempotency_key is None
    assert flags.rest_argv == ["intent-123", "--body", "payload.json"]


def test_resolve_harbor_recognition_from_flags(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    recognition = resolve_harbor_recognition(
        ctx,
        recognition_key_id="kid-1",
        recognition_seed_hex=AGENT_SEED_HEX,
    )
    assert recognition["agent_recognition_key_id"] == "kid-1"
    assert len(recognition["agent_recognition_signing_seed"]) == 32


def test_resolve_harbor_recognition_falls_back_to_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env.local").write_text(
        "\n".join(
            [
                "APP_AGENT_RECOGNITION_KEY_ID=kid-env",
                f"APP_AGENT_RECOGNITION_SEED_HEX={AGENT_SEED_HEX}",
            ]
        ),
        encoding="utf-8",
    )
    ctx = _make_ctx(tmp_path)
    recognition = resolve_harbor_recognition(ctx, recognition_key_id=None, recognition_seed_hex=None)
    assert recognition["agent_recognition_key_id"] == "kid-env"


def test_resolve_harbor_recognition_rejects_incomplete_credentials(tmp_path: Path) -> None:
    ctx = _make_ctx(tmp_path)
    with pytest.raises(CliError, match="Harbor intent mutation requires") as exc_info:
        resolve_harbor_recognition(ctx, recognition_key_id=None, recognition_seed_hex=None)
    assert exc_info.value.code == "cli.agent.recognition_incomplete"


def test_resolve_fund_payment_signature_from_body() -> None:
    assert resolve_fund_payment_signature_from_body({"payment_signature": " sig-1 "}) == "sig-1"
    assert resolve_fund_payment_signature_from_body({}) is None


def test_fund_body_shim_used() -> None:
    assert fund_body_shim_used(["--body", "fund.json"]) is True
    assert fund_body_shim_used(["--stdin"]) is True
    assert fund_body_shim_used(["--payment-signature", "sig"]) is False
