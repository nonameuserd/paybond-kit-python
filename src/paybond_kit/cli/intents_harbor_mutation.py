from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from paybond_kit.cli.agent_production_evidence import resolve_agent_recognition_from_cli
from paybond_kit.cli.core import CliContext, consume_flag


@dataclass(frozen=True)
class HarborMutationFlags:
    """Parsed recognition and idempotency flags for Harbor intent mutation CLI commands."""

    recognition_key_id: str | None
    recognition_seed_hex: str | None
    idempotency_key: str | None
    rest_argv: list[str]


def parse_harbor_mutation_flags(argv: list[str]) -> HarborMutationFlags:
    """Extract shared Harbor mutation flags from argv, leaving body and positional args in rest_argv."""
    _, recognition_key_id, argv = consume_flag(argv, "--agent-recognition-key-id")
    _, recognition_seed_hex, argv = consume_flag(argv, "--agent-recognition-signing-seed-hex")
    _, idempotency_key, argv = consume_flag(argv, "--idempotency-key")
    return HarborMutationFlags(
        recognition_key_id=recognition_key_id,
        recognition_seed_hex=recognition_seed_hex,
        idempotency_key=idempotency_key,
        rest_argv=argv,
    )


def resolve_harbor_recognition(
    ctx: CliContext,
    *,
    recognition_key_id: str | None,
    recognition_seed_hex: str | None,
) -> dict[str, Any]:
    """Resolve agent recognition credentials for Harbor intent mutations from flags and APP_* env fallbacks."""
    return resolve_agent_recognition_from_cli(
        cwd=ctx.cwd,
        env_file=ctx.globals.env_file,
        agent_recognition_key_id=recognition_key_id,
        agent_recognition_signing_seed_hex=recognition_seed_hex,
    )


DEPRECATED_INTENTS_FUND_BODY_WARNING = (
    "deprecated: intents fund --body; use --payment-signature"
)


def fund_body_shim_used(argv: list[str]) -> bool:
    """Whether deprecated ``--body`` / ``--stdin`` shims were passed to ``intents fund``."""
    return "--body" in argv or "--stdin" in argv


def resolve_fund_payment_signature_from_body(payload: dict[str, Any]) -> str | None:
    """Read ``payment_signature`` from deprecated ``intents fund --body`` JSON when present."""
    value = payload.get("payment_signature")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
