from __future__ import annotations

import pytest

from paybond_kit.paybond import PaybondIntents


class _UnusedHarbor:
    async def create_intent(self, body: dict[str, object], *, idempotency_key: str | None = None) -> dict[str, object]:
        raise AssertionError("create_intent should not be called for invalid settlement_rail")


@pytest.mark.asyncio
async def test_paybond_intents_create_rejects_unknown_settlement_rail() -> None:
    intents = PaybondIntents(_UnusedHarbor(), "tenant-a")

    with pytest.raises(ValueError, match="settlement_rail must be one of"):
        await intents.create(
            principal_did="did:web:example.com#principal",
            principal_signing_seed=b"\x01" * 32,
            payee_did="did:web:example.com#payee",
            budget={"currency": "usd", "max_spend_usd": 10},
            predicate={"version": 1, "root": {"op": "true"}},
            currency="usd",
            amount_cents=1000,
            evidence_schema={"type": "object"},
            deadline_rfc3339="2030-01-01T00:00:00Z",
            allowed_tools=["payments.capture"],
            settlement_rail="bogus",
        )
