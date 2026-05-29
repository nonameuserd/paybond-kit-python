"""Shared run-context binding for capability-gated tool execution (Agents SDK, LangGraph, custom)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from paybond_kit.harbor import GatewayHarborClient, HarborClient


@dataclass(frozen=True)
class PaybondCapabilityBinding:
    """
    Tenant-scoped Harbor binding for one funded intent and one Biscuit capability token.

    Reuse a single client only within the same tenant realm; never mix tenants or intent ids
    across concurrent agent runs.
    """

    harbor: HarborClient | GatewayHarborClient
    intent_id: UUID
    capability_token: str

    async def verify_spend_capability(
        self,
        *,
        operation: str,
        requested_spend_cents: int = 0,
    ):
        return await self.harbor.verify_capability(
            intent_id=self.intent_id,
            token=self.capability_token,
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )

    async def authorize_spend(
        self,
        *,
        operation: str,
        requested_spend_cents: int = 0,
    ):
        return await self.verify_spend_capability(
            operation=operation,
            requested_spend_cents=requested_spend_cents,
        )
