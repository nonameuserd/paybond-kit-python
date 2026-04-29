"""Shared run-context binding for capability-gated tool execution (Agents SDK, LangGraph, custom)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from paybond_kit.harbor import HarborClient


@dataclass(frozen=True)
class PaybondCapabilityBinding:
    """
    Tenant-scoped Harbor binding for one funded intent and one Biscuit capability token.

    Reuse a single :class:`HarborClient` only within the same tenant realm; never mix tenants or
    intent ids across concurrent agent runs.
    """

    harbor: HarborClient
    intent_id: UUID
    capability_token: str
