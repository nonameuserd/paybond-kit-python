from __future__ import annotations

import httpx
import pytest
import respx

from paybond_kit.a2a import GatewayA2AClient


@pytest.mark.asyncio
@respx.mock
async def test_get_agent_card_returns_published_document() -> None:
    respx.get("https://gateway.test/.well-known/agent-card.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "Paybond Protocol Trust Delegation",
                "description": "discovery",
                "supportedInterfaces": [],
                "version": "2.0.0-preview",
                "capabilities": {},
                "defaultInputModes": ["application/json"],
                "defaultOutputModes": ["application/json"],
                "skills": [],
            },
        )
    )
    client = GatewayA2AClient("https://gateway.test")
    try:
        card = await client.get_agent_card()
        assert card["name"] == "Paybond Protocol Trust Delegation"
        assert card["version"] == "2.0.0-preview"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_get_task_contract_returns_specific_contract() -> None:
    respx.get(
        "https://gateway.test/protocol/v2/a2a/task-contracts/paybond.settlement.intent.create.v1"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "schemaVersion": 1,
                "kind": "paybond.a2a.settlement_task_contract_v1",
                "id": "paybond.settlement.intent.create.v1",
                "name": "Create delegated commercial intent",
                "description": "desc",
                "url": "https://gateway.test/protocol/v2/a2a/task-contracts/paybond.settlement.intent.create.v1",
                "routeBindings": ["https://gateway.test/harbor/intents"],
                "requiredTrustArtifacts": ["paybond.agent_mandate_v1"],
                "settlementPhases": ["authorize"],
                "participants": [],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
                "inputFields": [],
                "resultFields": [],
            },
        )
    )
    client = GatewayA2AClient("https://gateway.test")
    try:
        contract = await client.get_task_contract(
            "paybond.settlement.intent.create.v1"
        )
        assert contract["id"] == "paybond.settlement.intent.create.v1"
        assert contract["routeBindings"] == ["https://gateway.test/harbor/intents"]
    finally:
        await client.aclose()
