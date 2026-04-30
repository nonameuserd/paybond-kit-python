from __future__ import annotations

import httpx
import pytest
import respx

from paybond_kit.signal import GatewaySignalClient, ServiceAccountSignalSession


@pytest.mark.asyncio
@respx.mock
async def test_portfolio_summary_rejects_tenant_mismatch() -> None:
    respx.get("https://gateway.test/signal/v1/portfolio/summary").mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "other",
                "score_model_version": "1.0",
                "scoring_model": "paybond.signal.v1",
                "checkpoint_last_ledger_seq": 1,
                "operator_count": 0,
                "average_score": 0,
                "total_terminal_intents": 0,
                "total_receipted_volume_cents": 0,
                "operators_under_review": 0,
            },
        )
    )
    client = GatewaySignalClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token="paybond_sk_" + "a" * 32 + "_" + "b" * 64,
    )
    try:
        with pytest.raises(RuntimeError, match="signal tenant mismatch"):
            await client.get_portfolio_summary()
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_service_account_signal_session_binds_tenant_from_principal() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(
            200,
            json={
                "tenant_id": "realm-z",
            },
        )
    )
    session = await ServiceAccountSignalSession.open(
        gateway_base_url="https://gateway.test",
        api_key="paybond_sk_" + "a" * 32 + "_" + "b" * 64,
    )
    try:
        assert session.signal.tenant_id == "realm-z"
    finally:
        await session.aclose()
