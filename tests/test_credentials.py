from __future__ import annotations

import uuid

import httpx
import pytest
import respx

from paybond_kit.credentials import GatewayAuthError, GatewayHarborTokenProvider
from paybond_kit.credentials import ServiceAccountHarborSession


@pytest.mark.asyncio
@respx.mock
async def test_gateway_token_provider_parses_tenant_and_token() -> None:
    respx.post("https://gw.test/v1/auth/harbor-access").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "jwt-1",
                "token_type": "Bearer",
                "expires_in": 3600,
                "tenant_id": "realm-a",
            },
        )
    )
    prov = GatewayHarborTokenProvider(
        gateway_base_url="https://gw.test",
        api_key="paybond_sk_" + "a" * 32 + "_" + "b" * 64,
    )
    try:
        tid = await prov.ensure_initial()
        assert tid == "realm-a"
        assert await prov.bearer() == "jwt-1"
    finally:
        await prov.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_gateway_token_provider_missing_tenant_raises() -> None:
    respx.post("https://gw.test/v1/auth/harbor-access").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "jwt-1",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )
    )
    prov = GatewayHarborTokenProvider(
        gateway_base_url="https://gw.test",
        api_key="paybond_sk_" + "a" * 32 + "_" + "b" * 64,
    )
    try:
        with pytest.raises(GatewayAuthError):
            await prov.ensure_initial()
    finally:
        await prov.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_service_account_session_rotates_harbor_token() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    route = respx.post("https://gw.test/v1/auth/harbor-access")

    call_count = [0]

    def _harbor_access(_request: httpx.Request) -> httpx.Response:
        call_count[0] += 1
        if call_count[0] == 1:
            return httpx.Response(
                200,
                json={
                    "access_token": "jwt-1",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "tenant_id": "realm-a",
                },
            )
        return httpx.Response(
            200,
            json={
                "access_token": "jwt-2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "tenant_id": "realm-a",
            },
        )

    route.mock(side_effect=_harbor_access)
    verify = respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "realm-a",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
            },
        )
    )
    session = await ServiceAccountHarborSession.open(
        gateway_base_url="https://gw.test",
        api_key="paybond_sk_" + "a" * 32 + "_" + "b" * 64,
        harbor_base_url="https://harbor.test",
        max_retries=1,
    )
    try:
        await session.harbor.verify_capability(
            intent_id=intent_id,
            token="Cg==",
            operation="demo.tool",
        )
        first_auth = verify.calls[0].request.headers.get("authorization")
        await session.rotate_harbor_token()
        await session.harbor.verify_capability(
            intent_id=intent_id,
            token="Cg==",
            operation="demo.tool",
        )
        second_auth = verify.calls[1].request.headers.get("authorization")
        assert first_auth == "Bearer jwt-1"
        assert second_auth == "Bearer jwt-2"
    finally:
        await session.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_service_account_negative_unauthorized_gateway() -> None:
    respx.post("https://gw.test/v1/auth/harbor-access").mock(
        return_value=httpx.Response(401, text="unauthorized")
    )
    with pytest.raises(GatewayAuthError) as ei:
        await ServiceAccountHarborSession.open(
            gateway_base_url="https://gw.test",
            api_key="paybond_sk_" + "a" * 32 + "_" + "b" * 64,
            harbor_base_url="https://harbor.test",
        )
    assert ei.value.status_code == 401
