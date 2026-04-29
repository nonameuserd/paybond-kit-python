from __future__ import annotations

import uuid

import httpx
import pytest
import respx

from paybond_kit.harbor import HarborClient, HarborHttpError, TenantBindingError


@pytest.mark.asyncio
@respx.mock
async def test_verify_success_checks_tenant_echo() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "tenant-a",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        out = await client.verify_capability(
            intent_id=intent_id,
            token="Cg==",
            operation="demo.tool",
            requested_spend_cents=0,
        )
        assert out.allow
        assert out.tenant == "tenant-a"
        assert out.intent_id == intent_id
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_verify_rejects_tenant_mismatch() -> None:
    intent_id = uuid.uuid4()
    audit_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": True,
                "audit_id": str(audit_id),
                "tenant": "other",
                "intent_id": str(intent_id),
                "code": None,
                "message": None,
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        with pytest.raises(TenantBindingError):
            await client.verify_capability(
                intent_id=intent_id,
                token="Cg==",
                operation="demo.tool",
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_verify_http_error_surfaces_status() -> None:
    intent_id = uuid.uuid4()
    respx.post("https://harbor.test/verify").mock(return_value=httpx.Response(500, text="boom"))
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        with pytest.raises(HarborHttpError):
            await client.verify_capability(
                intent_id=intent_id,
                token="Cg==",
                operation="demo.tool",
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_ledger_tip_rejects_tenant_mismatch() -> None:
    respx.get("https://harbor.test/ledger/v1/tip").mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "other",
                "seq": 1,
                "entry_commitment_hex": "ab" * 32,
                "empty": False,
            },
        )
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        with pytest.raises(TenantBindingError):
            await client.get_ledger_tip()
    finally:
        await client.aclose()


def _ledger_events_ok() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "schema_version": 1,
            "tenant_id": "tenant-a",
            "entries": [],
            "next_after_seq": None,
        },
    )


@pytest.mark.asyncio
@respx.mock
async def test_ledger_events_query_and_limit_clamp() -> None:
    respx.get("https://harbor.test/ledger/v1/events?after_seq=5&limit=10").mock(
        return_value=_ledger_events_ok()
    )
    respx.get("https://harbor.test/ledger/v1/events?after_seq=0&limit=256").mock(
        return_value=_ledger_events_ok()
    )
    client = HarborClient("https://harbor.test", "tenant-a")
    try:
        await client.get_ledger_events(after_seq=5, limit=10)
        await client.get_ledger_events(after_seq=0, limit=999)
    finally:
        await client.aclose()
