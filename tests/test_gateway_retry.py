"""Tests for paybond_kit.gateway_retry."""

from __future__ import annotations

import json

import httpx
import pytest

from paybond_kit.gateway_retry import (
    gateway_retry_delay_seconds,
    httpx_with_gateway_retries,
    is_cloudflare_edge_error_body,
    parse_retry_after_seconds,
    should_retry_gateway_http_status,
    should_retry_gateway_response,
)


CLOUDFLARE_502 = json.dumps(
    {
        "title": "Error 502: Bad gateway",
        "status": 502,
        "cloudflare_error": True,
        "retry_after": 60,
    }
)


def test_is_cloudflare_edge_error_body() -> None:
    assert is_cloudflare_edge_error_body(CLOUDFLARE_502) is True
    assert is_cloudflare_edge_error_body(json.dumps({"error": {"code": "validation_error"}})) is False


def test_should_retry_gateway_http_status_skips_cloudflare_edge() -> None:
    assert should_retry_gateway_http_status(502, CLOUDFLARE_502) is False
    assert should_retry_gateway_http_status(502, json.dumps({"error": {"message": "busy"}})) is True


def test_should_retry_gateway_response() -> None:
    assert should_retry_gateway_response(
        httpx.Response(502, text=json.dumps({"error": {"message": "busy"}}))
    )
    assert not should_retry_gateway_response(httpx.Response(502, text=CLOUDFLARE_502))


def test_gateway_retry_delay_seconds_prefers_retry_after() -> None:
    assert gateway_retry_delay_seconds(0, "2") == 2.0
    assert parse_retry_after_seconds("120") == 30.0
    assert gateway_retry_delay_seconds(3, None) > 0


@pytest.mark.asyncio
async def test_httpx_with_gateway_retries_eventually_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    async def fake_request() -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(503, text=json.dumps({"error": {"message": "busy"}}))
        return httpx.Response(200, text=json.dumps({"ok": True}))

    monkeypatch.setattr(
        "paybond_kit.gateway_retry.gateway_retry_delay_seconds",
        lambda _attempt, _header: 0,
    )
    response = await httpx_with_gateway_retries(fake_request, max_retries=2)
    assert response.status_code == 200
    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_httpx_with_gateway_retries_retries_cloudflare_edge_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    async def fake_request() -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(502, text=CLOUDFLARE_502)
        return httpx.Response(200, text=json.dumps({"ok": True}))

    monkeypatch.setattr(
        "paybond_kit.gateway_retry.gateway_retry_delay_seconds",
        lambda _attempt, _header: 0,
    )
    monkeypatch.setattr(
        "paybond_kit.gateway_retry.parse_cloudflare_retry_after_seconds",
        lambda _body: 0,
    )
    response = await httpx_with_gateway_retries(fake_request, max_retries=3)
    assert response.status_code == 200
    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_httpx_with_gateway_retries_skips_cloudflare_edge_after_one_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"count": 0}

    async def fake_request() -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(502, text=CLOUDFLARE_502)

    monkeypatch.setattr(
        "paybond_kit.gateway_retry.parse_cloudflare_retry_after_seconds",
        lambda _body: 0,
    )
    response = await httpx_with_gateway_retries(fake_request, max_retries=3)
    assert response.status_code == 502
    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_httpx_with_gateway_retries_raises_last_transport_error() -> None:
    async def fake_request() -> httpx.Response:
        raise httpx.ConnectError("connection reset")

    with pytest.raises(httpx.ConnectError, match="connection reset"):
        await httpx_with_gateway_retries(fake_request, max_retries=2)
