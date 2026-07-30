"""Tests for the Streamable HTTP transport (`paybond mcp serve --transport http`).

Two layers are covered, matching the two things this module is responsible
for:

1. `PaybondMcpHttpApp` itself -- the Bearer/Origin/rate-limit/body-cap/health
   gate this module adds in front of the official MCP SDK's Streamable HTTP
   app. These tests stub out the wrapped app (`_StubAsgiApp`) and drive
   `PaybondMcpHttpApp` directly over `httpx.ASGITransport`, which is enough
   for pure request-routing behavior and keeps the tests fast and hermetic.
2. End-to-end wiring via `create_mcp_http_app`, run on a real ASGI server
   (`uvicorn.Server`) so that the official MCP SDK's Streamable HTTP session
   manager actually starts (its task group is only created by a genuine ASGI
   lifespan event -- `httpx.ASGITransport` never sends one, which is exactly
   why layer 1 above cannot exercise a real MCP handshake). This is also the
   regression test for a real bug caught by manual smoke-testing during
   development: `_replay_receive` originally synthesized a fake
   `http.disconnect` after replaying the buffered request body, which made
   `sse_starlette`'s disconnect-watcher truncate every streamed response.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import uvicorn

from paybond_kit.mcp_http_server import (
    DEFAULT_ADDR,
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_RATE_LIMIT_PER_MINUTE,
    DEFAULT_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE,
    McpHttpServerOptions,
    PaybondMcpHttpApp,
    _FixedWindowRateLimiter,
    _parse_addr,
    create_mcp_http_app,
    mcp_http_server_options_from_env,
)
from paybond_kit.mcp_server import PaybondMCPSettings


def _api_key(fill: str = "a") -> str:
    return "paybond_sk_" + fill * 32 + "_" + fill * 64


# --------------------------------------------------------------------------
# Layer 1: PaybondMcpHttpApp routing/security, driven over a stub inner app.
# --------------------------------------------------------------------------


class _StubAsgiApp:
    """Stands in for `FastMCP(...).streamable_http_app()` so these tests
    exercise only the wrapper's own auth/origin/rate-limit/body-cap logic."""

    def __init__(self, status: int = 200, body: bytes = b'{"ok": true}') -> None:
        self.status = status
        self.body = body
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        chunks: list[bytes] = []
        more_body = True
        while more_body:
            message = await receive()
            if message.get("type") == "http.disconnect":
                break
            chunks.append(message.get("body", b""))
            more_body = bool(message.get("more_body", False))
        self.calls.append({"method": scope["method"], "path": scope["path"], "body": b"".join(chunks)})
        await send(
            {
                "type": "http.response.start",
                "status": self.status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": self.body, "more_body": False})


def _wrapped_app(
    *,
    api_key: str = _api_key(),
    options: McpHttpServerOptions | None = None,
    stub: _StubAsgiApp | None = None,
) -> tuple[PaybondMcpHttpApp, _StubAsgiApp]:
    stub_app = stub or _StubAsgiApp()
    app = PaybondMcpHttpApp(
        api_key=api_key,
        mcp_app=stub_app,
        mcp_path="/mcp",
        options=options or McpHttpServerOptions(),
    )
    return app, stub_app


def _client(app: PaybondMcpHttpApp) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


class TestHealthz:
    async def test_returns_200_without_authentication(self) -> None:
        app, _ = _wrapped_app()
        async with _client(app) as client:
            res = await client.get("/healthz")
        assert res.status_code == 200
        assert res.json() == {"status": "ok", "service": "paybond-mcp-http"}

    async def test_rejects_non_get_methods(self) -> None:
        app, _ = _wrapped_app()
        async with _client(app) as client:
            res = await client.post("/healthz")
        assert res.status_code == 405
        assert res.headers["allow"] == "GET"


class TestUnknownRoutes:
    async def test_returns_404_for_unrelated_paths(self) -> None:
        app, _ = _wrapped_app()
        async with _client(app) as client:
            res = await client.get("/other")
        assert res.status_code == 404

    async def test_404_does_not_require_authentication(self) -> None:
        # Route existence must not leak through the auth gate either way.
        app, _ = _wrapped_app()
        async with _client(app) as client:
            res = await client.get("/other")
        assert res.status_code == 404


class TestAuthentication:
    async def test_missing_authorization_returns_401_with_www_authenticate(self) -> None:
        app, stub = _wrapped_app()
        async with _client(app) as client:
            res = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert res.status_code == 401
        assert "Bearer" in res.headers["www-authenticate"]
        assert res.json()["error"] == "unauthorized"
        assert stub.calls == []

    async def test_wrong_bearer_token_returns_401(self) -> None:
        app, stub = _wrapped_app(api_key=_api_key("a"))
        async with _client(app) as client:
            res = await client.post(
                "/mcp",
                headers={"authorization": f"Bearer {_api_key('b')}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
        assert res.status_code == 401
        assert stub.calls == []

    async def test_correct_bearer_token_is_forwarded_to_the_wrapped_app(self) -> None:
        key = _api_key()
        app, stub = _wrapped_app(api_key=key)
        async with _client(app) as client:
            res = await client.post(
                "/mcp",
                headers={"authorization": f"Bearer {key}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
        assert res.status_code == 200
        assert len(stub.calls) == 1


class TestOriginValidation:
    async def test_allows_requests_with_no_origin_header_regardless_of_allowlist(self) -> None:
        key = _api_key()
        app, _ = _wrapped_app(
            api_key=key, options=McpHttpServerOptions(allowed_origins=("https://allowed.example",))
        )
        async with _client(app) as client:
            res = await client.post(
                "/mcp", headers={"authorization": f"Bearer {key}"}, json={"jsonrpc": "2.0", "method": "notify"}
            )
        assert res.status_code == 200

    async def test_rejects_a_present_origin_that_is_not_allowlisted(self) -> None:
        key = _api_key()
        app, stub = _wrapped_app(
            api_key=key, options=McpHttpServerOptions(allowed_origins=("https://allowed.example",))
        )
        async with _client(app) as client:
            res = await client.post(
                "/mcp",
                headers={"authorization": f"Bearer {key}", "origin": "https://evil.example"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
        assert res.status_code == 403
        assert stub.calls == []

    async def test_allows_an_allowlisted_origin(self) -> None:
        key = _api_key()
        app, _ = _wrapped_app(
            api_key=key, options=McpHttpServerOptions(allowed_origins=("https://allowed.example",))
        )
        async with _client(app) as client:
            res = await client.post(
                "/mcp",
                headers={"authorization": f"Bearer {key}", "origin": "https://allowed.example"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
        assert res.status_code == 200

    async def test_origin_check_happens_before_authentication(self) -> None:
        # A disallowed Origin should be rejected even with no/garbage
        # credentials -- Origin is a cheaper, pre-auth check.
        app, stub = _wrapped_app(options=McpHttpServerOptions(allowed_origins=("https://allowed.example",)))
        async with _client(app) as client:
            res = await client.post("/mcp", headers={"origin": "https://evil.example"}, json={})
        assert res.status_code == 403
        assert stub.calls == []


class TestBodyCap:
    async def test_rejects_bodies_larger_than_the_configured_limit(self) -> None:
        key = _api_key()
        app, stub = _wrapped_app(api_key=key, options=McpHttpServerOptions(max_body_bytes=16))
        async with _client(app) as client:
            res = await client.post(
                "/mcp",
                headers={"authorization": f"Bearer {key}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "padding": "x" * 100},
            )
        assert res.status_code == 413
        assert stub.calls == []

    async def test_allows_bodies_within_the_limit(self) -> None:
        key = _api_key()
        app, stub = _wrapped_app(api_key=key, options=McpHttpServerOptions(max_body_bytes=4096))
        async with _client(app) as client:
            res = await client.post(
                "/mcp", headers={"authorization": f"Bearer {key}"}, json={"jsonrpc": "2.0", "id": 1, "method": "x"}
            )
        assert res.status_code == 200
        assert len(stub.calls) == 1


class TestRateLimiting:
    async def test_returns_429_once_the_unauthenticated_rate_limit_is_exceeded(self) -> None:
        app, _ = _wrapped_app(options=McpHttpServerOptions(unauthenticated_rate_limit_per_minute=1))
        async with _client(app) as client:
            first = await client.post("/mcp", json={})
            second = await client.post("/mcp", json={})
        assert first.status_code == 401
        assert second.status_code == 429
        assert second.headers["retry-after"]

    async def test_returns_429_once_the_per_key_rate_limit_is_exceeded(self) -> None:
        key = _api_key()
        app, _ = _wrapped_app(api_key=key, options=McpHttpServerOptions(rate_limit_per_minute=1))
        async with _client(app) as client:
            first = await client.post("/mcp", headers={"authorization": f"Bearer {key}"}, json={})
            second = await client.post("/mcp", headers={"authorization": f"Bearer {key}"}, json={})
        assert first.status_code == 200
        assert second.status_code == 429

    async def test_authenticated_requests_do_not_consume_the_unauthenticated_limiter(self) -> None:
        key = _api_key()
        app, _ = _wrapped_app(
            api_key=key,
            options=McpHttpServerOptions(unauthenticated_rate_limit_per_minute=1, rate_limit_per_minute=100),
        )
        async with _client(app) as client:
            # Exhaust what would be the unauthenticated limit with a bad request.
            await client.post("/mcp", json={})
            # Authenticated traffic must be judged only against the (much
            # higher) authenticated limit, never the unauthenticated one.
            responses = [
                await client.post("/mcp", headers={"authorization": f"Bearer {key}"}, json={}) for _ in range(5)
            ]
        assert all(res.status_code == 200 for res in responses)


class TestFixedWindowRateLimiter:
    def test_allows_up_to_the_limit_then_rejects_within_the_window(self) -> None:
        limiter = _FixedWindowRateLimiter(limit=2, window_sec=60.0)
        assert limiter.allow("k", now=0.0) is True
        assert limiter.allow("k", now=1.0) is True
        assert limiter.allow("k", now=2.0) is False

    def test_resets_after_the_window_elapses(self) -> None:
        limiter = _FixedWindowRateLimiter(limit=1, window_sec=60.0)
        assert limiter.allow("k", now=0.0) is True
        assert limiter.allow("k", now=59.0) is False
        assert limiter.allow("k", now=61.0) is True

    def test_tracks_keys_independently(self) -> None:
        limiter = _FixedWindowRateLimiter(limit=1, window_sec=60.0)
        assert limiter.allow("a", now=0.0) is True
        assert limiter.allow("b", now=0.0) is True
        assert limiter.allow("a", now=0.0) is False


# --------------------------------------------------------------------------
# Layer 2: end-to-end wiring against a real running server, real lifespan.
# --------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@asynccontextmanager
async def _running_app(app: Any) -> AsyncIterator[str]:
    """Serve a real ASGI app (with a real lifespan) on an ephemeral localhost
    port. `httpx.ASGITransport` never drives the ASGI lifespan protocol, but
    the official MCP SDK's Streamable HTTP session manager requires a real
    lifespan startup event to start its task group before it will accept any
    request -- so the end-to-end tests below need an actual running server.
    """

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, lifespan="on", log_level="critical")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


def _sse_headers(session_id: str | None = None) -> dict[str, str]:
    headers = {"accept": "application/json, text/event-stream"}
    if session_id is not None:
        headers["mcp-session-id"] = session_id
    return headers


async def _read_first_data_event(response: httpx.Response) -> dict[str, Any]:
    async for line in response.aiter_lines():
        if line.startswith("data:"):
            return json.loads(line[len("data:") :].strip())
    raise AssertionError("stream ended without a data: event")


class _FakeGatewayApp:
    """Minimal ASGI stand-in for the gateway's principal endpoint.

    A real running server (rather than `respx`) is used for the one
    end-to-end test that needs a mocked gateway response: `respx` mocks the
    process-wide default httpx transport, which would also intercept this
    test's own client traffic to the local MCP server under test (both go
    out over plain `httpx.AsyncClient`).
    """

    def __init__(self, tenant_id: str) -> None:
        self._body = json.dumps({"tenant_id": tenant_id}).encode("utf-8")

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return
        if scope["path"] == "/v1/auth/principal":
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": self._body})
            return
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})


class TestEndToEndStreamableHttp:
    async def test_initialize_and_tools_list_round_trip(self) -> None:
        key = _api_key()
        app = create_mcp_http_app(
            settings=PaybondMCPSettings(gateway_base_url="https://gateway.test", api_key=key),
            options=McpHttpServerOptions(),
        )
        async with _running_app(app) as base_url, httpx.AsyncClient(timeout=5) as client:
            init_headers = {**_sse_headers(), "authorization": f"Bearer {key}"}
            async with client.stream(
                "POST",
                f"{base_url}/mcp",
                headers=init_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "0.0.1"},
                    },
                },
            ) as init_res:
                assert init_res.status_code == 200
                session_id = init_res.headers["mcp-session-id"]
                init_body = await _read_first_data_event(init_res)
            assert init_body["result"]["serverInfo"]["name"] == "Paybond MCP"

            notif_res = await client.post(
                f"{base_url}/mcp",
                headers={**_sse_headers(session_id), "authorization": f"Bearer {key}"},
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            assert notif_res.status_code == 202

            async with client.stream(
                "POST",
                f"{base_url}/mcp",
                headers={**_sse_headers(session_id), "authorization": f"Bearer {key}"},
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            ) as list_res:
                assert list_res.status_code == 200
                list_body = await _read_first_data_event(list_res)
            names = {tool["name"] for tool in list_body["result"]["tools"]}
            assert "paybond_get_principal" in names

    async def test_wrong_session_id_is_rejected(self) -> None:
        key = _api_key()
        app = create_mcp_http_app(
            settings=PaybondMCPSettings(gateway_base_url="https://gateway.test", api_key=key),
        )
        async with _running_app(app) as base_url, httpx.AsyncClient(timeout=5) as client:
            res = await client.post(
                f"{base_url}/mcp",
                headers={**_sse_headers("not-a-real-session"), "authorization": f"Bearer {key}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
        assert res.status_code == 404

    async def test_dns_rebinding_protection_is_disabled_for_non_localhost_host_header(self) -> None:
        # `create_mcp_http_app` deliberately disables the MCP SDK's built-in
        # Host-header check (see its docstring): Origin validation is
        # already enforced by this module's own allowlist, and this
        # transport must be reachable from a non-localhost Host header when
        # self-hosted behind a reverse proxy or on a LAN.
        key = _api_key()
        app = create_mcp_http_app(
            settings=PaybondMCPSettings(gateway_base_url="https://gateway.test", api_key=key),
        )
        async with _running_app(app) as base_url, httpx.AsyncClient(timeout=5) as client:
            res = await client.post(
                f"{base_url}/mcp",
                headers={**_sse_headers(), "authorization": f"Bearer {key}", "host": "mcp.example.com"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
        assert res.status_code == 200

    async def test_get_principal_tool_uses_the_gateway_backed_tenant_not_client_input(self) -> None:
        # Single-tenant self-host model: tenant identity always comes from
        # calling the gateway with the one configured PAYBOND_API_KEY, never
        # from client-supplied arguments (there is no tenant selector to
        # smuggle in the first place -- see the module docstring).
        key = _api_key()
        async with _running_app(_FakeGatewayApp("tenant-from-key")) as gateway_url:
            app = create_mcp_http_app(
                settings=PaybondMCPSettings(gateway_base_url=gateway_url, api_key=key),
            )
            async with _running_app(app) as base_url, httpx.AsyncClient(timeout=5) as client:
                init_headers = {**_sse_headers(), "authorization": f"Bearer {key}"}
                async with client.stream(
                    "POST",
                    f"{base_url}/mcp",
                    headers=init_headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "t", "version": "0"},
                        },
                    },
                ) as init_res:
                    session_id = init_res.headers["mcp-session-id"]
                    await _read_first_data_event(init_res)

                await client.post(
                    f"{base_url}/mcp",
                    headers={**_sse_headers(session_id), "authorization": f"Bearer {key}"},
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                )

                async with client.stream(
                    "POST",
                    f"{base_url}/mcp",
                    headers={**_sse_headers(session_id), "authorization": f"Bearer {key}"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "paybond_get_principal", "arguments": {}},
                    },
                ) as call_res:
                    assert call_res.status_code == 200
                    call_body = await _read_first_data_event(call_res)
        assert call_body["result"]["structuredContent"]["tenant_id"] == "tenant-from-key"


# --------------------------------------------------------------------------
# Configuration parsing.
# --------------------------------------------------------------------------


class TestMcpHttpServerOptionsFromEnv:
    def test_applies_documented_defaults_when_no_env_vars_are_set(self) -> None:
        options = mcp_http_server_options_from_env({})
        assert options.addr == DEFAULT_ADDR
        assert options.allowed_origins == ()
        assert options.max_body_bytes == DEFAULT_MAX_BODY_BYTES
        assert options.rate_limit_per_minute == DEFAULT_RATE_LIMIT_PER_MINUTE
        assert options.unauthenticated_rate_limit_per_minute == DEFAULT_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE

    def test_parses_overrides_from_environment_variables(self) -> None:
        options = mcp_http_server_options_from_env(
            {
                "PAYBOND_MCP_HTTP_ADDR": "0.0.0.0:9000",
                "PAYBOND_MCP_HTTP_ALLOWED_ORIGINS": "https://a.example, https://b.example",
                "PAYBOND_MCP_HTTP_MAX_BODY_BYTES": "2048",
                "PAYBOND_MCP_HTTP_RATE_LIMIT_PER_MINUTE": "60",
                "PAYBOND_MCP_HTTP_RATE_LIMIT_UNAUTH_PER_MINUTE": "5",
            }
        )
        assert options.addr == "0.0.0.0:9000"
        assert options.allowed_origins == ("https://a.example", "https://b.example")
        assert options.max_body_bytes == 2048
        assert options.rate_limit_per_minute == 60
        assert options.unauthenticated_rate_limit_per_minute == 5

    def test_rejects_a_non_positive_integer_override(self) -> None:
        with pytest.raises(ValueError, match="invalid PAYBOND_MCP_HTTP_MAX_BODY_BYTES"):
            mcp_http_server_options_from_env({"PAYBOND_MCP_HTTP_MAX_BODY_BYTES": "0"})

    def test_rejects_a_non_integer_override(self) -> None:
        with pytest.raises(ValueError, match="invalid PAYBOND_MCP_HTTP_RATE_LIMIT_PER_MINUTE"):
            mcp_http_server_options_from_env({"PAYBOND_MCP_HTTP_RATE_LIMIT_PER_MINUTE": "not-a-number"})


class TestParseAddr:
    def test_parses_host_and_port(self) -> None:
        assert _parse_addr("0.0.0.0:8080") == ("0.0.0.0", 8080)
        assert _parse_addr("127.0.0.1:9000") == ("127.0.0.1", 9000)

    def test_parses_bracketed_ipv6_hosts(self) -> None:
        assert _parse_addr("[::1]:9000") == ("::1", 9000)
        assert _parse_addr("[::]:8080") == ("::", 8080)

    def test_rejects_missing_colon(self) -> None:
        with pytest.raises(ValueError, match="invalid address"):
            _parse_addr("0.0.0.0")

    def test_rejects_out_of_range_port(self) -> None:
        with pytest.raises(ValueError, match="invalid port"):
            _parse_addr("0.0.0.0:70000")
