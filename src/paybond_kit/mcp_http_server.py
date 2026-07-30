"""Streamable HTTP transport for paybond-kit's MCP server (self-host / local parity).

Unlike the multi-tenant TypeScript Streamable HTTP transport that backs the
hosted `mcp.paybond.ai` endpoint (see `kit/ts/src/mcp-http-server.ts`), this
Python transport is a **single-tenant, long-lived process**: it exposes the
exact same tenant-bound MCP server that `paybond-mcp-server` already runs
over stdio, over the network instead. It exists for self-hosting — one
operator, one `PAYBOND_API_KEY` from the environment (exactly like stdio),
reachable over HTTP for remote or containerized agent hosts that cannot
launch a local stdio subprocess. It is not the runtime behind
`https://mcp.paybond.ai` (that is TypeScript-only; see
docs/kit/mcp-server.md).

Because there is only ever one configured API key for the life of the
process, the `Authorization: Bearer <token>` header on every `/mcp` request
is checked with a constant-time comparison against that same
`PAYBOND_API_KEY` — it is a shared-secret gate protecting network access to
this process, not a per-request tenant selector. This is a deliberate
difference from the TypeScript hosted transport, where the bearer token
*is* forwarded to the gateway per request and determines tenant scope
because that process serves many tenants. Here, tenant identity always
comes from calling the gateway with the one configured `PAYBOND_API_KEY`,
exactly as stdio already does; client-supplied identifiers are never
accepted as a substitute.

Framing (JSON-RPC over Streamable HTTP, sessions, optional SSE) is provided
entirely by the official `mcp` SDK via `FastMCP.streamable_http_app()` —
this module only layers the Bearer/Origin/rate-limit/health-check contract
that the TypeScript transport also enforces on top of it.

Not a standalone console-script entrypoint: `run_mcp_http_server()` is
invoked from `paybond mcp serve --transport http` (see
`paybond_kit/cli/commands.py`), the same canonical command stdio already
uses, so there is one CLI surface per transport instead of a second binary.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from paybond_kit.mcp_server import PaybondMCPSettings, build_mcp_server

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, MutableMapping

    # Matches the ASGI message typing convention used by httpx/starlette
    # (`MutableMapping[str, Any]`, not `dict[str, Any]`) so that
    # `PaybondMcpHttpApp` type-checks as an `_ASGIApp` for tools such as
    # `httpx.ASGITransport` without a variance mismatch on `receive`/`send`.
    Scope = MutableMapping[str, Any]
    Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
    Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]

HEALTHZ_PATH = "/healthz"
DEFAULT_ADDR = "0.0.0.0:8080"
DEFAULT_MAX_BODY_BYTES = 1_048_576  # 1 MiB: JSON-RPC tool payloads, no file uploads.
DEFAULT_RATE_LIMIT_PER_MINUTE = 120  # per matching bearer token
DEFAULT_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE = 30  # per source IP, slows credential scanning
RATE_LIMIT_WINDOW_SEC = 60.0


@dataclass(frozen=True)
class McpHttpServerOptions:
    """Resolved configuration for `PaybondMcpHttpApp`, independent of the
    tenant-bound `PaybondMCPSettings` (gateway URL, tool policy, etc.)."""

    addr: str = DEFAULT_ADDR
    allowed_origins: tuple[str, ...] = ()
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    rate_limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE
    unauthenticated_rate_limit_per_minute: int = DEFAULT_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE


def _parse_positive_int(raw: str, fallback: int, name: str) -> int:
    trimmed = raw.strip()
    if not trimmed:
        return fallback
    try:
        value = int(trimmed)
    except ValueError as exc:
        raise ValueError(f"invalid {name}: {raw} (expected a positive integer)") from exc
    if value <= 0:
        raise ValueError(f"invalid {name}: {raw} (expected a positive integer)")
    return value


def _parse_origin_allowlist(raw: str) -> tuple[str, ...]:
    if not raw.strip():
        return ()
    return tuple(entry.strip() for entry in raw.split(",") if entry.strip())


def mcp_http_server_options_from_env(env: Mapping[str, str] | None = None) -> McpHttpServerOptions:
    """Resolve `McpHttpServerOptions` from `PAYBOND_MCP_HTTP_*` environment
    variables, matching the TypeScript transport's env contract exactly."""

    values: Mapping[str, str] = env if env is not None else os.environ
    return McpHttpServerOptions(
        addr=values.get("PAYBOND_MCP_HTTP_ADDR", "").strip() or DEFAULT_ADDR,
        allowed_origins=_parse_origin_allowlist(values.get("PAYBOND_MCP_HTTP_ALLOWED_ORIGINS", "")),
        max_body_bytes=_parse_positive_int(
            values.get("PAYBOND_MCP_HTTP_MAX_BODY_BYTES", ""),
            DEFAULT_MAX_BODY_BYTES,
            "PAYBOND_MCP_HTTP_MAX_BODY_BYTES",
        ),
        rate_limit_per_minute=_parse_positive_int(
            values.get("PAYBOND_MCP_HTTP_RATE_LIMIT_PER_MINUTE", ""),
            DEFAULT_RATE_LIMIT_PER_MINUTE,
            "PAYBOND_MCP_HTTP_RATE_LIMIT_PER_MINUTE",
        ),
        unauthenticated_rate_limit_per_minute=_parse_positive_int(
            values.get("PAYBOND_MCP_HTTP_RATE_LIMIT_UNAUTH_PER_MINUTE", ""),
            DEFAULT_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE,
            "PAYBOND_MCP_HTTP_RATE_LIMIT_UNAUTH_PER_MINUTE",
        ),
    )


def _parse_addr(addr: str) -> tuple[str, int]:
    trimmed = addr.strip()
    if trimmed.startswith("["):
        end = trimmed.find("]")
        if end == -1 or not trimmed[end + 1 :].startswith(":"):
            raise ValueError(f"invalid address (expected [host]:port): {addr}")
        host = trimmed[1:end] or "::"
        port = int(trimmed[end + 2 :])
    else:
        if ":" not in trimmed:
            raise ValueError(f"invalid address (expected host:port): {addr}")
        host, _, port_part = trimmed.rpartition(":")
        host = host or "0.0.0.0"
        port = int(port_part)
    if port <= 0 or port > 65535:
        raise ValueError(f"invalid port in address: {addr}")
    return host, port


class _FixedWindowRateLimiter:
    """Bounded-memory fixed-window rate limiter. Stale buckets are swept lazily."""

    def __init__(self, limit: int, window_sec: float = RATE_LIMIT_WINDOW_SEC) -> None:
        self._limit = limit
        self._window_sec = window_sec
        self._sweep_interval_sec = window_sec * 5
        self._buckets: dict[str, tuple[int, float]] = {}
        self._last_sweep = 0.0

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        self._maybe_sweep(now)
        count, window_start = self._buckets.get(key, (0, now))
        if now - window_start >= self._window_sec:
            self._buckets[key] = (1, now)
            return True
        if count >= self._limit:
            return False
        self._buckets[key] = (count + 1, window_start)
        return True

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep < self._sweep_interval_sec:
            return
        self._last_sweep = now
        stale = [key for key, (_, start) in self._buckets.items() if now - start >= self._window_sec]
        for key in stale:
            del self._buckets[key]


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _extract_bearer_token(header: str | None) -> str | None:
    if not header:
        return None
    stripped = header.strip()
    if not stripped.lower().startswith("bearer "):
        return None
    token = stripped[len("bearer ") :].strip()
    return token or None


def _client_ip(scope: Scope) -> str:
    cf_connecting_ip = _header(scope, b"cf-connecting-ip")
    if cf_connecting_ip:
        return cf_connecting_ip
    fly_client_ip = _header(scope, b"fly-client-ip")
    if fly_client_ip:
        return fly_client_ip
    client = scope.get("client")
    if client:
        return str(client[0])
    return "unknown"


def _origin_allowed(origin: str | None, allowed_origins: tuple[str, ...]) -> bool:
    # Non-browser MCP clients (Claude, Codex CLI, curl, MCP Inspector in HTTP
    # mode) do not send an Origin header at all, so requests without one are
    # the expected common case. When an Origin is present, it must be
    # explicitly allowlisted — this endpoint is Bearer-token authenticated,
    # not cookie-authenticated, so arbitrary browser-hosted JavaScript is not
    # the intended caller.
    if not origin:
        return True
    return origin in allowed_origins


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _log_access(entry: dict[str, Any]) -> None:
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **entry}
    sys.stderr.write(json.dumps(record) + "\n")


async def _send_json(
    send: Send,
    status: int,
    body: dict[str, Any],
    extra_headers: dict[str, str] | None = None,
) -> None:
    payload = json.dumps(body).encode("utf-8")
    headers = [(b"content-type", b"application/json; charset=utf-8")]
    for key, value in (extra_headers or {}).items():
        headers.append((key.encode("latin-1"), value.encode("latin-1")))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


async def _read_capped_body(receive: Receive, max_bytes: int) -> tuple[bool, bytes]:
    """Buffer an ASGI request body, capped at `max_bytes`.

    Mirrors the TypeScript transport's `readBody`: once the cap is exceeded
    we stop buffering (bounding memory use) but keep draining `receive`
    until the message ends, instead of aborting mid-stream. Ending the ASGI
    connection abruptly while the client is still sending would risk a
    connection reset instead of letting the `413` response reach the
    client.
    """

    total = 0
    too_large = False
    chunks: list[bytes] = []
    more_body = True
    while more_body:
        message = await receive()
        if message.get("type") == "http.disconnect":
            break
        if message.get("type") != "http.request":
            continue
        chunk = message.get("body", b"") or b""
        total += len(chunk)
        if total > max_bytes:
            too_large = True
        else:
            chunks.append(chunk)
        more_body = bool(message.get("more_body", False))
    return too_large, b"".join(chunks)


def _replay_receive(body: bytes, original_receive: Receive) -> Receive:
    """Build a `receive` callable that replays an already-buffered body once,
    then falls through to `original_receive` for every later call.

    Used to hand the wrapped MCP app a body we have already read and size
    validated, since ASGI `receive()` cannot be rewound. The response to a
    streamable HTTP POST is a long-lived SSE stream: the MCP SDK's SSE layer
    (`sse_starlette`) spawns a background task that keeps calling `receive()`
    for the lifetime of that stream solely to detect a genuine
    `http.disconnect` from the client and cancel the response early.
    Synthesizing our own `http.disconnect` after the replayed body (instead
    of delegating to the real `receive`) fired that watcher immediately on
    every request, truncating every SSE response before completion. Once the
    buffered body has been replayed, later calls must observe the real
    connection state from the underlying ASGI server.
    """

    sent = False

    async def receive() -> MutableMapping[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await original_receive()

    return receive


class PaybondMcpHttpApp:
    """ASGI application: Bearer + Origin + rate-limit gate in front of the
    official Streamable HTTP MCP app for one tenant-bound API key.

    See the module docstring for why this differs from the TypeScript
    hosted transport's per-request, multi-tenant bearer handling.
    """

    def __init__(
        self,
        *,
        api_key: str,
        mcp_app: Any,
        mcp_path: str,
        options: McpHttpServerOptions,
    ) -> None:
        self.mcp_path = mcp_path
        self._api_key = api_key.strip()
        self._api_key_hash = _hash_token(self._api_key)
        self._mcp_app = mcp_app
        self._allowed_origins = options.allowed_origins
        self._max_body_bytes = options.max_body_bytes
        self._auth_limiter = _FixedWindowRateLimiter(options.rate_limit_per_minute)
        self._unauth_limiter = _FixedWindowRateLimiter(options.unauthenticated_rate_limit_per_minute)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            # lifespan (session-manager task-group startup/shutdown) and any
            # websocket scope: hand straight to the wrapped MCP app,
            # unauthenticated and unmodified.
            await self._mcp_app(scope, receive, send)
            return

        method = scope["method"]
        path = scope["path"]
        ip = _client_ip(scope)

        if path == HEALTHZ_PATH:
            if method != "GET":
                await _send_json(send, 405, {"error": "method_not_allowed"}, {"allow": "GET"})
                return
            await _send_json(send, 200, {"status": "ok", "service": "paybond-mcp-http"})
            return

        if path != self.mcp_path:
            await _send_json(send, 404, {"error": "not_found"})
            return

        origin = _header(scope, b"origin")
        if not _origin_allowed(origin, self._allowed_origins):
            await _send_json(send, 403, {"error": "origin_not_allowed"})
            _log_access({"path": path, "method": method, "status": 403, "ip": ip, "reason": "origin", "origin": origin})
            return

        bearer = _extract_bearer_token(_header(scope, b"authorization"))
        if not bearer or not hmac.compare_digest(bearer, self._api_key):
            if not self._unauth_limiter.allow(ip):
                await _send_json(send, 429, {"error": "rate_limited"}, {"retry-after": "60"})
                _log_access({"path": path, "method": method, "status": 429, "ip": ip, "reason": "unauthenticated_rate_limit"})
                return
            await _send_json(
                send,
                401,
                {
                    "error": "unauthorized",
                    "message": "Authorization: Bearer <the configured PAYBOND_API_KEY> is required",
                },
                {"www-authenticate": 'Bearer realm="paybond-mcp", error="invalid_token"'},
            )
            _log_access({"path": path, "method": method, "status": 401, "ip": ip})
            return

        if not self._auth_limiter.allow(self._api_key_hash):
            await _send_json(send, 429, {"error": "rate_limited"}, {"retry-after": "60"})
            _log_access({"path": path, "method": method, "status": 429, "ip": ip, "reason": "rate_limit"})
            return

        if method == "POST":
            original_receive = receive
            too_large, body = await _read_capped_body(original_receive, self._max_body_bytes)
            if too_large:
                await _send_json(send, 413, {"error": "payload_too_large"})
                _log_access({"path": path, "method": method, "status": 413, "ip": ip, "token_hash": self._api_key_hash})
                return
            receive = _replay_receive(body, original_receive)

        started_at = time.monotonic()
        response_status: dict[str, int] = {}

        async def send_with_logging(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                response_status["status"] = int(message.get("status", 0))
            await send(message)

        await self._mcp_app(scope, receive, send_with_logging)
        _log_access(
            {
                "path": path,
                "method": method,
                "status": response_status.get("status"),
                "ip": ip,
                "token_hash": self._api_key_hash,
                "ms": round((time.monotonic() - started_at) * 1000, 1),
            }
        )


def create_mcp_http_app(
    *,
    settings: PaybondMCPSettings | None = None,
    options: McpHttpServerOptions | None = None,
) -> PaybondMcpHttpApp:
    """Build the Streamable HTTP ASGI app for one tenant-bound API key.

    Exposed separately from `run_mcp_http_server()` so tests and embedders
    (e.g. an operator's own ASGI server) can mount it without going through
    the CLI/env/uvicorn plumbing.
    """

    from mcp.server.transport_security import TransportSecuritySettings

    resolved_settings = settings or PaybondMCPSettings.from_env()
    resolved_options = options or mcp_http_server_options_from_env()

    server = build_mcp_server(resolved_settings)
    # The official SDK auto-enables DNS-rebinding protection scoped to
    # 127.0.0.1/localhost Host headers whenever no `host` is configured on
    # the FastMCP instance (see `build_mcp_server`, which never sets one
    # since it is shared with the stdio transport). This transport is meant
    # to be reachable from a non-localhost Host header when self-hosted
    # behind a reverse proxy or on a LAN, and Origin validation is already
    # enforced above by this module's own allowlist check — matching the
    # TypeScript Streamable HTTP transport's contract. Disable the SDK's
    # localhost-oriented check rather than let it silently reject valid
    # remote traffic.
    server.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

    mcp_path = server.settings.streamable_http_path
    mcp_app = server.streamable_http_app()

    return PaybondMcpHttpApp(
        api_key=resolved_settings.api_key,
        mcp_app=mcp_app,
        mcp_path=mcp_path,
        options=resolved_options,
    )


def run_mcp_http_server(argv: list[str] | None = None) -> int:
    """Run the tenant-bound Paybond MCP server over Streamable HTTP (self-host)."""

    parser = argparse.ArgumentParser(
        description="Run the tenant-bound Paybond MCP server over Streamable HTTP (self-host / local parity)."
    )
    parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit(
            "The Paybond MCP HTTP transport requires the optional 'mcp' dependency "
            '(it bundles uvicorn/starlette). Install it with `pip install "paybond-kit[mcp]"`.'
        ) from exc

    try:
        options = mcp_http_server_options_from_env()
        app = create_mcp_http_app(options=options)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    host, port = _parse_addr(options.addr)
    sys.stderr.write(
        f"Paybond MCP Streamable HTTP server listening on http://{host}:{port}{app.mcp_path} "
        f"(health check: {HEALTHZ_PATH})\n"
    )
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


__all__ = [
    "McpHttpServerOptions",
    "PaybondMcpHttpApp",
    "create_mcp_http_app",
    "mcp_http_server_options_from_env",
    "run_mcp_http_server",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run_mcp_http_server())
