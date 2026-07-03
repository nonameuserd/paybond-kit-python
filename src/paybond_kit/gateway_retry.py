"""Shared gateway HTTP retry helpers (429/5xx, Retry-After, Cloudflare edge skip)."""

from __future__ import annotations

import asyncio
import json
import random
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

RETRYABLE_HTTP_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


def is_cloudflare_edge_error_body(body_text: str) -> bool:
    """Return True when the body is a Cloudflare-generated edge error payload."""
    trimmed = body_text.strip()
    if not trimmed:
        return False
    try:
        body = json.loads(trimmed)
    except json.JSONDecodeError:
        return False
    return isinstance(body, dict) and body.get("cloudflare_error") is True


def should_retry_gateway_http_status(status: int, body_text: str) -> bool:
    """Whether an HTTP status/body pair should be retried by SDK gateway clients."""
    if status not in RETRYABLE_HTTP_STATUS_CODES:
        return False
    return not is_cloudflare_edge_error_body(body_text)


def should_retry_gateway_response(response: httpx.Response) -> bool:
    """Inspect an httpx response to decide whether to retry transient gateway errors."""
    if response.status_code not in RETRYABLE_HTTP_STATUS_CODES:
        return False
    return should_retry_gateway_http_status(response.status_code, response.text)


def backoff_seconds(attempt: int) -> float:
    """Exponential backoff with jitter, capped at five seconds."""
    base = 0.2 * (2**attempt)
    jitter = random.uniform(0.0, 0.1)
    return min(base + jitter, 5.0)


def parse_retry_after_seconds(value: str | None) -> float | None:
    """Parse a Retry-After header value in seconds (capped at 30)."""
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        return min(float(stripped), 30.0)
    except ValueError:
        return None


def gateway_retry_delay_seconds(attempt: int, retry_after_header: str | None) -> float:
    """Prefer Retry-After when present; otherwise exponential backoff with jitter."""
    retry_after = parse_retry_after_seconds(retry_after_header)
    if retry_after is not None:
        return retry_after
    return backoff_seconds(attempt)


async def httpx_with_gateway_retries(
    request: Callable[[], Awaitable[httpx.Response]],
    *,
    max_retries: int,
) -> httpx.Response:
    """
    Run an httpx request with shared 429/5xx retry policy.

    Skips retries on Cloudflare edge error bodies. Returns the response on success;
    otherwise re-raises the last transport error.
    """
    last_exc: BaseException | None = None
    for attempt in range(max_retries):
        try:
            response = await request()
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_exc = exc
            if attempt + 1 >= max_retries:
                raise
            await asyncio.sleep(gateway_retry_delay_seconds(attempt, None))
            continue

        if response.status_code in RETRYABLE_HTTP_STATUS_CODES and attempt + 1 < max_retries:
            if not should_retry_gateway_response(response):
                return response
            await asyncio.sleep(
                gateway_retry_delay_seconds(attempt, response.headers.get("retry-after"))
            )
            continue
        return response

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("gateway request exhausted retries without a response")
