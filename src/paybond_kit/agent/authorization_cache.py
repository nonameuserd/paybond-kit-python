"""Authorize → wrap_execute cache with TTL and call-shape validation."""

from __future__ import annotations

import time
from typing import Any, TypedDict, TypeVar

AUTHORIZATION_CACHE_TTL_SEC = 120.0


class CachedAuthorizationEntry(TypedDict):
    auth: Any
    operation: str
    requested_spend_cents: int
    tool_name: str
    cached_at: float
    policy_digest: str | None


class AuthorizationCacheExpectation(TypedDict):
    operation: str
    requested_spend_cents: int
    tool_name: str


TAuth = TypeVar("TAuth")


def evict_expired_authorization_cache(
    cache: dict[str, CachedAuthorizationEntry],
    *,
    ttl_sec: float = AUTHORIZATION_CACHE_TTL_SEC,
    now: float | None = None,
) -> None:
    """Drop expired entries before inserting a new authorization."""
    if now is None:
        now = time.monotonic()
    ttl = ttl_sec
    expired = [key for key, entry in cache.items() if now - entry["cached_at"] > ttl]
    for key in expired:
        del cache[key]


def take_valid_cached_authorization(
    cache: dict[str, CachedAuthorizationEntry],
    cache_key: str,
    expected: AuthorizationCacheExpectation,
    *,
    ttl_sec: float = AUTHORIZATION_CACHE_TTL_SEC,
    now: float | None = None,
) -> CachedAuthorizationEntry | None:
    """Pop a cache entry when fresh and matching the wrap_execute call shape."""
    cached = cache.pop(cache_key, None)
    if cached is None:
        return None

    if now is None:
        now = time.monotonic()
    if now - cached["cached_at"] > ttl_sec:
        return None
    if cached["operation"] != expected["operation"]:
        return None
    if cached["requested_spend_cents"] != expected["requested_spend_cents"]:
        return None
    if cached["tool_name"] != expected["tool_name"]:
        return None

    return cached


__all__ = [
    "AUTHORIZATION_CACHE_TTL_SEC",
    "AuthorizationCacheExpectation",
    "CachedAuthorizationEntry",
    "evict_expired_authorization_cache",
    "take_valid_cached_authorization",
]
