"""Tests for authorize → wrap_execute authorization cache helpers."""

from __future__ import annotations

from typing import Any

from paybond_kit.agent.authorization_cache import (
    AUTHORIZATION_CACHE_TTL_SEC,
    CachedAuthorizationEntry,
    evict_expired_authorization_cache,
    take_valid_cached_authorization,
)


def _entry(
    *,
    auth: Any = None,
    operation: str = "travel.book_hotel",
    requested_spend_cents: int = 100,
    tool_name: str = "travel.book_hotel",
    cached_at: float = 100.0,
    policy_digest: str | None = None,
    authorized_at_ms: int = 100_000,
) -> CachedAuthorizationEntry:
    return {
        "auth": auth if auth is not None else {"audit_id": "audit-1"},
        "operation": operation,
        "requested_spend_cents": requested_spend_cents,
        "tool_name": tool_name,
        "cached_at": cached_at,
        "policy_digest": policy_digest,
        "authorized_at_ms": authorized_at_ms,
    }


def test_evict_expired_authorization_cache() -> None:
    now = 200.0
    cache = {
        "fresh": _entry(cached_at=now - 1.0),
        "stale": _entry(cached_at=now - AUTHORIZATION_CACHE_TTL_SEC - 1.0),
    }
    evict_expired_authorization_cache(
        cache,
        ttl_sec=AUTHORIZATION_CACHE_TTL_SEC,
        now=now,
    )
    assert list(cache) == ["fresh"]


def test_take_valid_cached_authorization_accepts_matching_entry() -> None:
    cache = {"call-1:travel.book_hotel": _entry()}
    cached = take_valid_cached_authorization(
        cache,
        "call-1:travel.book_hotel",
        {
            "operation": "travel.book_hotel",
            "requested_spend_cents": 100,
            "tool_name": "travel.book_hotel",
        },
        ttl_sec=AUTHORIZATION_CACHE_TTL_SEC,
        now=101.0,
    )
    assert cached is not None
    assert cached["auth"]["audit_id"] == "audit-1"
    assert cache == {}


def test_take_valid_cached_authorization_rejects_stale_and_mismatched_entries() -> None:
    stale = {"k": _entry(cached_at=0.0)}
    assert (
        take_valid_cached_authorization(
            stale,
            "k",
            {
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
                "tool_name": "travel.book_hotel",
            },
            ttl_sec=AUTHORIZATION_CACHE_TTL_SEC,
            now=AUTHORIZATION_CACHE_TTL_SEC + 1,
        )
        is None
    )

    operation_mismatch = {"k": _entry(operation="travel.book_flight")}
    assert (
        take_valid_cached_authorization(
            operation_mismatch,
            "k",
            {
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
                "tool_name": "travel.book_hotel",
            },
        )
        is None
    )

    spend_mismatch = {"k": _entry(requested_spend_cents=9_999)}
    assert (
        take_valid_cached_authorization(
            spend_mismatch,
            "k",
            {
                "operation": "travel.book_hotel",
                "requested_spend_cents": 100,
                "tool_name": "travel.book_hotel",
            },
        )
        is None
    )
