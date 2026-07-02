"""In-memory capability token cache for Paybond MCP runtimes."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Mapping

MCP_CAPABILITY_TOKEN_TTL_ENV = "PAYBOND_MCP_CAPABILITY_TOKEN_TTL_SEC"
MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV = "PAYBOND_MCP_CAPABILITY_TOKEN_CACHE_MAX"
DEFAULT_MCP_CAPABILITY_TOKEN_TTL_SEC = 900.0
DEFAULT_MCP_CAPABILITY_TOKEN_CACHE_MAX = 64
MIN_MCP_CAPABILITY_TOKEN_TTL_SEC = 60.0
MAX_MCP_CAPABILITY_TOKEN_TTL_SEC = 86_400.0
MIN_MCP_CAPABILITY_TOKEN_CACHE_MAX = 1
MAX_MCP_CAPABILITY_TOKEN_CACHE_MAX = 512

# MCP tools that mint or return funded intent capability tokens from Harbor.
MCP_CAPABILITY_TOKEN_STORE_TOOLS: frozenset[str] = frozenset(
    {
        "paybond_bootstrap_sandbox_guardrail",
        "paybond_create_intent",
        "paybond_create_spend_intent",
        "paybond_fund_intent",
    }
)


def mcp_tool_stores_capability_token(tool_name: str) -> bool:
    """Return True when an MCP tool response may populate the runtime token cache."""
    return tool_name.strip() in MCP_CAPABILITY_TOKEN_STORE_TOOLS


@dataclass(frozen=True)
class McpCapabilityTokenCacheConfig:
    """TTL and size limits for MCP capability token caching."""

    ttl_sec: float = DEFAULT_MCP_CAPABILITY_TOKEN_TTL_SEC
    max_entries: int = DEFAULT_MCP_CAPABILITY_TOKEN_CACHE_MAX


@dataclass
class _CacheEntry:
    token: str
    stored_at_monotonic: float


class McpCapabilityTokenCache:
    """Bounded, TTL-backed cache keyed by intent_id."""

    def __init__(self, config: McpCapabilityTokenCacheConfig | None = None) -> None:
        resolved = config or McpCapabilityTokenCacheConfig()
        self._ttl_sec = resolved.ttl_sec
        self._max_entries = resolved.max_entries
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()

    def store(self, intent_id: str, token: str) -> None:
        key = intent_id.strip()
        value = token.strip()
        if not key or not value:
            return
        self._evict_expired()
        self._entries[key] = _CacheEntry(
            token=value,
            stored_at_monotonic=time.monotonic(),
        )
        self._entries.move_to_end(key)
        self._evict_overflow()

    def resolve(self, intent_id: str) -> str | None:
        self._evict_expired()
        key = str(intent_id).strip()
        entry = self._entries.get(key)
        if entry is None:
            return None
        if time.monotonic() - entry.stored_at_monotonic > self._ttl_sec:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return entry.token

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [
            key
            for key, entry in self._entries.items()
            if now - entry.stored_at_monotonic > self._ttl_sec
        ]
        for key in expired:
            del self._entries[key]

    def _evict_overflow(self) -> None:
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)


def parse_mcp_capability_token_cache_config(
    env: Mapping[str, str] | None = None,
) -> McpCapabilityTokenCacheConfig:
    import os

    values = env or os.environ
    ttl_raw = values.get(MCP_CAPABILITY_TOKEN_TTL_ENV, "").strip()
    max_raw = values.get(MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV, "").strip()

    ttl_sec = DEFAULT_MCP_CAPABILITY_TOKEN_TTL_SEC
    if ttl_raw:
        try:
            ttl_sec = float(ttl_raw)
        except ValueError as exc:
            raise ValueError(
                f"invalid {MCP_CAPABILITY_TOKEN_TTL_ENV} (expected a number of seconds)"
            ) from exc
        if not MIN_MCP_CAPABILITY_TOKEN_TTL_SEC <= ttl_sec <= MAX_MCP_CAPABILITY_TOKEN_TTL_SEC:
            raise ValueError(
                f"invalid {MCP_CAPABILITY_TOKEN_TTL_ENV} "
                f"(expected {int(MIN_MCP_CAPABILITY_TOKEN_TTL_SEC)}-"
                f"{int(MAX_MCP_CAPABILITY_TOKEN_TTL_SEC)} seconds)"
            )

    max_entries = DEFAULT_MCP_CAPABILITY_TOKEN_CACHE_MAX
    if max_raw:
        try:
            max_entries = int(max_raw)
        except ValueError as exc:
            raise ValueError(
                f"invalid {MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV} (expected an integer)"
            ) from exc
        if not MIN_MCP_CAPABILITY_TOKEN_CACHE_MAX <= max_entries <= MAX_MCP_CAPABILITY_TOKEN_CACHE_MAX:
            raise ValueError(
                f"invalid {MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV} "
                f"(expected {MIN_MCP_CAPABILITY_TOKEN_CACHE_MAX}-"
                f"{MAX_MCP_CAPABILITY_TOKEN_CACHE_MAX})"
            )

    return McpCapabilityTokenCacheConfig(ttl_sec=ttl_sec, max_entries=max_entries)


__all__ = [
    "DEFAULT_MCP_CAPABILITY_TOKEN_CACHE_MAX",
    "DEFAULT_MCP_CAPABILITY_TOKEN_TTL_SEC",
    "MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV",
    "MCP_CAPABILITY_TOKEN_STORE_TOOLS",
    "MCP_CAPABILITY_TOKEN_TTL_ENV",
    "McpCapabilityTokenCache",
    "McpCapabilityTokenCacheConfig",
    "mcp_tool_stores_capability_token",
    "parse_mcp_capability_token_cache_config",
]
