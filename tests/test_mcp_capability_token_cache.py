from __future__ import annotations

import time

import pytest

from paybond_kit.mcp_capability_token_cache import (
    MCP_CAPABILITY_TOKEN_STORE_TOOLS,
    McpCapabilityTokenCache,
    McpCapabilityTokenCacheConfig,
    mcp_tool_stores_capability_token,
    parse_mcp_capability_token_cache_config,
)


def test_store_and_resolve_returns_token() -> None:
    cache = McpCapabilityTokenCache(
        McpCapabilityTokenCacheConfig(ttl_sec=60.0, max_entries=4),
    )

    cache.store("intent-1", "cap-token")

    assert cache.resolve("intent-1") == "cap-token"


def test_resolve_returns_none_after_ttl_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 1_000.0
    monkeypatch.setattr(time, "monotonic", lambda: now)

    cache = McpCapabilityTokenCache(
        McpCapabilityTokenCacheConfig(ttl_sec=30.0, max_entries=4),
    )
    cache.store("intent-1", "cap-token")

    now += 31.0
    assert cache.resolve("intent-1") is None


def test_store_evicts_oldest_entry_when_max_entries_exceeded() -> None:
    cache = McpCapabilityTokenCache(
        McpCapabilityTokenCacheConfig(ttl_sec=60.0, max_entries=2),
    )

    cache.store("intent-1", "cap-1")
    cache.store("intent-2", "cap-2")
    cache.store("intent-3", "cap-3")

    assert cache.resolve("intent-1") is None
    assert cache.resolve("intent-2") == "cap-2"
    assert cache.resolve("intent-3") == "cap-3"


def test_parse_config_reads_env_overrides() -> None:
    config = parse_mcp_capability_token_cache_config(
        {
            "PAYBOND_MCP_CAPABILITY_TOKEN_TTL_SEC": "120",
            "PAYBOND_MCP_CAPABILITY_TOKEN_CACHE_MAX": "8",
        }
    )

    assert config.ttl_sec == 120.0
    assert config.max_entries == 8


def test_parse_config_rejects_invalid_ttl() -> None:
    with pytest.raises(ValueError, match="PAYBOND_MCP_CAPABILITY_TOKEN_TTL_SEC"):
        parse_mcp_capability_token_cache_config(
            {"PAYBOND_MCP_CAPABILITY_TOKEN_TTL_SEC": "not-a-number"}
        )


def test_mcp_tool_stores_capability_token_allowlist() -> None:
    assert mcp_tool_stores_capability_token("paybond_create_spend_intent")
    assert mcp_tool_stores_capability_token(" paybond_fund_intent ")
    assert not mcp_tool_stores_capability_token("paybond_authorize_agent_spend")
    assert not mcp_tool_stores_capability_token("paybond_verify_capability")
    assert len(MCP_CAPABILITY_TOKEN_STORE_TOOLS) == 4
