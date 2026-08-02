"""Restricted-key scope filtering for the Python MCP server."""

from __future__ import annotations

import pytest

from paybond_kit.mcp_server import McpScopeContext, PaybondMCPRuntime, PaybondMCPSettings, mcp_standard_key_warning
from paybond_kit.mcp_scope_catalog import McpScope


def _settings(*, api_key: str = "paybond_rk_sandbox_" + ("a" * 32) + "_" + ("b" * 64)) -> PaybondMCPSettings:
    return PaybondMCPSettings(
        gateway_base_url="https://gateway.test",
        api_key=api_key,
    )


@pytest.mark.asyncio
async def test_scope_denial_for_restricted_key() -> None:
    runtime = PaybondMCPRuntime(_settings())
    runtime._scope_context = McpScopeContext(  # noqa: SLF001 - unit test inject
        restricted=True,
        scopes=(McpScope("mcp.discovery", "read"),),
        unresolved_reason=None,
    )
    assert await runtime.scope_denial_for("paybond_get_principal") is None
    denial = await runtime.scope_denial_for("paybond_authorize_agent_spend")
    assert denial is not None
    assert "mcp.spend:write" in denial
    await runtime.aclose()


@pytest.mark.asyncio
async def test_standard_key_skips_scope_denial() -> None:
    runtime = PaybondMCPRuntime(
        _settings(api_key="paybond_sk_sandbox_" + ("a" * 32) + "_" + ("b" * 64))
    )
    runtime._scope_context = McpScopeContext(  # noqa: SLF001
        restricted=False,
        scopes=(),
        unresolved_reason=None,
    )
    assert await runtime.scope_denial_for("paybond_authorize_agent_spend") is None
    await runtime.aclose()


def test_standard_key_warning_only_for_remote_hosts() -> None:
    key = "paybond_sk_sandbox_" + ("a" * 32) + "_" + ("b" * 64)
    assert mcp_standard_key_warning("https://api.paybond.ai", key) is not None
    assert mcp_standard_key_warning("http://127.0.0.1:8080", key) is None
    assert mcp_standard_key_warning("https://api.paybond.ai", "paybond_rk_sandbox_x") is None
