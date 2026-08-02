from __future__ import annotations

import json
from pathlib import Path

from paybond_kit.mcp_scope_catalog import (
    MCP_RESOURCE_SCOPES,
    MCP_SCOPE_CATALOG_VERSION,
    MCP_SCOPE_DEFINITIONS,
    MCP_SCOPE_LEVELS,
    MCP_SCOPE_PRESETS,
    MCP_SCOPE_ROUTES,
    MCP_TOOL_SCOPES,
    McpScope,
    classify_paybond_api_key,
    format_mcp_scope,
    normalize_mcp_scopes,
    parse_mcp_scope_token,
    parse_mcp_scopes,
    preset_scopes,
    scope_satisfies,
    tool_allowed_by_scope,
)

CATALOG_PATH = Path(__file__).resolve().parents[1].parent / "mcp-scopes" / "catalog.json"


def _load_canonical() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def test_catalog_mirrors_version_levels_and_definitions() -> None:
    canonical = _load_canonical()
    assert MCP_SCOPE_CATALOG_VERSION == canonical["version"]
    assert list(MCP_SCOPE_LEVELS) == list(canonical["levels"])
    assert [
        {
            "id": definition.id,
            "title": definition.title,
            "max_level": definition.max_level,
            "description": definition.description,
        }
        for definition in MCP_SCOPE_DEFINITIONS
    ] == canonical["scopes"]


def test_catalog_mirrors_tools_resources_routes_and_presets() -> None:
    canonical = _load_canonical()
    assert {
        name: {"scope": required.scope, "level": required.level}
        for name, required in MCP_TOOL_SCOPES.items()
    } == canonical["tools"]
    assert {
        name: {"scope": required.scope, "level": required.level}
        for name, required in MCP_RESOURCE_SCOPES.items()
    } == canonical["resources"]
    assert [
        {
            "method": route.method,
            "pattern": route.pattern,
            "scope": route.scope,
            "level": route.level,
        }
        for route in MCP_SCOPE_ROUTES
    ] == canonical["routes"]
    assert [
        {
            "id": preset.id,
            "title": preset.title,
            "description": preset.description,
            "scopes": [{"scope": scope.scope, "level": scope.level} for scope in preset.scopes],
        }
        for preset in MCP_SCOPE_PRESETS
    ] == canonical["presets"]


def test_presets_never_include_settlement_write() -> None:
    for preset in MCP_SCOPE_PRESETS:
        assert not any(
            grant.scope == "mcp.settlement" and grant.level == "write" for grant in preset.scopes
        )


def test_key_classification_and_scope_helpers() -> None:
    assert classify_paybond_api_key("paybond_sk_sandbox_x_y") == "standard"
    assert classify_paybond_api_key("paybond_rk_live_x_y") == "restricted"
    assert classify_paybond_api_key("paybond_oat_sandbox_x_y") == "restricted"
    assert classify_paybond_api_key("other") == "unknown"

    assert parse_mcp_scope_token("mcp.spend:write") == McpScope("mcp.spend", "write")
    try:
        parse_mcp_scope_token("mcp.discovery:write")
        raise AssertionError("expected discovery write to be rejected")
    except ValueError as exc:
        assert "at most" in str(exc)

    assert scope_satisfies([McpScope("mcp.spend", "write")], McpScope("mcp.spend", "read"))
    assert tool_allowed_by_scope("paybond_create_intent", [McpScope("mcp.spend", "write")])
    assert not tool_allowed_by_scope("paybond_fund_intent", [McpScope("mcp.spend", "write")])

    assert normalize_mcp_scopes(
        [
            McpScope("mcp.spend", "read"),
            McpScope("mcp.spend", "write"),
            McpScope("mcp.discovery", "read"),
        ]
    ) == [
        McpScope("mcp.discovery", "read"),
        McpScope("mcp.spend", "write"),
    ]
    assert format_mcp_scope(McpScope("mcp.discovery", "read")) == "mcp.discovery:read"
    assert parse_mcp_scopes(["mcp.discovery:read", {"scope": "mcp.spend", "level": "write"}]) == [
        McpScope("mcp.discovery", "read"),
        McpScope("mcp.spend", "write"),
    ]
    assert preset_scopes("mcp-readonly") is not None
    assert len(preset_scopes("mcp-readonly") or []) == 4
    assert preset_scopes("nope") is None
