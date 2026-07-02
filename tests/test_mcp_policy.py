from __future__ import annotations

import pytest

from paybond_kit.mcp_policy import (
    McpToolPolicyConfig,
    merge_mcp_tool_policy,
    parse_mcp_tool_allowlist,
    parse_mcp_tool_policy,
    tool_allowed_by_policy,
    validate_mcp_tool_schema,
)


class _Annotations:
    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


def test_readonly_policy_allows_read_only_tools_only() -> None:
    config = parse_mcp_tool_policy("readonly")
    assert tool_allowed_by_policy("paybond_get_principal", _Annotations(readOnlyHint=True), config)
    assert not tool_allowed_by_policy(
        "paybond_create_spend_intent",
        _Annotations(readOnlyHint=False, destructiveHint=False),
        config,
    )


def test_spend_write_policy_blocks_live_money_tools() -> None:
    config = parse_mcp_tool_policy("spend-write")
    assert tool_allowed_by_policy(
        "paybond_create_spend_intent",
        _Annotations(readOnlyHint=False, destructiveHint=False),
        config,
    )
    assert not tool_allowed_by_policy(
        "paybond_fund_intent",
        _Annotations(readOnlyHint=False, destructiveHint=True),
        config,
    )


def test_allowlist_requires_tool_names() -> None:
    with pytest.raises(ValueError, match="--tool-allowlist is required"):
        merge_mcp_tool_policy(parse_mcp_tool_policy("allowlist"))


def test_validate_tool_schema_reports_missing_fields() -> None:
    errors = validate_mcp_tool_schema({"name": "paybond_get_principal"})
    assert any("description" in error for error in errors)


def test_parse_allowlist_splits_comma_separated_names() -> None:
    assert parse_mcp_tool_allowlist("paybond_get_principal,paybond_list_intents") == (
        "paybond_get_principal",
        "paybond_list_intents",
    )


def test_unset_policy_defaults_to_spend_write() -> None:
    from paybond_kit.mcp_policy import default_mcp_tool_policy_config, resolve_mcp_tool_policy

    assert resolve_mcp_tool_policy(McpToolPolicyConfig()).policy == "spend-write"
    assert default_mcp_tool_policy_config().policy == "spend-write"
    assert not tool_allowed_by_policy(
        "paybond_fund_intent",
        _Annotations(readOnlyHint=False, destructiveHint=True),
        McpToolPolicyConfig(),
    )
