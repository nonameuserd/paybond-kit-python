"""Tests for MCP policy hot-reload gate."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from paybond_kit.mcp_policy_reload import (
    McpPolicyReloadConfig,
    McpPolicyReloadGate,
    McpPolicySpendGateInput,
    parse_mcp_policy_reload_config,
    parse_mcp_policy_reload_mode,
)
from paybond_kit.policy.digest import policy_document_to_dict
from paybond_kit.policy.schema import parse_paybond_policy_document_v1


def _travel_document(max_spend_cents: int = 20_000):
    return parse_paybond_policy_document_v1(
        {
            "version": 1,
            "name": "travel-agent-v1",
            "default_deny": True,
            "tools": {
                "travel.book_hotel": {
                    "side_effecting": True,
                    "max_spend_cents": max_spend_cents,
                    "evidence_preset": "cost_and_completion",
                },
            },
            "intent": {"allowed_tools": ["travel.book_hotel"]},
        }
    )


def test_parse_mcp_policy_reload_config() -> None:
    assert parse_mcp_policy_reload_mode("watch") == "watch"
    assert parse_mcp_policy_reload_mode(None) == "off"
    config = parse_mcp_policy_reload_config(
        {
            "PAYBOND_POLICY_FILE": "./paybond.policy.yaml",
            "PAYBOND_POLICY_RELOAD": "poll",
        }
    )
    assert config is not None
    assert config.reload_mode == "poll"
    assert config.policy_file.endswith("paybond.policy.yaml")


@pytest.mark.asyncio
async def test_assert_spend_gate_resolves_policy_cap(tmp_path: Path) -> None:
    path = tmp_path / "paybond.policy.json"
    path.write_text(
        json.dumps(policy_document_to_dict(_travel_document(12_500))),
        encoding="utf-8",
    )
    gate = await McpPolicyReloadGate.open(
        McpPolicyReloadConfig(policy_file=str(path), reload_mode="off"),
    )
    gated = gate.assert_spend_gate(
        McpPolicySpendGateInput(
            operation="travel.book_hotel",
            allowed_tools=["travel.book_hotel"],
        ),
    )
    assert gated.requested_spend_cents == 12_500
    assert gated.policy_digest is not None
    assert gated.policy_digest.startswith("sha256:")


@pytest.mark.asyncio
async def test_reload_waits_for_in_flight_tool_calls(tmp_path: Path) -> None:
    path = tmp_path / "paybond.policy.json"
    path.write_text(
        json.dumps(policy_document_to_dict(_travel_document(20_000))),
        encoding="utf-8",
    )
    gate = await McpPolicyReloadGate.open(
        McpPolicyReloadConfig(policy_file=str(path), reload_mode="off"),
    )
    gate.begin_tool_call()
    path.write_text(
        json.dumps(policy_document_to_dict(_travel_document(5_000))),
        encoding="utf-8",
    )
    reload_done = False

    async def reload() -> None:
        nonlocal reload_done
        await gate.reload_policy({"file": str(path)})
        reload_done = True

    task = asyncio.create_task(reload())
    await asyncio.sleep(0.05)
    assert reload_done is False
    gate.end_tool_call()
    await task
    gated = gate.assert_spend_gate(
        McpPolicySpendGateInput(
            operation="travel.book_hotel",
            allowed_tools=["travel.book_hotel"],
        ),
    )
    assert gated.requested_spend_cents == 5_000
