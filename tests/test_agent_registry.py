from __future__ import annotations

import pytest

from paybond_kit.agent import (
    PaybondToolRegistry,
    PaybondToolRegistryValidationError,
    create_paybond_tool_registry,
)


def test_registry_registers_side_effecting_tools() -> None:
    registry = create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: args["estimated_price_cents"],
                    "evidence_preset": "cost_and_completion",
                }
            },
            "default_deny": True,
        }
    )

    assert registry.is_side_effecting("travel.book_hotel") is True
    assert registry.resolve_operation("travel.book_hotel") == "travel.book_hotel"
    assert (
        registry.resolve_spend_cents("travel.book_hotel", {"estimated_price_cents": 18_700})
        == 18_700
    )

    resolution = registry.resolve_tool(
        "travel.book_hotel",
        allowed_tools=["travel.book_hotel"],
    )
    assert resolution.kind == "side_effecting"
    assert resolution.entry is not None
    assert resolution.entry.evidence_preset == "cost_and_completion"


def test_registry_passes_through_read_only_tools() -> None:
    registry = create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": 100,
                    "evidence_preset": "cost_and_completion",
                }
            },
            "default_deny": True,
        }
    )

    resolution = registry.resolve_tool("search.web", allowed_tools=["travel.book_hotel"])
    assert resolution.kind == "passthrough"
    assert resolution.tool_name == "search.web"
    assert registry.is_side_effecting("search.web") is False


def test_registry_default_deny_rejects_unregistered_allowed_tools() -> None:
    registry = create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": 100,
                    "evidence_preset": "cost_and_completion",
                }
            },
            "default_deny": True,
        }
    )

    denied = registry.resolve_tool(
        "travel.book_flight",
        allowed_tools=["travel.book_hotel", "travel.book_flight"],
    )
    assert denied.kind == "denied"
    assert denied.tool_name == "travel.book_flight"
    assert denied.operation == "travel.book_flight"
    assert denied.reason == "unregistered_side_effecting"


def test_registry_allows_unregistered_tools_when_default_deny_false() -> None:
    registry = create_paybond_tool_registry({"default_deny": False})

    resolution = registry.resolve_tool(
        "travel.book_flight",
        allowed_tools=["travel.book_flight"],
    )
    assert resolution.kind == "passthrough"


def test_registry_operation_override() -> None:
    registry = create_paybond_tool_registry(
        {
            "side_effecting": {
                "bookHotel": {
                    "operation": "travel.book_hotel",
                    "spend_cents": 500,
                    "evidence_preset": "cost_and_completion",
                }
            }
        }
    )

    assert registry.resolve_operation("bookHotel") == "travel.book_hotel"
    assert registry.side_effecting_operations() == ["travel.book_hotel"]


def test_registry_requires_evidence_preset() -> None:
    with pytest.raises(PaybondToolRegistryValidationError, match="evidence_preset"):
        create_paybond_tool_registry(
            {
                "side_effecting": {
                    "travel.book_hotel": {
                        "spend_cents": 100,
                    }
                }
            }
        )


def test_registry_rejects_unknown_evidence_preset() -> None:
    with pytest.raises(PaybondToolRegistryValidationError, match="unknown evidence_preset"):
        create_paybond_tool_registry(
            {
                "side_effecting": {
                    "travel.book_hotel": {
                        "spend_cents": 100,
                        "evidence_preset": "not_a_real_preset",
                    }
                }
            }
        )


def test_registry_rejects_duplicate_operations() -> None:
    with pytest.raises(PaybondToolRegistryValidationError, match="duplicate side-effecting operation"):
        create_paybond_tool_registry(
            {
                "side_effecting": {
                    "bookHotelA": {
                        "operation": "travel.book_hotel",
                        "evidence_preset": "cost_and_completion",
                    },
                    "bookHotelB": {
                        "operation": "travel.book_hotel",
                        "evidence_preset": "cost_and_completion",
                    },
                }
            }
        )


def test_registry_validate_for_bind_with_default_deny() -> None:
    registry = PaybondToolRegistry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "evidence_preset": "cost_and_completion",
                }
            },
            "default_deny": True,
        }
    )

    registry.validate_for_bind(["travel.book_hotel"])
    with pytest.raises(PaybondToolRegistryValidationError, match="defaultDeny"):
        registry.validate_for_bind(["travel.book_hotel", "travel.book_flight"])
