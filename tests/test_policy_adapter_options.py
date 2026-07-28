"""Tests for policy adapter option mapping."""

from __future__ import annotations

import pytest

from paybond_kit.policy.adapter_options import policy_to_adapter_options
from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.merge import merge_paybond_policies
from paybond_kit.policy.schema import (
    PaybondPolicyValidationError,
    parse_paybond_policy_document,
    parse_paybond_policy_document_v1,
    parse_paybond_policy_document_v2,
)

TRAVEL_POLICY = {
    "version": 1,
    "name": "travel-agent-v1",
    "default_deny": True,
    "tools": {
        "travel.book_hotel": {
            "side_effecting": True,
            "max_spend_cents": 20000,
            "evidence_preset": "cost_and_completion",
        },
    },
}


def test_policy_to_adapter_options_when_flag_true() -> None:
    doc = parse_paybond_policy_document_v1(
        {
            **TRAVEL_POLICY,
            "adapter": {"deny_provider_executed_tools": True},
        }
    )
    assert policy_to_adapter_options(doc).deny_provider_executed_tools is True
    assert policy_to_adapter_options(doc).to_vercel_options() == {
        "denyProviderExecutedTools": True
    }


def test_policy_to_adapter_options_when_flag_omitted_and_default_deny_false() -> None:
    doc = parse_paybond_policy_document_v1({**TRAVEL_POLICY, "default_deny": False})
    assert policy_to_adapter_options(doc).deny_provider_executed_tools is None


def test_policy_to_adapter_options_inherits_default_deny() -> None:
    doc = parse_paybond_policy_document_v1(TRAVEL_POLICY)
    assert policy_to_adapter_options(doc).deny_provider_executed_tools is True


def test_policy_to_adapter_options_allows_explicit_opt_out() -> None:
    doc = parse_paybond_policy_document_v1(
        {
            **TRAVEL_POLICY,
            "adapter": {"deny_provider_executed_tools": False},
        }
    )
    assert policy_to_adapter_options(doc).deny_provider_executed_tools is None


def test_paybond_policy_adapter_accessors() -> None:
    policy = PaybondPolicy.from_document(
        parse_paybond_policy_document_v1(
            {
                **TRAVEL_POLICY,
                "adapter": {"deny_provider_executed_tools": True},
            }
        )
    )
    assert policy.deny_provider_executed_tools is True
    assert policy.to_adapter_options().deny_provider_executed_tools is True


def test_paybond_policy_adapter_inherits_default_deny() -> None:
    policy = PaybondPolicy.from_document(parse_paybond_policy_document_v1(TRAVEL_POLICY))
    assert policy.deny_provider_executed_tools is True
    assert policy.to_adapter_options().deny_provider_executed_tools is True


def test_merge_org_adapter_deny_into_effective_policy() -> None:
    base = parse_paybond_policy_document(
        {
            "version": 2,
            "name": "org-base",
            "default_deny": True,
            "tools": TRAVEL_POLICY["tools"],
            "adapter": {"deny_provider_executed_tools": True},
        }
    )
    overlay = parse_paybond_policy_document_v2(
        {
            "version": 2,
            "name": "tenant-east",
            "default_deny": True,
            "extends": {"org_policy_id": "org-base", "org_id": "org_acme_corp"},
            "tools": {},
        }
    )
    merged = merge_paybond_policies(base, overlay)
    assert merged.effective.adapter is not None
    assert merged.effective.adapter.deny_provider_executed_tools is True


def test_merge_rejects_tenant_relaxing_org_adapter_deny() -> None:
    base = parse_paybond_policy_document(
        {
            "version": 2,
            "name": "org-base",
            "default_deny": True,
            "tools": TRAVEL_POLICY["tools"],
            "adapter": {"deny_provider_executed_tools": True},
        }
    )
    overlay = parse_paybond_policy_document_v2(
        {
            "version": 2,
            "name": "tenant-east",
            "default_deny": True,
            "extends": {"org_policy_id": "org-base", "org_id": "org_acme_corp"},
            "overrides": {"adapter": {"deny_provider_executed_tools": False}},
            "tools": {},
        }
    )
    with pytest.raises(PaybondPolicyValidationError):
        merge_paybond_policies(base, overlay)
