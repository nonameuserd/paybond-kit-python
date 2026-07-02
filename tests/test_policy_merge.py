from __future__ import annotations

import json
from pathlib import Path

import pytest

from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.merge import merge_paybond_policies
from paybond_kit.policy.schema import (
    PaybondPolicyValidationError,
    parse_paybond_policy_document_v2,
)

EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "policy" / "examples"

ORG_BASE = json.loads((EXAMPLES_DIR / "org-base-acme-agent-spend-v1.json").read_text(encoding="utf-8"))
TENANT_OVERLAY = json.loads(
    (EXAMPLES_DIR / "tenant-overlay-acme-travel-east.json").read_text(encoding="utf-8")
)


def test_merge_org_base_with_tenant_overlay() -> None:
    base = parse_paybond_policy_document_v2(ORG_BASE)
    overlay = parse_paybond_policy_document_v2(TENANT_OVERLAY)
    result = merge_paybond_policies(base, overlay)

    assert result.effective.version == 1
    assert result.effective.name == "acme-travel-tenant-east"
    assert result.effective.tools["travel.book_hotel"].max_spend_cents == 15000
    assert result.effective.tools["acme.internal.approve_po"].side_effecting is True
    assert result.effective.intent is not None
    assert result.effective.intent.budget is not None
    assert result.effective.intent.budget["max_spend_usd"] == 150
    assert result.report.org_policy_id == "acme-agent-spend-v1"
    assert "tools.travel.book_hotel.max_spend_cents" in result.report.overrides_applied


def test_merge_rejects_spend_cap_widenings() -> None:
    base = parse_paybond_policy_document_v2(ORG_BASE)
    overlay = parse_paybond_policy_document_v2(
        {
            **TENANT_OVERLAY,
            "overrides": {
                "tools": {
                    "travel.book_hotel": {"max_spend_cents": 25000},
                }
            },
        }
    )
    with pytest.raises(PaybondPolicyValidationError):
        merge_paybond_policies(base, overlay)


def test_merge_local_from_example_files() -> None:
    result = PaybondPolicy.merge_local(
        base=EXAMPLES_DIR / "org-base-acme-agent-spend-v1.json",
        overlay=EXAMPLES_DIR / "tenant-overlay-acme-travel-east.json",
    )
    assert result.effective.tools["travel.book_hotel"].max_spend_cents == 15000
