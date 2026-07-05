from __future__ import annotations

from pathlib import Path

import pytest

from paybond_kit.policy import PaybondPolicy, PolicyValidator, scaffold_paybond_policy
from paybond_kit.policy.init import (
    ScaffoldPaybondPolicyOptions,
    ScaffoldOrgBasePolicyOptions,
    ScaffoldTenantOverlayPolicyOptions,
    parse_policy_extends_ref,
    scaffold_org_base_policy,
    scaffold_tenant_overlay_policy,
)
from paybond_kit.policy.parse_text import parse_policy_document_text
from paybond_kit.policy.schema import parse_paybond_policy_document
from paybond_kit.policy.validate import PolicyValidatorOptions


TRAVEL_POLICY: dict[str, object] = {
    "version": 1,
    "name": "travel-agent-v1",
    "default_deny": True,
    "tools": {
        "travel.book_hotel": {
            "side_effecting": True,
            "max_spend_cents": 20000,
            "evidence_preset": "cost_and_completion",
        },
        "search.web": {
            "side_effecting": False,
        },
    },
    "intent": {
        "allowed_tools": ["travel.book_hotel"],
    },
}


def test_policy_validator_accepts_aligned_policy() -> None:
    report = PolicyValidator.validate(TRAVEL_POLICY)
    assert report.valid is True
    assert report.policy_name == "travel-agent-v1"
    assert report.tools.side_effecting == 1
    assert report.tools.read_only == 1
    assert report.errors == ()


def test_policy_validator_rejects_unknown_allowed_tool() -> None:
    bad = {
        **TRAVEL_POLICY,
        "intent": {"allowed_tools": ["travel.book_hotel", "payments.charge"]},
    }
    report = PolicyValidator.validate(bad)
    assert report.valid is False
    assert any(issue.code == "policy.allowed_tool_not_registered" for issue in report.errors)


def test_policy_validator_strict_requires_allowed_side_effecting_tools() -> None:
    report = PolicyValidator.validate(
        {
            "version": 1,
            "name": "strict-gap-v1",
            "default_deny": True,
            "tools": {
                "travel.book_hotel": {
                    "side_effecting": True,
                    "evidence_preset": "cost_and_completion",
                },
                "travel.book_flight": {
                    "side_effecting": True,
                    "evidence_preset": "cost_and_completion",
                },
            },
            "intent": {"allowed_tools": ["travel.book_hotel"]},
        },
        PolicyValidatorOptions(strict=True),
    )
    assert report.valid is False
    assert any(issue.code == "policy.side_effecting_not_allowed" for issue in report.errors)


def test_scaffold_paybond_policy_writes_valid_file(tmp_path: Path) -> None:
    out = tmp_path / "paybond.policy.yaml"
    result = scaffold_paybond_policy(
        ScaffoldPaybondPolicyOptions(
            out=out,
            operation="travel.book_hotel",
            evidence_preset="cost_and_completion",
        )
    )
    assert result["name"] == "travel-book-hotel-v1"
    yaml = out.read_text(encoding="utf-8")
    assert "create_with_policy_binding" in yaml
    policy = PaybondPolicy.load(out)
    report = policy.validate()
    assert report.valid is True


def test_scaffold_paybond_policy_refuses_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "paybond.policy.yaml"
    out.write_text("version: 1\n", encoding="utf-8")
    with pytest.raises(Exception, match="already exists"):
        scaffold_paybond_policy(
            ScaffoldPaybondPolicyOptions(
                out=out,
                operation="travel.book_hotel",
                evidence_preset="cost_and_completion",
            )
        )


def test_parse_policy_extends_ref() -> None:
    org_id, policy_id = parse_policy_extends_ref("org_acme_corp/acme-agent-spend-v1")
    assert org_id == "org_acme_corp"
    assert policy_id == "acme-agent-spend-v1"


def test_scaffold_org_base_policy_writes_valid_file(tmp_path: Path) -> None:
    out = tmp_path / "org-base.yaml"
    result = scaffold_org_base_policy(
        ScaffoldOrgBasePolicyOptions(
            out=out,
            policy_id="acme-agent-spend-v1",
            operation="travel.book_hotel",
            evidence_preset="cost_and_completion",
            max_spend_cents=20000,
        )
    )
    assert result["policy_id"] == "acme-agent-spend-v1"
    report = PolicyValidator.validate(out)
    assert report.valid is True


def test_scaffold_tenant_overlay_policy_writes_valid_overlay(tmp_path: Path) -> None:
    out = tmp_path / "paybond.policy.yaml"
    result = scaffold_tenant_overlay_policy(
        ScaffoldTenantOverlayPolicyOptions(
            out=out,
            extends_ref="org_acme_corp/acme-agent-spend-v1",
            operation="acme.internal.approve_po",
            evidence_preset="cost_and_completion",
        )
    )
    assert result["org_id"] == "org_acme_corp"
    assert result["org_policy_id"] == "acme-agent-spend-v1"
    doc = parse_paybond_policy_document(parse_policy_document_text(out.read_text(encoding="utf-8"), str(out)))
    assert doc.version == 2
    assert doc.extends is not None
