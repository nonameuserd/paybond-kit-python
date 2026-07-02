from typing import Any

import pytest

from paybond_kit.policy import PaybondPolicy
from paybond_kit.policy.validate_remote import (
    PolicyRemoteValidateOptions,
    PolicyRemoteValidateResult,
    parse_policy_remote_validate_response,
    policy_validate_query_string,
    validate_policy_payload_remote,
    validate_policy_remote,
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
        "search.web": {
            "side_effecting": False,
        },
    },
    "intent": {
        "allowed_tools": ["travel.book_hotel"],
        "policy_binding": {
            "template_id": "completion_budget_v1",
            "head_digest": "sha256:" + "0" * 64,
        },
    },
}

REMOTE_REPORT = {
    "valid": False,
    "local_valid": True,
    "remote_valid": False,
    "policy_name": "travel-agent-v1",
    "tenant_id": "tenant-sandbox-1",
    "errors": [
        {
            "path": "intent.policy_binding.head_digest",
            "code": "template_head_mismatch",
            "message": "head digest does not match published tenant head",
        }
    ],
    "warnings": [],
    "checks": [
        {"name": "template_exists", "passed": True},
        {"name": "head_digest_match", "passed": False},
    ],
}


def test_parse_policy_remote_validate_response() -> None:
    report = parse_policy_remote_validate_response(REMOTE_REPORT)
    assert report.valid is False
    assert report.local_valid is True
    assert report.remote_valid is False
    assert report.policy_name == "travel-agent-v1"
    assert report.tenant_id == "tenant-sandbox-1"
    assert len(report.errors) == 1
    assert report.checks[1].name == "head_digest_match"


def test_parse_policy_remote_validate_response_inheritance_metadata() -> None:
    report = parse_policy_remote_validate_response(
        {
            **REMOTE_REPORT,
            "valid": True,
            "remote_valid": True,
            "errors": [],
            "effective_policy_digest": "sha256:" + "b" * 64,
            "merge_report": {
                "org_policy_id": "acme-agent-spend-v1",
                "org_id": "org_acme_corp",
                "base_policy_name": "acme-agent-spend-v1",
                "overlay_policy_name": "acme-travel-tenant-east",
                "overrides_applied": ["tools.travel.book_hotel.max_spend_cents"],
                "denied_widenings": [],
            },
        }
    )
    assert report.effective_policy_digest == "sha256:" + "b" * 64
    assert report.merge_report is not None
    assert report.merge_report.org_policy_id == "acme-agent-spend-v1"


def test_policy_validate_query_string() -> None:
    assert (
        policy_validate_query_string(
            options=PolicyRemoteValidateOptions(strict=True, resolve_inheritance=True)
        )
        == "?strict=1&resolve_inheritance=1"
    )


class _FakeGateway:
    def __init__(self) -> None:
        self.calls: list[tuple[dict[str, Any], PolicyRemoteValidateOptions | None]] = []

    async def validate_policy(
        self,
        document: dict[str, Any],
        *,
        options: PolicyRemoteValidateOptions | None = None,
    ) -> PolicyRemoteValidateResult:
        self.calls.append((document, options))
        return parse_policy_remote_validate_response(REMOTE_REPORT)


@pytest.mark.asyncio
async def test_validate_policy_remote_serializes_document() -> None:
    gateway = _FakeGateway()
    report = await validate_policy_remote(
        PaybondPolicy.load(TRAVEL_POLICY).document,
        gateway,
        options=PolicyRemoteValidateOptions(strict=True),
    )
    assert report.remote_valid is False
    assert len(gateway.calls) == 1
    payload, options = gateway.calls[0]
    assert options is not None and options.strict is True
    assert payload["name"] == "travel-agent-v1"
    assert payload["intent"]["policy_binding"]["template_id"] == "completion_budget_v1"


@pytest.mark.asyncio
async def test_validate_policy_payload_remote_passes_resolve_inheritance() -> None:
    gateway = _FakeGateway()
    overlay = {
        "version": 2,
        "name": "acme-travel-tenant-east",
        "extends": {"org_policy_id": "acme-agent-spend-v1", "org_id": "org_acme_corp"},
        "default_deny": True,
        "tools": {},
    }
    await validate_policy_payload_remote(
        overlay,
        gateway,
        options=PolicyRemoteValidateOptions(strict=True, resolve_inheritance=True),
    )
    _, options = gateway.calls[0]
    assert options is not None
    assert options.strict is True
    assert options.resolve_inheritance is True


@pytest.mark.asyncio
async def test_paybond_policy_validate_remote_delegates() -> None:
    gateway = _FakeGateway()
    policy = PaybondPolicy.load(TRAVEL_POLICY)
    report = await policy.validate_remote(gateway)
    assert report.policy_name == "travel-agent-v1"
    assert len(gateway.calls) == 1
