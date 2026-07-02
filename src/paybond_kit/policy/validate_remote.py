"""Server-authoritative policy validation via Gateway POST /v1/policy/validate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

from paybond_kit.policy.load_effective import _parse_merge_report
from paybond_kit.policy.merge import PolicyMergeReport
from paybond_kit.policy.schema import PaybondPolicyDocumentV1, policy_document_to_dict


@dataclass(frozen=True, slots=True)
class PolicyRemoteValidateIssue:
    path: str
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class PolicyRemoteValidateCheck:
    name: str
    passed: bool


@dataclass(frozen=True, slots=True)
class PolicyRemoteValidateResult:
    valid: bool
    local_valid: bool
    remote_valid: bool
    policy_name: str | None
    tenant_id: str
    errors: tuple[PolicyRemoteValidateIssue, ...]
    warnings: tuple[PolicyRemoteValidateIssue, ...]
    checks: tuple[PolicyRemoteValidateCheck, ...]
    effective_policy_digest: str | None = None
    merge_report: PolicyMergeReport | None = None


@dataclass(frozen=True, slots=True)
class PolicyRemoteValidateOptions:
    strict: bool | None = None
    resolve_inheritance: bool | None = None


class PolicyRemoteValidateClient(Protocol):
    async def validate_policy(
        self,
        document: dict[str, Any],
        *,
        options: PolicyRemoteValidateOptions | None = None,
    ) -> PolicyRemoteValidateResult:
        """POST the policy document to Gateway /v1/policy/validate."""


def policy_validate_query_string(*, options: PolicyRemoteValidateOptions | None = None) -> str:
    """Build query parameters for Gateway POST /v1/policy/validate."""
    params: dict[str, str] = {}
    if options is not None and options.strict:
        params["strict"] = "1"
    if options is not None and options.resolve_inheritance:
        params["resolve_inheritance"] = "1"
    if not params:
        return ""
    return f"?{urlencode(params)}"


def _parse_issue(value: object) -> PolicyRemoteValidateIssue | None:
    if not isinstance(value, dict):
        return None
    path = str(value.get("path", "")).strip()
    code = str(value.get("code", "")).strip()
    message = str(value.get("message", "")).strip()
    if not path or not code or not message:
        return None
    return PolicyRemoteValidateIssue(path=path, code=code, message=message)


def _parse_check(value: object) -> PolicyRemoteValidateCheck | None:
    if not isinstance(value, dict):
        return None
    name = str(value.get("name", "")).strip()
    passed = value.get("passed")
    if not name or not isinstance(passed, bool):
        return None
    return PolicyRemoteValidateCheck(name=name, passed=passed)


def parse_policy_remote_validate_response(body: object) -> PolicyRemoteValidateResult:
    """Parse a Gateway POST /v1/policy/validate JSON body."""
    if not isinstance(body, dict):
        raise ValueError("policy validate response must be a JSON object")

    errors = tuple(
        issue
        for row in body.get("errors", [])
        if (issue := _parse_issue(row)) is not None
    )
    warnings = tuple(
        issue
        for row in body.get("warnings", [])
        if (issue := _parse_issue(row)) is not None
    )
    checks = tuple(
        check
        for row in body.get("checks", [])
        if (check := _parse_check(row)) is not None
    )

    policy_name_raw = body.get("policy_name")
    policy_name = None if policy_name_raw is None else str(policy_name_raw)

    digest_raw = body.get("effective_policy_digest")
    effective_policy_digest = None
    if digest_raw is not None:
        digest = str(digest_raw).strip()
        if digest:
            effective_policy_digest = digest

    merge_report = None
    if body.get("merge_report") is not None:
        merge_report = _parse_merge_report(body.get("merge_report"))

    return PolicyRemoteValidateResult(
        valid=bool(body.get("valid")),
        local_valid=bool(body.get("local_valid")),
        remote_valid=bool(body.get("remote_valid")),
        policy_name=policy_name,
        tenant_id=str(body.get("tenant_id", "")),
        errors=errors,
        warnings=warnings,
        checks=checks,
        effective_policy_digest=effective_policy_digest,
        merge_report=merge_report,
    )


def policy_remote_validate_result_to_dict(result: PolicyRemoteValidateResult) -> dict[str, object]:
    """Serialize a remote validation report for CLI or logging output."""
    payload: dict[str, object] = {
        "valid": result.valid,
        "local_valid": result.local_valid,
        "remote_valid": result.remote_valid,
        "policy_name": result.policy_name,
        "tenant_id": result.tenant_id,
        "errors": [
            {"path": issue.path, "code": issue.code, "message": issue.message}
            for issue in result.errors
        ],
        "warnings": [
            {"path": issue.path, "code": issue.code, "message": issue.message}
            for issue in result.warnings
        ],
        "checks": [{"name": check.name, "passed": check.passed} for check in result.checks],
    }
    if result.effective_policy_digest:
        payload["effective_policy_digest"] = result.effective_policy_digest
    if result.merge_report is not None:
        payload["merge_report"] = {
            "org_policy_id": result.merge_report.org_policy_id,
            "org_id": result.merge_report.org_id,
            "base_policy_name": result.merge_report.base_policy_name,
            "overlay_policy_name": result.merge_report.overlay_policy_name,
            "overrides_applied": list(result.merge_report.overrides_applied),
            "denied_widenings": list(result.merge_report.denied_widenings),
        }
    return payload


async def validate_policy_payload_remote(
    document: dict[str, Any],
    client: PolicyRemoteValidateClient,
    *,
    options: PolicyRemoteValidateOptions | None = None,
) -> PolicyRemoteValidateResult:
    """Validate a raw policy payload against the tenant-scoped Gateway registry endpoint."""
    return await client.validate_policy(document, options=options)


async def validate_policy_remote(
    document: PaybondPolicyDocumentV1,
    client: PolicyRemoteValidateClient,
    *,
    options: PolicyRemoteValidateOptions | None = None,
) -> PolicyRemoteValidateResult:
    """Validate a policy document against the tenant-scoped Gateway registry endpoint."""
    return await validate_policy_payload_remote(
        policy_document_to_dict(document),
        client,
        options=options,
    )
