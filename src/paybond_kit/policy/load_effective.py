"""Gateway-backed org-policy effective resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from paybond_kit.policy.merge import PolicyMergeReport


@dataclass(frozen=True, slots=True)
class PolicyEffectiveResolveResult:
    effective_policy: dict[str, Any]
    effective_policy_digest: str
    effective_policy_version: str
    merge_report: PolicyMergeReport
    org_base_version_seq: int
    org_base_content_digest: str
    unchanged: bool = False


class PolicyEffectiveResolveClient(Protocol):
    async def resolve_policy_effective(
        self,
        org_policy_id: str,
        overlay: dict[str, Any],
        *,
        current_digest: str | None = None,
    ) -> PolicyEffectiveResolveResult: ...


def _parse_merge_report(value: Any) -> PolicyMergeReport:
    if not isinstance(value, dict):
        raise ValueError("merge_report must be an object")
    denied = tuple(
        {
            "path": str(item.get("path", "")),
            "code": str(item.get("code", "")),
            "message": str(item.get("message", "")),
        }
        for item in value.get("denied_widenings", [])
        if isinstance(item, dict)
    )
    return PolicyMergeReport(
        org_policy_id=value.get("org_policy_id"),
        org_id=value.get("org_id"),
        base_policy_name=str(value.get("base_policy_name", "")),
        overlay_policy_name=value.get("overlay_policy_name"),
        overrides_applied=tuple(str(item) for item in value.get("overrides_applied", [])),
        denied_widenings=denied,
    )


def parse_policy_effective_resolve_response(body: Any) -> PolicyEffectiveResolveResult:
    """Parse a Gateway org-policy effective resolution JSON body."""
    if not isinstance(body, dict):
        raise ValueError("policy effective response must be a JSON object")
    digest = str(body.get("effective_policy_digest", ""))
    if not digest:
        raise ValueError("effective_policy_digest is required")
    version = str(body.get("effective_policy_version", ""))
    if not version:
        raise ValueError("effective_policy_version is required")
    if body.get("unchanged") is True:
        return PolicyEffectiveResolveResult(
            effective_policy={},
            effective_policy_digest=digest,
            effective_policy_version=version,
            merge_report=_parse_merge_report(body.get("merge_report")),
            org_base_version_seq=int(body.get("org_base_version_seq", 0)),
            org_base_content_digest=str(body.get("org_base_content_digest", "")),
            unchanged=True,
        )
    effective = body.get("effective_policy")
    if not isinstance(effective, dict):
        raise ValueError("effective_policy must be an object")
    return PolicyEffectiveResolveResult(
        effective_policy=effective,
        effective_policy_digest=digest,
        effective_policy_version=version,
        merge_report=_parse_merge_report(body.get("merge_report")),
        org_base_version_seq=int(body.get("org_base_version_seq", 0)),
        org_base_content_digest=str(body.get("org_base_content_digest", "")),
    )


async def resolve_policy_effective_remote(
    overlay_payload: dict[str, Any],
    client: PolicyEffectiveResolveClient,
) -> PolicyEffectiveResolveResult:
    """Resolve merged effective policy via Gateway org-policy inheritance endpoint."""
    extends = overlay_payload.get("extends")
    if not isinstance(extends, dict):
        raise ValueError("overlay must declare extends")
    org_policy_id = extends.get("org_policy_id")
    if not isinstance(org_policy_id, str) or not org_policy_id:
        raise ValueError("overlay must declare extends.org_policy_id")
    return await client.resolve_policy_effective(org_policy_id, overlay_payload)
