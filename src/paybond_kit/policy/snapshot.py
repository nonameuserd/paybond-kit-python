"""Versioned policy snapshots for agent run bind and hot-reload."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from paybond_kit.policy.digest import canonical_policy_document_digest, policy_version_label
from paybond_kit.policy.schema import PaybondPolicyDocumentV1

PaybondPolicySnapshotSource = Literal["file", "remote", "effective"]


@dataclass(frozen=True, slots=True)
class PaybondPolicySnapshot:
    """Versioned policy snapshot loaded at bind time (Tier 7 hot-reload foundation)."""

    digest: str
    version: str
    loaded_at: str
    source: PaybondPolicySnapshotSource
    registry: Any
    document: PaybondPolicyDocumentV1


def create_policy_snapshot(
    *,
    document: PaybondPolicyDocumentV1,
    registry: Any,
    source: PaybondPolicySnapshotSource,
    digest: str | None = None,
    loaded_at: str | None = None,
) -> PaybondPolicySnapshot:
    """Build a policy snapshot for :meth:`PaybondAgentRun.bind`."""
    resolved_digest = (digest or "").strip() or canonical_policy_document_digest(document)
    return PaybondPolicySnapshot(
        digest=resolved_digest,
        version=policy_version_label(document.name, resolved_digest),
        loaded_at=loaded_at or datetime.now(UTC).isoformat(),
        source=source,
        registry=registry,
        document=document,
    )


def create_policy_snapshot_from_effective(
    *,
    document: PaybondPolicyDocumentV1,
    registry: Any,
    effective_policy_digest: str,
    loaded_at: str | None = None,
) -> PaybondPolicySnapshot:
    """Build a snapshot from a Gateway effective-policy resolution."""
    return create_policy_snapshot(
        document=document,
        registry=registry,
        source="effective",
        digest=effective_policy_digest,
        loaded_at=loaded_at,
    )
