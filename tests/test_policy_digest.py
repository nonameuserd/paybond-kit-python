from __future__ import annotations

from paybond_kit.policy.digest import canonical_policy_document_digest, policy_version_label
from paybond_kit.policy.schema import parse_paybond_policy_document_v1

TRAVEL_POLICY = {
    "version": 1,
    "name": "travel-agent-v1",
    "default_deny": True,
    "tools": {
        "travel.book_hotel": {
            "side_effecting": True,
            "max_spend_cents": 20000,
            "evidence_preset": "cost_and_completion",
        }
    },
}


def test_canonical_policy_document_digest_is_stable() -> None:
    document = parse_paybond_policy_document_v1(TRAVEL_POLICY)
    first = canonical_policy_document_digest(document)
    second = canonical_policy_document_digest(document)
    assert first == second
    assert first.startswith("sha256:")
    assert len(first) == len("sha256:") + 64


def test_policy_version_label_formats_digest_short() -> None:
    digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    assert policy_version_label("travel-agent-v1", digest) == "travel-agent-v1@abcdef01"
