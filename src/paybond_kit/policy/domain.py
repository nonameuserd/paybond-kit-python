"""Bundled domain policy layers."""

from __future__ import annotations

from paybond_kit.policy.layers_io import load_bundled_domain_document
from paybond_kit.policy.schema import PaybondPolicyDocumentV1, parse_paybond_policy_document_v1


def _load_domain(preset_id: str) -> PaybondPolicyDocumentV1:
    return parse_paybond_policy_document_v1(load_bundled_domain_document(preset_id))


def travel() -> PaybondPolicyDocumentV1:
    return _load_domain("travel")


def shopping() -> PaybondPolicyDocumentV1:
    return _load_domain("shopping")


def saas() -> PaybondPolicyDocumentV1:
    return _load_domain("saas")


def aws() -> PaybondPolicyDocumentV1:
    return _load_domain("aws")


class DomainNamespace:
    travel = staticmethod(travel)
    shopping = staticmethod(shopping)
    saas = staticmethod(saas)
    aws = staticmethod(aws)


domain = DomainNamespace()

__all__ = ["aws", "domain", "saas", "shopping", "travel"]
