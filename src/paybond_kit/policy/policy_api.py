"""Programmatic policy composition API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from paybond_kit.policy.compose import bundled_default_guardrails, compose_bundled_preset_default, compose_policy_layers
from paybond_kit.policy.domain import domain
from paybond_kit.policy.guardrails import PolicyGuardrailLayer, guardrails, max_spend, max_spend_usd
from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.presets import is_known_policy_preset_id, is_layered_policy_preset_id, resolve_composed_preset_document
from paybond_kit.policy.schema import PaybondPolicyDocumentV1


@dataclass(frozen=True, slots=True)
class VerticalPolicyOptions:
    max_spend: int | None = None
    max_spend_usd: float | None = None
    guardrails: tuple[PolicyGuardrailLayer, ...] = ()


def _vertical_policy(preset_id: str, options: VerticalPolicyOptions | None = None) -> PaybondPolicy:
    if options is None or (
        options.max_spend is None
        and options.max_spend_usd is None
        and not options.guardrails
    ):
        return PaybondPolicy.from_document(compose_bundled_preset_default(preset_id))

    layers = [*bundled_default_guardrails(preset_id)]
    if options.max_spend is not None:
        layers.append(max_spend(options.max_spend))
    if options.max_spend_usd is not None:
        layers.append(max_spend_usd(options.max_spend_usd))
    layers.extend(options.guardrails)
    loader = getattr(domain, preset_id)
    return PaybondPolicy.from_document(compose_policy_layers(loader(), *layers))


def _compose_to_policy(domain_document: PaybondPolicyDocumentV1, *layers: PolicyGuardrailLayer) -> PaybondPolicy:
    return PaybondPolicy.from_document(compose_policy_layers(domain_document, *layers))


class PaybondPolicyPresetsNamespace:
    @staticmethod
    def travel(options: VerticalPolicyOptions | None = None) -> PaybondPolicy:
        return _vertical_policy("travel", options)

    @staticmethod
    def shopping(options: VerticalPolicyOptions | None = None) -> PaybondPolicy:
        return _vertical_policy("shopping", options)

    @staticmethod
    def saas(options: VerticalPolicyOptions | None = None) -> PaybondPolicy:
        return _vertical_policy("saas", options)

    @staticmethod
    def aws(options: VerticalPolicyOptions | None = None) -> PaybondPolicy:
        return _vertical_policy("aws", options)

    @staticmethod
    def read_only() -> PaybondPolicy:
        return PaybondPolicy.from_document(resolve_composed_preset_document("read-only"))

    @staticmethod
    def strict() -> PaybondPolicy:
        return PaybondPolicy.from_document(resolve_composed_preset_document("strict"))

    compose = staticmethod(_compose_to_policy)
    domain = domain
    guardrails = guardrails

    @staticmethod
    def resolve_preset_document(preset_id: str) -> PaybondPolicyDocumentV1:
        if not is_known_policy_preset_id(preset_id):
            raise ValueError(f"unknown policy preset: {preset_id}")
        return resolve_composed_preset_document(preset_id)

    @staticmethod
    def is_layered_preset(preset_id: str) -> bool:
        return is_layered_policy_preset_id(preset_id)


paybond_policy_presets = PaybondPolicyPresetsNamespace()
