"""Programmatic solution bundle API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from paybond_kit.policy.policy_api import VerticalPolicyOptions, paybond_policy_presets
from paybond_kit.policy.schema import PaybondPolicyDocumentV1
from paybond_kit.solution_catalog import (
    SolutionSmokeDefaults,
    get_solution_smoke_defaults,
    load_solution_manifest,
)


@dataclass(frozen=True, slots=True)
class PaybondSolutionBundle:
    id: str
    title: str
    policy: Any
    smoke_defaults: SolutionSmokeDefaults
    completion_preset: str
    operations: tuple[str, ...]
    vendor_pack: str | None = None


def _list_side_effecting_operations(document: PaybondPolicyDocumentV1) -> tuple[str, ...]:
    operations: list[str] = []
    for tool_name, entry in document.tools.items():
        if not entry.side_effecting:
            continue
        operations.append(entry.operation.strip() if entry.operation else tool_name)
    return tuple(operations)


def _resolve_solution_bundle(
    solution_id: str,
    options: VerticalPolicyOptions | None = None,
) -> PaybondSolutionBundle:
    manifest = load_solution_manifest(solution_id)
    loader = getattr(paybond_policy_presets, solution_id)
    policy = loader(options)
    document = policy.document
    return PaybondSolutionBundle(
        id=solution_id,
        title=manifest["title"],
        policy=policy,
        smoke_defaults=get_solution_smoke_defaults(solution_id),
        completion_preset=manifest["completion_preset"],
        operations=_list_side_effecting_operations(document),
        vendor_pack=manifest.get("vendor_pack"),
    )


class PaybondSolutionPresetsNamespace:
    @staticmethod
    def travel(options: VerticalPolicyOptions | None = None) -> PaybondSolutionBundle:
        return _resolve_solution_bundle("travel", options)

    @staticmethod
    def shopping(options: VerticalPolicyOptions | None = None) -> PaybondSolutionBundle:
        return _resolve_solution_bundle("shopping", options)

    @staticmethod
    def saas(options: VerticalPolicyOptions | None = None) -> PaybondSolutionBundle:
        return _resolve_solution_bundle("saas", options)

    @staticmethod
    def aws(options: VerticalPolicyOptions | None = None) -> PaybondSolutionBundle:
        return _resolve_solution_bundle("aws", options)

    load_manifest = staticmethod(load_solution_manifest)
    smoke_defaults = staticmethod(get_solution_smoke_defaults)


paybond_solution_presets = PaybondSolutionPresetsNamespace()
