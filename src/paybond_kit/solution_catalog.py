"""Load bundled solution manifests (travel, shopping, etc.)."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, NotRequired, Required, TypedDict, cast


class SolutionPolicyDefault(TypedDict):
    domain: str
    guardrails: list[str]


class SolutionSmokeManifest(TypedDict):
    result_body: dict[str, Any]
    evidence_preset: str


class SolutionManifest(TypedDict):
    id: Required[str]
    title: Required[str]
    policy_default: Required[SolutionPolicyDefault]
    primary_operation: Required[str]
    completion_preset: Required[str]
    vendor_pack: NotRequired[str]
    smoke: Required[SolutionSmokeManifest]


class SolutionSmokeDefaults(TypedDict):
    operation: str
    requested_spend_cents: int
    evidence_preset: str
    result_body: dict[str, Any]


KNOWN_SOLUTION_IDS = ("travel", "shopping", "saas", "aws", "stripe-commerce")
SolutionId = str


def _solution_candidate_paths(solution_id: str) -> list[Path]:
    module_dir = Path(__file__).resolve().parent
    file_name = f"{solution_id}.json"
    paths = [
        module_dir / "data" / "solutions" / file_name,
        module_dir.parents[3] / "kit" / "solutions" / file_name,
        module_dir.parents[2] / "solutions" / file_name,
    ]
    env_root = os.environ.get("PAYBOND_SOLUTIONS_DIR", "").strip()
    if env_root:
        paths.insert(0, Path(env_root) / file_name)
    return paths


def _parse_solution_manifest(raw: Any, source_label: str) -> SolutionManifest:
    if not isinstance(raw, dict):
        raise ValueError(f"invalid solution manifest at {source_label}")
    smoke = raw.get("smoke")
    if not isinstance(smoke, dict):
        raise ValueError(f"solution manifest {source_label} missing smoke block")
    result_body = smoke.get("result_body")
    if not isinstance(result_body, dict):
        raise ValueError(f"solution manifest {source_label} missing smoke.result_body object")
    evidence_preset = smoke.get("evidence_preset")
    if not isinstance(evidence_preset, str) or not evidence_preset.strip():
        raise ValueError(f"solution manifest {source_label} missing smoke.evidence_preset")
    policy_default = raw.get("policy_default")
    if not isinstance(policy_default, dict):
        raise ValueError(f"solution manifest {source_label} missing policy_default block")
    domain = policy_default.get("domain")
    guardrails = policy_default.get("guardrails")
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError(f"solution manifest {source_label} missing policy_default.domain")
    if not isinstance(guardrails, list) or any(not isinstance(entry, str) for entry in guardrails):
        raise ValueError(f"solution manifest {source_label} missing policy_default.guardrails")

    solution_id = raw.get("id")
    title = raw.get("title")
    primary_operation = raw.get("primary_operation")
    completion_preset = raw.get("completion_preset")
    if not isinstance(solution_id, str) or not solution_id.strip():
        raise ValueError(f"solution manifest {source_label} missing id")
    if not isinstance(title, str) or not title.strip():
        raise ValueError(f"solution manifest {source_label} missing title")
    if not isinstance(primary_operation, str) or not primary_operation.strip():
        raise ValueError(f"solution manifest {source_label} missing primary_operation")
    if not isinstance(completion_preset, str) or not completion_preset.strip():
        raise ValueError(f"solution manifest {source_label} missing completion_preset")

    manifest: SolutionManifest = {
        "id": solution_id.strip(),
        "title": title.strip(),
        "policy_default": {
            "domain": domain.strip(),
            "guardrails": [entry.strip() for entry in guardrails],
        },
        "primary_operation": primary_operation.strip(),
        "completion_preset": completion_preset.strip(),
        "smoke": {
            "result_body": dict(result_body),
            "evidence_preset": evidence_preset.strip(),
        },
    }
    vendor_pack = raw.get("vendor_pack")
    if vendor_pack is not None:
        if not isinstance(vendor_pack, str) or not vendor_pack.strip():
            raise ValueError(f"solution manifest {source_label} has invalid vendor_pack")
        manifest["vendor_pack"] = vendor_pack.strip()
    return manifest


def is_known_solution_id(value: str) -> bool:
    """True when ``value`` is a bundled solution id."""
    return value.strip() in KNOWN_SOLUTION_IDS


def list_solution_ids() -> tuple[str, ...]:
    """List bundled solution ids shipped with paybond-kit."""
    return KNOWN_SOLUTION_IDS


@lru_cache(maxsize=16)
def load_solution_manifest(solution_id: str) -> SolutionManifest:
    trimmed = solution_id.strip()
    if not is_known_solution_id(trimmed):
        raise ValueError(f"unknown solution: {trimmed}")
    last_error: Exception | None = None
    for candidate in _solution_candidate_paths(trimmed):
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
            manifest = _parse_solution_manifest(raw, str(candidate))
            if manifest["id"] != trimmed:
                raise ValueError(
                    f'manifest id "{manifest["id"]}" does not match file name "{trimmed}"'
                )
            return manifest
        except OSError as exc:
            last_error = exc
        except ValueError as exc:
            last_error = exc
    joined = ", ".join(str(path) for path in _solution_candidate_paths(trimmed))
    raise FileNotFoundError(
        f"solution manifest not found for: {trimmed} ({joined}): {last_error}"
    )


def _resolve_requested_spend_cents(result_body: dict[str, Any]) -> int:
    cost_cents = result_body.get("cost_cents")
    if isinstance(cost_cents, (int, float)) and cost_cents >= 0:
        return int(cost_cents)
    raise ValueError("solution smoke.result_body must include non-negative cost_cents")


def get_solution_smoke_defaults(solution_id: str) -> SolutionSmokeDefaults:
    manifest = load_solution_manifest(solution_id)
    result_body = dict(manifest["smoke"]["result_body"])
    return {
        "operation": manifest["primary_operation"],
        "requested_spend_cents": _resolve_requested_spend_cents(result_body),
        "evidence_preset": manifest["smoke"]["evidence_preset"],
        "result_body": result_body,
    }
