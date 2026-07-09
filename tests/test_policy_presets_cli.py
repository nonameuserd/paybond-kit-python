from __future__ import annotations

import io
from pathlib import Path

from paybond_kit.cli.policy import handle_policy_init, handle_policy_presets_list, handle_policy_presets_show
from paybond_kit.cli.core import CliContext, GlobalOptions
from paybond_kit.policy.catalog import list_policy_presets_catalog
from paybond_kit.policy.guardrail_spec import parse_guardrail_specs
from paybond_kit.policy.init import (
    ScaffoldComposedPolicyOptions,
    ScaffoldPolicyFromPresetOptions,
    scaffold_composed_policy,
    scaffold_policy_from_preset,
)
from paybond_kit.policy.load import PaybondPolicy
from paybond_kit.policy.presets import (
    is_known_policy_preset_id,
    list_policy_preset_ids,
    read_policy_preset_yaml,
    resolve_composed_preset_document,
    resolve_policy_preset_path,
)
from paybond_kit.solution_catalog import (
    get_solution_smoke_defaults,
    is_known_solution_id,
    list_solution_ids,
    load_solution_manifest,
)
from paybond_kit.policy.render_yaml import render_policy_document_yaml


def _ctx(tmp_path: Path) -> CliContext:
    return CliContext(
        globals=GlobalOptions(),
        cwd=tmp_path,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )


def test_parse_guardrail_specs() -> None:
    layers = parse_guardrail_specs("read-only,max-spend:500")
    assert len(layers) == 2
    assert layers[1].budget_max_spend_usd == 500
    assert layers[1].side_effecting_max_spend_cents == 50_000


def test_list_policy_presets_catalog() -> None:
    catalog = list_policy_presets_catalog()
    domains = catalog["domains"]
    solutions = catalog["solutions"]
    assert isinstance(domains, list)
    assert isinstance(solutions, list)
    assert len(domains) == 4
    assert len(solutions) == 5


def test_scaffold_policy_from_preset_with_max_spend(tmp_path: Path) -> None:
    out = tmp_path / "paybond.policy.yaml"
    result = scaffold_policy_from_preset(
        ScaffoldPolicyFromPresetOptions(out=out, preset_id="travel", max_spend_usd=500)
    )
    assert result["max_spend_usd"] == 500
    policy = PaybondPolicy.load(str(out))
    assert policy.document.intent is not None
    assert policy.document.intent.budget is not None
    budget = policy.document.intent.budget
    max_spend = budget["max_spend_usd"] if isinstance(budget, dict) else budget.max_spend_usd
    assert max_spend == 500


def test_scaffold_composed_policy(tmp_path: Path) -> None:
    out = tmp_path / "paybond.policy.yaml"
    result = scaffold_composed_policy(
        ScaffoldComposedPolicyOptions(
            out=out,
            domain_id="travel",
            guardrails="read-only,max-spend:500",
        )
    )
    assert result["domain"] == "travel"
    policy = PaybondPolicy.load(str(out))
    assert list(policy.document.tools) == ["search.web"]


def test_handle_policy_presets_list() -> None:
    data = handle_policy_presets_list(_ctx(Path.cwd()), [])
    assert len(data["domains"]) == 4
    assert len(data["solutions"]) == 5


def test_handle_policy_presets_show_travel() -> None:
    data = handle_policy_presets_show(_ctx(Path.cwd()), ["travel"])
    assert data["preset"] == "travel"
    assert "travel.book_hotel" in data["yaml"]


def test_handle_policy_init_domain_guardrails(tmp_path: Path) -> None:
    out = tmp_path / "paybond.policy.yaml"
    data = handle_policy_init(
        _ctx(tmp_path),
        [
            "--domain",
            "travel",
            "--guardrails",
            "default-deny,max-spend:100",
            "--out",
            str(out),
        ],
    )
    assert data["domain"] == "travel"
    policy = PaybondPolicy.load(str(out))
    assert policy.document.default_deny is True
    assert policy.document.intent is not None
    assert policy.document.intent.budget is not None
    budget = policy.document.intent.budget
    max_spend = budget["max_spend_usd"] if isinstance(budget, dict) else budget.max_spend_usd
    assert max_spend == 100


def test_render_policy_document_yaml_travel() -> None:
    yaml = render_policy_document_yaml(resolve_composed_preset_document("travel"))
    assert "travel.book_hotel:" in yaml
    assert "search.web:" in yaml
