from __future__ import annotations

from pathlib import Path

import pytest

from paybond_kit.policy.schema import PaybondPolicyValidationError
from paybond_kit.project_init import ProjectInitOptions, run_project_init


def test_run_project_init_non_interactive_travel(tmp_path: Path) -> None:
    result = run_project_init(
        ProjectInitOptions(
            cwd=tmp_path,
            solution="travel",
            max_spend_usd=500,
            framework="langgraph",
            language="typescript",
            non_interactive=True,
            force=True,
        )
    )
    assert result["solution"] == "travel"
    assert result["preset_id"] == "travel"
    assert result["framework"] == "langgraph"
    assert (tmp_path / "paybond.policy.yaml").exists()
    assert (tmp_path / "paybond.instrument.ts").exists()
    policy_text = (tmp_path / "paybond.policy.yaml").read_text(encoding="utf-8")
    assert "max_spend_usd: 500" in policy_text
    instrument_text = (tmp_path / "paybond.instrument.ts").read_text(encoding="utf-8")
    assert "instrumentLangGraph" in instrument_text


def test_run_project_init_interactive_overwrite_confirmation(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text("name: existing\n", encoding="utf-8")
    prompts: list[str] = []

    result = run_project_init(
        ProjectInitOptions(
            cwd=tmp_path,
            solution="saas",
            max_spend_usd=100,
            framework="generic",
            language="typescript",
            prompt=lambda question: prompts.append(question) or "yes",
        )
    )

    assert result["preset_id"] == "saas"
    assert prompts == [f"{policy_path} already exists. Overwrite it? [y/N] "]
    assert "name: saas" in policy_path.read_text(encoding="utf-8")


def test_run_project_init_force_overwrites_existing_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text("name: existing\n", encoding="utf-8")

    run_project_init(
        ProjectInitOptions(
            cwd=tmp_path,
            solution="saas",
            max_spend_usd=100,
            framework="generic",
            language="typescript",
            non_interactive=True,
            force=True,
        )
    )

    policy_text = policy_path.read_text(encoding="utf-8")
    assert "name: saas" in policy_text
    assert "max_spend_usd: 100" in policy_text


def test_run_project_init_non_interactive_refuses_existing_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text("name: existing\n", encoding="utf-8")

    with pytest.raises(PaybondPolicyValidationError, match=r"paybond\.policy\.yaml already exists.*--force"):
        run_project_init(
            ProjectInitOptions(
                cwd=tmp_path,
                solution="saas",
                max_spend_usd=100,
                framework="generic",
                language="typescript",
                non_interactive=True,
            )
        )
