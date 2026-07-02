from __future__ import annotations

from pathlib import Path

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
