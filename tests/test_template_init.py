from __future__ import annotations

import json
from pathlib import Path

import pytest

from paybond_kit.template_init import (
    CopyTemplateOptions,
    copy_template_to_directory,
    list_template_entries,
    normalize_template_id,
)


def test_list_template_entries_includes_travel_agent() -> None:
    entries = list_template_entries()
    assert len(entries) >= 9
    assert any(entry["id"] == "travel-agent" for entry in entries)


def test_normalize_template_id_accepts_repo_slug() -> None:
    assert normalize_template_id("paybond-travel-agent") == "travel-agent"
    assert normalize_template_id("paybond-invoice-agent") == "invoice-agent"
    assert normalize_template_id("paybond-crewai-procurement-agent") == "crewai-procurement-agent"
    assert (
        normalize_template_id("paybond-microsoft-agent-framework-procurement-agent")
        == "microsoft-agent-framework-procurement-agent"
    )


def test_copy_travel_agent_template(tmp_path: Path) -> None:
    lines: list[str] = []
    result = copy_template_to_directory(
        CopyTemplateOptions(
            cwd=tmp_path,
            template_id="travel-agent",
            write_stdout=lines.append,
        )
    )
    assert result["template_id"] == "travel-agent"
    assert result["repo"] == "paybond-travel-agent"
    assert result["preset"] == "travel"
    assert "--policy-file paybond.policy.yaml" in str(result["smoke_command"])

    package_json = json.loads((tmp_path / "package.json").read_text(encoding="utf-8"))
    assert package_json["dependencies"]["@paybond/kit"].startswith("^")
    assert (tmp_path / "paybond.policy.yaml").exists()
    assert (tmp_path / "src/index.ts").exists()
    assert any(line.startswith("Created ") for line in lines)


def test_copy_invoice_agent_python_template(tmp_path: Path) -> None:
    result = copy_template_to_directory(
        CopyTemplateOptions(
            cwd=tmp_path,
            template_id="invoice-agent",
            force=True,
        )
    )
    assert result["language"] == "python"
    assert (tmp_path / "app.py").exists()
    assert (tmp_path / "paybond_config.py").exists()
    assert (tmp_path / "requirements.txt").exists()


def test_copy_crewai_procurement_agent_template(tmp_path: Path) -> None:
    result = copy_template_to_directory(
        CopyTemplateOptions(
            cwd=tmp_path,
            template_id="crewai-procurement-agent",
            framework="crewai",
            force=True,
        )
    )
    assert result["language"] == "python"
    assert result["framework"] == "crewai"
    assert result["repo"] == "paybond-crewai-procurement-agent"
    assert (tmp_path / "app.py").exists()
    assert (tmp_path / "crew.py").exists()
    assert (tmp_path / "paybond.policy.yaml").exists()
    assert (tmp_path / "requirements.txt").exists()
    requirements = (tmp_path / "requirements.txt").read_text(encoding="utf-8")
    assert "paybond-kit[crewai]" in requirements
    assert "crewai" in requirements
    assert "procurement.submit_po" in str(result["smoke_command"])


def test_copy_refuses_overwrite_without_force(tmp_path: Path) -> None:
    copy_template_to_directory(
        CopyTemplateOptions(cwd=tmp_path, template_id="travel-agent", force=True)
    )
    with pytest.raises(RuntimeError, match="already exists"):
        copy_template_to_directory(
            CopyTemplateOptions(cwd=tmp_path, template_id="travel-agent", force=False)
        )
