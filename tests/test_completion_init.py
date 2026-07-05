from __future__ import annotations

import json
from pathlib import Path

import pytest

from paybond_kit.completion_catalog import get_completion_preset, load_completion_catalog
from paybond_kit.completion_init import run_completion_init


def test_catalog_loads_api_response_ok() -> None:
    catalog = load_completion_catalog()
    assert catalog["version"] == 1
    preset = get_completion_preset("api_response_ok")
    assert preset["harbor_template_id"] == "api_response_v1"
    assert preset["evidence_schema"]["required"] == ["http_status", "vendor_ref_id", "response_digest"]


def test_init_completion_scaffolds_aligned_schema(tmp_path: Path, capsys) -> None:
    out = tmp_path / "paybond_completion_api_response_ok.py"
    preset = get_completion_preset("api_response_ok")

    assert run_completion_init(["--preset", "api_response_ok", "--out", str(out)]) == 0

    captured = capsys.readouterr()
    assert "Created Paybond completion integration" in captured.out
    body = out.read_text(encoding="utf-8")
    for fragment in (
        'COMPLETION_PRESET_ID = "api_response_ok"',
        'HARBOR_TEMPLATE_ID = "api_response_v1"',
        "def build_completion_evidence",
        "http_status: int",
        "vendor_ref_id: str",
        "response_digest: str",
        str(preset["sample_evidence"]["http_status"]),
        "policy_binding_stub",
        "create_with_policy_binding",
        "signing v7",
        "completion_preset=COMPLETION_PRESET_ID",
        "paybond policy preview",
    ):
        assert fragment in body


def test_init_completion_refuses_overwrite_without_force(tmp_path: Path) -> None:
    out = tmp_path / "paybond_completion.py"
    out.write_text("existing", encoding="utf-8")

    with pytest.raises(SystemExit):
        run_completion_init(["--preset", "api_response_ok", "--out", str(out)])

    assert out.read_text(encoding="utf-8") == "existing"
