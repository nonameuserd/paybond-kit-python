from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from paybond_kit.cli.core import CliContext, CliError, default_globals
from paybond_kit.cli.policy import handle_policy_init, handle_policy_validate_tools


def _ctx(cwd: Path) -> CliContext:
    return CliContext(
        globals=default_globals(),
        cwd=cwd,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )


def test_handle_policy_init_writes_policy_file(tmp_path: Path) -> None:
    out = tmp_path / "paybond.policy.yaml"
    result = handle_policy_init(
        _ctx(tmp_path),
        ["--out", str(out), "--operation", "travel.book_hotel", "--evidence-preset", "cost_and_completion"],
    )
    assert result["name"] == "travel-book-hotel-v1"
    assert out.exists()


def test_handle_policy_validate_tools_rejects_misaligned_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text(
        """version: 1
name: bad-allowed-v1
default_deny: true
tools:
  travel.book_hotel:
    side_effecting: true
    evidence_preset: cost_and_completion
intent:
  allowed_tools:
    - payments.charge
""",
        encoding="utf-8",
    )
    with pytest.raises(CliError, match="policy validation failed") as exc:
        handle_policy_validate_tools(_ctx(tmp_path), ["--file", str(policy_path)])
    assert exc.value.code == "cli.policy.validation_failed"
    assert exc.value.details is not None
    assert exc.value.details["valid"] is False


def test_handle_policy_validate_tools_accepts_valid_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text(
        json.dumps(
            {
                "version": 1,
                "name": "travel-agent-v1",
                "default_deny": True,
                "tools": {
                    "travel.book_hotel": {
                        "side_effecting": True,
                        "evidence_preset": "cost_and_completion",
                    }
                },
                "intent": {"allowed_tools": ["travel.book_hotel"]},
            }
        ),
        encoding="utf-8",
    )
    result = handle_policy_validate_tools(_ctx(tmp_path), ["--file", str(policy_path), "--local-only"])
    assert result["valid"] is True
    assert result["policy_name"] == "travel-agent-v1"


def test_handle_policy_validate_tools_remote(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "paybond.policy.yaml"
    policy_path.write_text(
        json.dumps(
            {
                "version": 1,
                "name": "travel-agent-v1",
                "default_deny": True,
                "tools": {
                    "travel.book_hotel": {
                        "side_effecting": True,
                        "evidence_preset": "cost_and_completion",
                    }
                },
                "intent": {"allowed_tools": ["travel.book_hotel"]},
            }
        ),
        encoding="utf-8",
    )

    def _fake_gateway_request(
        ctx: CliContext,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        assert method == "POST"
        assert path == "/v1/policy/validate"
        assert payload is not None
        assert payload["name"] == "travel-agent-v1"
        return {
            "valid": True,
            "local_valid": True,
            "remote_valid": True,
            "policy_name": "travel-agent-v1",
            "tenant_id": "tenant-sandbox",
            "errors": [],
            "warnings": [],
            "checks": [{"name": "template_exists", "passed": True}],
        }

    monkeypatch.setattr("paybond_kit.cli.policy.gateway_request", _fake_gateway_request)
    result = handle_policy_validate_tools(_ctx(tmp_path), ["--file", str(policy_path), "--remote"])
    assert result["remote_valid"] is True
