from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from paybond_kit.cli.help_text import COMMAND_HELP, ROOT_HELP
from paybond_kit.cli.router import run_cli
from paybond_kit.login import mask_api_key

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "cli-parity" / "contract.json"
COMMANDS_PATH = Path(__file__).resolve().parents[2] / "cli-parity" / "commands.json"

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def build_argv(case: dict[str, Any]) -> list[str]:
    argv = list(case["argv"])
    if case.get("format") == "json" and not any(
        arg == "--format" or arg.startswith("--format=") for arg in argv
    ):
        return ["--format", "json", *argv]
    return argv


@pytest.fixture
def contract() -> dict[str, Any]:
    return load_contract()


def test_root_help_matches_contract(contract: dict[str, Any]) -> None:
    assert ROOT_HELP == contract["root_help"]


def test_command_help_matches_contract(contract: dict[str, Any]) -> None:
    expected = contract["command_help"]
    assert COMMAND_HELP == expected
    assert sorted(COMMAND_HELP.keys()) == sorted(expected.keys())


def test_key_masking_matches_contract(contract: dict[str, Any]) -> None:
    for sample in contract["key_masking"]:
        assert mask_api_key(sample["input"]) == sample["expected"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case_index", range(len(load_contract()["error_cases"])))
async def test_error_cases_match_contract(case_index: int, contract: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = contract["error_cases"][case_index]
    monkeypatch.chdir(tmp_path)
    if case.get("with_api_key"):
        monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)
    stdout = io.StringIO()
    stderr = io.StringIO()
    argv = build_argv(case)
    code = await run_cli(argv, stdout=stdout, stderr=stderr)
    assert code == case["exit_code"]
    if case["format"] == "json":
        payload = json.loads(stdout.getvalue())
        assert payload["ok"] is False
        assert payload["error"] is not None
        for key in contract["envelope"]["success_keys"]:
            assert key in payload
        for key in contract["envelope"]["error_object_keys"]:
            assert key in payload["error"]
        if "error" in case:
            assert payload["error"]["category"] == case["error"]["category"]
            assert payload["error"]["code"] == case["error"]["code"]
        assert case["message_contains"] in payload["error"]["message"]
    else:
        assert case["message_contains"] in stderr.getvalue()


@pytest.mark.asyncio
@pytest.mark.parametrize("case_index", range(len(load_contract().get("parse_error_cases", []))))
async def test_parse_error_cases_honor_json_format(
    case_index: int,
    contract: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = contract.get("parse_error_cases", [])
    case = cases[case_index]
    monkeypatch.chdir(tmp_path)
    stdout = io.StringIO()
    stderr = io.StringIO()
    argv = build_argv(case)
    code = await run_cli(argv, stdout=stdout, stderr=stderr)
    assert code == case["exit_code"]
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is False
    assert payload["error"] is not None
    for key in contract["envelope"]["success_keys"]:
        assert key in payload
    for key in contract["envelope"]["error_object_keys"]:
        assert key in payload["error"]
    if "error" in case:
        assert payload["error"]["category"] == case["error"]["category"]
        assert payload["error"]["code"] == case["error"]["code"]
    assert case["message_contains"] in payload["error"]["message"]
    assert stderr.getvalue() == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("case_index", range(len(load_contract().get("help_paths", []))))
async def test_help_paths_match_contract(case_index: int, contract: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = contract["help_paths"][case_index]
    monkeypatch.chdir(tmp_path)
    stdout = io.StringIO()
    code = await run_cli(list(case["argv"]), stdout=stdout)
    assert code == 0
    assert case["contains"] in stdout.getvalue()


@pytest.mark.asyncio
@pytest.mark.parametrize("case_index", range(len(load_contract().get("global_flag_placement", []))))
async def test_global_flag_placement_matches_contract(
    case_index: int,
    contract: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = contract["global_flag_placement"][case_index]
    monkeypatch.chdir(tmp_path)
    if case.get("with_api_key"):
        monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        return {
            "tenant_id": "tenant-sandbox",
            "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "environment": "sandbox",
            "service_account_role": "operator",
        }

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(list(case["argv"]), stdout=stdout)
    assert code == case["exit_code"]
    if case.get("envelope_ok"):
        payload = json.loads(stdout.getvalue())
        assert payload["ok"] is True
        for key in contract["envelope"]["success_keys"]:
            assert key in payload


@pytest.mark.asyncio
async def test_whoami_json_output_keys_match_contract(
    contract: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        assert method == "GET"
        assert path == "/v1/auth/principal"
        return {
            "tenant_id": "tenant-sandbox",
            "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "environment": "sandbox",
            "service_account_role": "operator",
            "access_token": "secret",
        }

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "--request-id", "01PARITYWHOAMI", "whoami", "--env-file", ".env.local"],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    for key in contract["command_data_keys"]["whoami"]:
        assert key in payload["data"]
    assert "access_token" not in payload["data"]["principal"]


@pytest.mark.asyncio
async def test_doctor_json_output_keys_match_contract(
    contract: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)
    env_path = tmp_path / ".env.local"
    env_path.write_text(f"PAYBOND_API_KEY={RAW_KEY}\n", encoding="utf-8")

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        return {
            "tenant_id": "tenant-sandbox",
            "tenant_uuid": "550e8400-e29b-41d4-a716-446655440000",
            "environment": "sandbox",
            "service_account_role": "operator",
        }

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "--request-id", "01PARITYDOCTOR", "doctor", "--env-file", ".env.local"],
        stdout=stdout,
    )
    assert code in (0, 1)
    payload = json.loads(stdout.getvalue())
    for key in contract["command_data_keys"]["doctor"]:
        assert key in payload["data"]
    for check in payload["data"]["checks"]:
        for key in contract["nested_data_keys"]["doctor.checks[]"]:
            assert key in check


@pytest.mark.asyncio
async def test_keys_list_json_output_keys_match_contract(
    contract: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        assert method == "GET"
        assert path.startswith("/v1/admin/api-keys")
        return {
            "items": [
                {
                    "key_id": "key-1",
                    "environment": "sandbox",
                    "service_account_role": "operator",
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": None,
                }
            ]
        }

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "--request-id", "01PARITYKEYS", "keys", "list", "--env-file", ".env.local"],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    for key in contract["command_data_keys"]["keys list"]:
        assert key in payload["data"]
    for row in payload["data"]["keys"]:
        for key in contract["nested_data_keys"]["keys list.keys[]"]:
            assert key in row


@pytest.mark.asyncio
async def test_guardrails_bootstrap_json_output_keys_match_contract(
    contract: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        assert method == "POST"
        assert path == "/v1/sandbox/guardrails/bootstrap"
        return {
            "tenant_id": "tenant-sandbox",
            "intent_id": "intent-1",
            "capability_token": "cap-token",
            "operation": "paid-tool",
            "requested_spend_cents": 100,
            "sandbox_lifecycle_status": "active",
        }

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "--request-id",
            "01PARITYGUARD",
            "guardrails",
            "bootstrap",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--env-file",
            ".env.local",
        ],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    for key in contract["command_data_keys"]["guardrails bootstrap"]:
        assert key in payload["data"]


def test_shared_audit_manifest_fixture_matches_contract(contract: dict[str, Any]) -> None:
    fixture_rel = contract["shared_fixtures"]["signed_audit_manifest"]
    fixture_path = CONTRACT_PATH.parent / fixture_rel
    manifest = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert manifest["kind"] == "paybond.audit_export_manifest_v1"
    assert manifest["job_id"] == "job-parity-1"


def test_contract_matches_commands_spec() -> None:
    spec = json.loads(COMMANDS_PATH.read_text(encoding="utf-8"))
    contract = load_contract()
    assert contract["envelope"] == spec["envelope"]
    assert contract["key_masking"] == spec["key_masking"]
    assert contract["error_cases"] == spec["error_cases"]
    assert contract.get("parse_error_cases", []) == spec.get("parse_error_cases", [])
    assert contract.get("help_paths", []) == spec.get("help_paths", [])
    assert contract.get("global_flag_placement", []) == spec.get("global_flag_placement", [])
    assert sorted(contract["command_help"].keys()) == sorted(command["path"] for command in spec["commands"])
