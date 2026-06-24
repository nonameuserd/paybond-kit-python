from __future__ import annotations

import io
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from paybond_kit.cli.audit_export import verify_audit_manifest
from paybond_kit.cli.router import run_cli

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "cli-parity" / "contract.json"
FIXTURE_PATH = Path(__file__).resolve().parents[2] / "cli-parity" / "fixtures" / "signed_audit_manifest.json"

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def _load_signed_audit_manifest() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _native_ed25519_available() -> bool:
    try:
        from paybond_kit._native import verify_ed25519_sha256_hex  # noqa: F401

        return True
    except (ImportError, AttributeError):
        return False


@pytest.mark.skipif(not _native_ed25519_available(), reason="paybond-kit native extension not built")
def test_shared_signed_audit_manifest_fixture_verifies() -> None:
    manifest = _load_signed_audit_manifest()
    assert verify_audit_manifest(manifest) is True


@pytest.mark.asyncio
@pytest.mark.skipif(not _native_ed25519_available(), reason="paybond-kit native extension not built")
async def test_audit_exports_verify_cli_accepts_shared_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    manifest = _load_signed_audit_manifest()
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "audit", "exports", "verify", str(bundle_dir)], stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["ok"] is True
    assert payload["data"]["verified"] is True
    assert payload["data"]["job_id"] == "job-parity-1"
    assert payload["data"]["tenant_realm_id"] == "realm_demo"


@pytest.mark.asyncio
async def test_config_list_json_redacts_sensitive_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_dir = tmp_path / ".config" / "paybond"
    config_dir.mkdir(parents=True)
    (config_dir / "config.json").write_text(
        json.dumps({"values": {"gateway": "https://api.paybond.ai", "api_key": RAW_KEY}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.chdir(tmp_path)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "config", "list"], stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["entries"]["gateway"] == "https://api.paybond.ai"
    assert RAW_KEY not in payload["data"]["entries"]["api_key"]
    assert "paybond_sk_" in payload["data"]["entries"]["api_key"]


@pytest.mark.asyncio
async def test_intents_fund_json_redacts_capability_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        assert method == "POST"
        assert path == "/harbor/intents/intent-1/fund"
        return {"intent_id": "intent-1", "capability_token": "cap-secret", "state": "funded"}

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "intents", "fund", "intent-1"], stdout=stdout)
    assert code == 0
    output = stdout.getvalue()
    payload = json.loads(output)
    assert payload["data"]["capability_token"] == "[redacted]"
    assert "cap-secret" not in output


@pytest.mark.asyncio
async def test_mcp_install_json_reports_0600_written_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    out_path = tmp_path / "mcp.json"
    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "mcp", "install", "--host", "generic", "--scope", "project", "--out", str(out_path)],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["config_path"] == str(out_path)
    assert stat.S_IMODE(out_path.stat().st_mode) == 0o600


def test_contract_declares_shared_audit_manifest_fixture() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    fixture_rel = contract["shared_fixtures"]["signed_audit_manifest"]
    fixture_path = CONTRACT_PATH.parent / fixture_rel
    assert fixture_path.is_file()
    manifest = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert manifest["kind"] == "paybond.audit_export_manifest_v1"
