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
    monkeypatch.setenv("APP_AGENT_RECOGNITION_KEY_ID", "kid-1")
    monkeypatch.setenv("APP_AGENT_RECOGNITION_SEED_HEX", "02" * 32)

    fund_calls: dict[str, object] = {}

    async def fake_with_paybond_cli(ctx, handler):  # type: ignore[no-untyped-def]
        class FakeHarbor:
            tenant_id = "tenant-sandbox"

            async def fund_intent(self, intent_id, *, recognition_proof, payment_signature=None, idempotency_key=None):  # type: ignore[no-untyped-def]
                fund_calls["intent_id"] = intent_id
                fund_calls["recognition_proof"] = recognition_proof
                fund_calls["payment_signature"] = payment_signature
                from paybond_kit.harbor import FundIntentResult

                return FundIntentResult(
                    status_code=200,
                    payment_required=None,
                    payment_response=None,
                    intent_id=intent_id,
                    tenant="tenant-sandbox",
                    state="funded",
                    settlement_rail="x402_usdc_base",
                    currency="USD",
                    amount_cents=100,
                    funded=True,
                    capability_token="cap-secret",
                    funding=None,
                )

        class FakePaybond:
            harbor = FakeHarbor()

        return await handler(FakePaybond(), [])

    monkeypatch.setattr("paybond_kit.cli.agent_paybond.with_paybond_cli", fake_with_paybond_cli)

    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "intents", "fund", "12345678-1234-5678-1234-567812345678"], stdout=stdout)
    assert code == 0
    assert fund_calls["recognition_proof"]
    output = stdout.getvalue()
    payload = json.loads(output)
    assert payload["data"]["capability_token"] == "[redacted]"
    assert "cap-secret" not in output


@pytest.mark.asyncio
async def test_intents_fund_body_shim_maps_payment_signature_and_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)
    monkeypatch.setenv("APP_AGENT_RECOGNITION_KEY_ID", "kid-1")
    monkeypatch.setenv("APP_AGENT_RECOGNITION_SEED_HEX", "02" * 32)
    body_path = tmp_path / "fund.json"
    body_path.write_text(json.dumps({"payment_signature": "sig-from-body"}), encoding="utf-8")

    fund_calls: dict[str, object] = {}

    async def fake_with_paybond_cli(ctx, handler):  # type: ignore[no-untyped-def]
        class FakeHarbor:
            tenant_id = "tenant-sandbox"

            async def fund_intent(self, intent_id, *, recognition_proof, payment_signature=None, idempotency_key=None):  # type: ignore[no-untyped-def]
                fund_calls["payment_signature"] = payment_signature
                from paybond_kit.harbor import FundIntentResult

                return FundIntentResult(
                    status_code=200,
                    payment_required=None,
                    payment_response=None,
                    intent_id=intent_id,
                    tenant="tenant-sandbox",
                    state="funded",
                    settlement_rail="x402_usdc_base",
                    currency="USD",
                    amount_cents=100,
                    funded=True,
                    capability_token=None,
                    funding=None,
                )

        class FakePaybond:
            harbor = FakeHarbor()

        return await handler(FakePaybond(), [])

    monkeypatch.setattr("paybond_kit.cli.agent_paybond.with_paybond_cli", fake_with_paybond_cli)

    stderr = io.StringIO()
    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "intents", "fund", "12345678-1234-5678-1234-567812345678", "--body", str(body_path)],
        stdout=stdout,
        stderr=stderr,
    )
    assert code == 0
    assert fund_calls["payment_signature"] == "sig-from-body"
    assert "deprecated: intents fund --body; use --payment-signature" in stderr.getvalue()


@pytest.mark.asyncio
async def test_intents_evidence_sends_recognition_proof_via_sdk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)
    monkeypatch.setenv("APP_AGENT_RECOGNITION_KEY_ID", "kid-1")
    monkeypatch.setenv("APP_AGENT_RECOGNITION_SEED_HEX", "02" * 32)
    body_path = tmp_path / "evidence.json"
    body_path.write_text(json.dumps({"status": "ok"}), encoding="utf-8")

    evidence_calls: dict[str, object] = {}

    async def fake_with_paybond_cli(ctx, handler):  # type: ignore[no-untyped-def]
        class FakeHarbor:
            tenant_id = "tenant-sandbox"

            async def submit_evidence(self, intent_id, evidence_body, *, recognition_proof, idempotency_key=None):  # type: ignore[no-untyped-def]
                evidence_calls["intent_id"] = intent_id
                evidence_calls["evidence_body"] = evidence_body
                evidence_calls["recognition_proof"] = recognition_proof
                return {
                    "intent_id": str(intent_id),
                    "tenant": "tenant-sandbox",
                    "state": "evidence_submitted",
                }

        class FakePaybond:
            harbor = FakeHarbor()

        return await handler(FakePaybond(), [])

    monkeypatch.setattr("paybond_kit.cli.agent_paybond.with_paybond_cli", fake_with_paybond_cli)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "intents",
            "evidence",
            "12345678-1234-5678-1234-567812345678",
            "--body",
            str(body_path),
        ],
        stdout=stdout,
    )
    assert code == 0
    assert evidence_calls["recognition_proof"]
    assert evidence_calls["evidence_body"] == {"status": "ok"}
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["state"] == "evidence_submitted"


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
