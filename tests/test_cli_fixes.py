from __future__ import annotations

import io
import json
import stat
from pathlib import Path

import pytest

from paybond_kit.cli.audit_export import audit_verify_result, build_manifest_core, manifest_core_bytes, verify_audit_manifest
from paybond_kit.cli.core import list_config_entries, parse_optional_non_negative_int, parse_required_non_negative_int, rejects_tenant_override_flag
from paybond_kit.cli.automation import build_list_query_params
from paybond_kit.cli.help_text import ROOT_HELP
from paybond_kit.cli.redact import is_sensitive_config_key, redact_config_value, redact_sensitive_fields
from paybond_kit.cli.router import run_cli

RAW_KEY = (
    "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def test_rejects_tenant_override_variants() -> None:
    assert rejects_tenant_override_flag("--tenant-id")
    assert rejects_tenant_override_flag("--tenant-id=tenant-a")
    assert rejects_tenant_override_flag("--tenant")
    assert rejects_tenant_override_flag("--tenant_id")
    assert not rejects_tenant_override_flag("--tenant-name")


def test_parse_non_negative_int_rejects_invalid_values() -> None:
    with pytest.raises(Exception, match="invalid --requested-spend-cents"):
        parse_required_non_negative_int("abc", field="--requested-spend-cents")
    assert parse_optional_non_negative_int(None, field="--requested-spend-cents") == 0


def test_config_list_redacts_sensitive_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_dir = tmp_path / ".config" / "paybond"
    config_dir.mkdir(parents=True)
    config_path = config_dir / "config.json"
    config_path.write_text(
        json.dumps({"values": {"gateway": "https://api.paybond.ai", "api_key": RAW_KEY}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    entries = list_config_entries(None)
    assert entries["gateway"] == "https://api.paybond.ai"
    assert RAW_KEY not in entries["api_key"]
    assert redact_config_value("api_key", RAW_KEY) != RAW_KEY


def test_redact_config_value_leaves_non_secret_keys_untouched() -> None:
    assert redact_config_value("gateway", "https://api.paybond.ai") == "https://api.paybond.ai"
    assert redact_config_value("token_endpoint", "https://issuer.example/oauth/token") == "https://issuer.example/oauth/token"
    assert is_sensitive_config_key("monkey") is False


@pytest.mark.asyncio
async def test_config_get_redacts_sensitive_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_dir = tmp_path / ".config" / "paybond"
    config_dir.mkdir(parents=True)
    (config_dir / "config.json").write_text(
        json.dumps({"values": {"api_key": RAW_KEY}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.chdir(tmp_path)
    stdout = io.StringIO()
    code = await run_cli(["--format", "json", "config", "get", "api_key"], stdout=stdout)
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert RAW_KEY not in stdout.getvalue()
    assert payload["data"]["value"] != RAW_KEY


def test_root_help_formats_long_flag_and_command_names() -> None:
    assert "never Colorize" in ROOT_HELP
    assert "fish Shell completion scripts" in ROOT_HELP
    assert "tools MCP server" in ROOT_HELP


def test_build_list_query_params_url_encodes_cursor() -> None:
    assert build_list_query_params("20", "a&b=c") == "limit=20&cursor=a%26b%3Dc"


def test_resolve_api_key_with_meta_warns_on_process_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from paybond_kit.cli.core import GlobalOptions, resolve_api_key_with_meta

    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)
    _, warnings = resolve_api_key_with_meta(GlobalOptions(), tmp_path)
    assert any("cli.warn.env_fallback" in warning for warning in warnings)


def test_redact_sensitive_fields_masks_capability_token() -> None:
    redacted = redact_sensitive_fields({"capability_token": "secret-token", "intent_id": "intent-1"})
    assert redacted == {"capability_token": "[redacted]", "intent_id": "intent-1"}


def test_manifest_core_bytes_omits_signature_fields() -> None:
    core = build_manifest_core(
        {
            "schema_version": 1,
            "kind": "paybond.audit_export_manifest_v1",
            "tenant_realm_id": "realm_demo",
            "signing_public_key_ed25519_hex": "aa",
        }
    )
    assert "signing_public_key_ed25519_hex" not in core
    assert manifest_core_bytes({"schema_version": 1, "kind": "k"}) == b'{"schema_version":1,"kind":"k"}'


def test_verify_audit_manifest_rejects_tampered_digest() -> None:
    manifest = {
        "schema_version": 1,
        "kind": "paybond.audit_export_manifest_v1",
        "tenant_realm_id": "realm_demo",
        "signed_payload_sha256_hex": "00" * 32,
        "ed25519_signature_hex": "00" * 64,
        "signing_public_key_ed25519_hex": "00" * 32,
    }
    assert verify_audit_manifest(manifest) is False
    result = audit_verify_result(manifest, path="bundle.zip")
    assert result["verified"] is False


@pytest.mark.asyncio
async def test_invalid_requested_spend_cents_returns_cli_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)
    stderr = io.StringIO()
    code = await run_cli(
        ["guardrails", "bootstrap", "--operation", "paid-tool", "--requested-spend-cents", "abc"],
        stderr=stderr,
    )
    assert code == 1
    assert "invalid --requested-spend-cents" in stderr.getvalue()


@pytest.mark.asyncio
async def test_intents_create_json_redacts_capability_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)
    body_path = tmp_path / "intent.json"
    body_path.write_text("{}", encoding="utf-8")

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        assert method == "POST"
        assert path == "/harbor/intents"
        return {"intent_id": "intent-1", "capability_token": "cap-secret"}

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        ["--format", "json", "intents", "create", "--body", str(body_path)],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["capability_token"] == "[redacted]"
    assert "cap-secret" not in stdout.getvalue()


@pytest.mark.asyncio
async def test_keys_create_returns_one_time_api_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PAYBOND_API_KEY", RAW_KEY)

    def fake_gateway_request(ctx, method, path, payload=None):  # type: ignore[no-untyped-def]
        assert method == "POST"
        assert path == "/v1/admin/api-keys"
        return {
            "api_key": RAW_KEY,
            "item": {
                "key_id": "key-1",
                "service_account_role": "operator",
                "created_at": "2026-01-01T00:00:00Z",
            },
        }

    monkeypatch.setattr("paybond_kit.cli.commands.gateway_request", fake_gateway_request)

    stdout = io.StringIO()
    code = await run_cli(
        [
            "--format",
            "json",
            "keys",
            "create",
            "--name",
            "ci-bot",
            "--role",
            "operator",
        ],
        stdout=stdout,
    )
    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["data"]["api_key"] == RAW_KEY
    assert payload["data"]["key_masked"] != RAW_KEY


@pytest.mark.asyncio
async def test_mcp_install_writes_config_with_0600_permissions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stdout = io.StringIO()
    code = await run_cli(
        [
            "mcp",
            "install",
            "--host",
            "generic",
            "--scope",
            "project",
            "--out",
            str(tmp_path / "mcp.json"),
        ],
        stdout=stdout,
    )
    assert code == 0
    config_path = tmp_path / "mcp.json"
    assert config_path.is_file()
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert "PAYBOND_ENV_FILE" in config_path.read_text(encoding="utf-8")
