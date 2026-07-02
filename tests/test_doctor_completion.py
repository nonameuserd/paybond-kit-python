from __future__ import annotations

import json
from pathlib import Path

from paybond_kit.completion_catalog import get_completion_preset
from paybond_kit.completion_resolve import resolve_completion_preset
from paybond_kit.doctor_completion import (
    is_stripe_funding_webhook_event_type,
    run_completion_catalog_doctor_checks,
)


def _build_scaffold_body(
    preset_id: str,
    *,
    parameters: dict[str, object] | None = None,
    evidence_schema: dict[str, object] | None = None,
) -> str:
    resolved = resolve_completion_preset(preset_id)
    preset = resolved["preset"]
    params = parameters if parameters is not None else resolved["parameters"]
    schema = evidence_schema if evidence_schema is not None else preset["evidence_schema"]
    return (
        f'COMPLETION_PRESET_ID = "{preset_id}"\n\n'
        f"completion_evidence_schema: dict[str, Any] = {json.dumps(schema)}\n\n"
        f"completion_template_parameters: dict[str, Any] = {json.dumps(params)}\n\n"
    )


def test_doctor_warns_on_deprecated_stripe_webhook_payment(tmp_path: Path) -> None:
    scaffold = tmp_path / "paybond_completion_stripe_webhook_payment.py"
    scaffold.write_text(_build_scaffold_body("stripe_webhook_payment"), encoding="utf-8")

    checks = run_completion_catalog_doctor_checks(cwd=tmp_path)
    deprecated = next(check for check in checks if check["name"] == "completion_deprecated_preset")
    assert "warn:" in deprecated["message"]
    assert "vendor_webhook_confirmed" in deprecated["message"]


def test_doctor_warns_on_forbidden_evidence_fields(tmp_path: Path) -> None:
    preset = get_completion_preset("ach_paid_api_ok")
    polluted = dict(preset["evidence_schema"])
    polluted["properties"] = {
        **preset["evidence_schema"]["properties"],
        "payment_intent_id": {"type": "string"},
    }
    scaffold = tmp_path / "paybond_completion_ach_paid_api_ok.py"
    scaffold.write_text(
        _build_scaffold_body("ach_paid_api_ok", evidence_schema=polluted),
        encoding="utf-8",
    )

    checks = run_completion_catalog_doctor_checks(cwd=tmp_path)
    forbidden = next(check for check in checks if check["name"] == "completion_forbidden_fields")
    assert "payment_intent_id" in forbidden["message"]


def test_doctor_warns_on_stripe_funding_event_misuse(tmp_path: Path) -> None:
    scaffold = tmp_path / "paybond_completion_webhook_confirmed.py"
    scaffold.write_text(
        _build_scaffold_body(
            "webhook_confirmed",
            parameters={
                "event_type_path": ["event_type"],
                "expected_event_type": "charge.succeeded",
            },
        ),
        encoding="utf-8",
    )

    checks = run_completion_catalog_doctor_checks(cwd=tmp_path)
    funding = next(check for check in checks if check["name"] == "completion_funding_event_misuse")
    assert "charge.succeeded" in funding["message"]


def test_is_stripe_funding_webhook_event_type() -> None:
    assert is_stripe_funding_webhook_event_type("payment_intent.succeeded")
    assert is_stripe_funding_webhook_event_type("charge.succeeded")
    assert not is_stripe_funding_webhook_event_type("job.completed")


def test_doctor_warns_when_vendor_pack_pin_lags_catalog(tmp_path: Path) -> None:
    preset = get_completion_preset("stripe_charge")
    contract = preset.get("vendor_contract")
    assert isinstance(contract, dict)
    scaffold = tmp_path / "paybond_completion_stripe_charge.py"
    scaffold.write_text(
        (
            'COMPLETION_PRESET_ID = "stripe_charge"\n\n'
            'VENDOR_CONTRACT_API_VERSION = "legacy_epoch"\n'
            f'VENDOR_SCHEMA_DIGEST_HEX = "{contract["schema_digest_hex"]}"\n'
            f'CANONICAL_SCHEMA_DIGEST_HEX = "{contract["canonical_schema_digest_hex"]}"\n\n'
            f"completion_evidence_schema: dict[str, Any] = {json.dumps(preset['evidence_schema'])}\n\n"
            f"completion_template_parameters: dict[str, Any] = {json.dumps(resolve_completion_preset('stripe_charge')['parameters'])}\n\n"
        ),
        encoding="utf-8",
    )

    checks = run_completion_catalog_doctor_checks(cwd=tmp_path)
    pack_stale = next(check for check in checks if check["name"] == "completion_pack_stale")
    assert "warn:" in pack_stale["message"]
    assert "legacy_epoch" in pack_stale["message"]
