"""Tests for bundled solution manifests and SDK API."""

from __future__ import annotations

from paybond_kit.paybond import Paybond
from paybond_kit.policy.policy_api import paybond_policy_presets
from paybond_kit.policy.presets import resolve_composed_preset_document
from paybond_kit.solution_api import paybond_solution_presets
from paybond_kit.solution_catalog import get_solution_smoke_defaults, load_solution_manifest


def test_travel_solution_manifest_smoke_defaults() -> None:
    manifest = load_solution_manifest("travel")
    assert manifest["id"] == "travel"
    assert manifest["primary_operation"] == "travel.book_hotel"
    assert manifest["completion_preset"] == "ach_travel_booking"
    assert manifest.get("vendor_pack") == "travel_booking_v1"

    smoke = get_solution_smoke_defaults("travel")
    assert smoke["operation"] == "travel.book_hotel"
    assert smoke["requested_spend_cents"] == 18_700
    assert smoke["evidence_preset"] == "cost_and_completion"
    assert smoke["result_body"] == {"status": "completed", "cost_cents": 18_700}


def test_paybond_solution_travel_bundle() -> None:
    bundle = paybond_solution_presets.travel()
    assert bundle.id == "travel"
    assert bundle.title == "Travel booking agent"
    assert bundle.completion_preset == "ach_travel_booking"
    assert bundle.vendor_pack == "travel_booking_v1"
    assert bundle.operations == ("travel.book_hotel",)
    assert bundle.smoke_defaults["requested_spend_cents"] == 18_700
    assert bundle.policy.document == resolve_composed_preset_document("travel")


def test_paybond_solution_property() -> None:
    from paybond_kit.solution_api import paybond_solution_presets as solution_namespace

    class _Host:
        harbor = object()
        guardrails = object()
        signal = object()
        fraud = object()
        a2a = object()
        protocol = object()
        intents = object()
        audit = object()

    host = _Host()
    paybond = Paybond(
        harbor=host.harbor,  # type: ignore[arg-type]
        guardrails=host.guardrails,  # type: ignore[arg-type]
        signal=host.signal,  # type: ignore[arg-type]
        fraud=host.fraud,  # type: ignore[arg-type]
        a2a=host.a2a,  # type: ignore[arg-type]
        protocol=host.protocol,  # type: ignore[arg-type]
        intents=host.intents,  # type: ignore[arg-type]
        audit=host.audit,  # type: ignore[arg-type]
    )
    assert paybond.solution is solution_namespace


def test_paybond_solution_presets_match_policy_presets() -> None:
    bundle = paybond_solution_presets.travel()
    assert bundle.policy.document == paybond_policy_presets.travel().document
