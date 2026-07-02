from __future__ import annotations

import json

import httpx
import pytest
import respx

from paybond_kit.fraud import GatewayFraudClient, ServiceAccountFraudSession


def _api_key() -> str:
    return "paybond_sk_" + "a" * 32 + "_" + "b" * 64


@pytest.mark.asyncio
@respx.mock
async def test_get_fraud_assessment_checks_tenant_and_operator_binding() -> None:
    respx.get(
        "https://gateway.test/signal/v1/operators/did%3Aexample%3Aalpha/review-status"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "tenant-a",
                "operator_did": "did:example:alpha",
                "score_model_version": "1.0",
                "review_state": "open",
                "review_reasons": ["FRAUD_REVIEW"],
                "fraud_signals": [
                    {
                        "code": "REPEATED_FAILED_PREDICATES",
                        "severity": "high",
                        "category": "manipulation",
                        "window": "7d",
                        "evidence_count": 3,
                        "summary": "failed predicates clustered",
                        "affects_score": False,
                        "signal_source": "signal_model",
                        "first_seen_at": "2026-05-23T17:00:00Z",
                        "last_seen_at": "2026-05-23T18:00:00Z",
                        "evidence_binding_strength": "intent_bound",
                        "intent_refs": ["intent-1"],
                    }
                ],
                "fraud_assessment": {
                    "fraud_signal_version": "1.0.4",
                    "level": "high",
                    "highest_severity": "high",
                    "review_priority": "high",
                    "signal_count": 1,
                    "severe_signal_count": 1,
                    "summary": "level=high",
                },
            },
        )
    )
    client = GatewayFraudClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token=_api_key(),
    )
    try:
        assessment = await client.get_fraud_assessment("did:example:alpha")
        assert assessment is not None
        assert assessment["tenant_id"] == "tenant-a"
        assert assessment["operator_did"] == "did:example:alpha"
        assert assessment["fraud_assessment"]["level"] == "high"
        first_signal = assessment["fraud_signals"][0]
        assert first_signal.get("signal_source") == "signal_model"
        assert first_signal.get("intent_refs") == ["intent-1"]
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_get_fraud_assessment_rejects_tenant_mismatch() -> None:
    respx.get(
        "https://gateway.test/signal/v1/operators/did%3Aexample%3Aalpha/review-status"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "other",
                "operator_did": "did:example:alpha",
                "score_model_version": "1.0",
                "review_state": "open",
                "review_reasons": [],
                "fraud_signals": [],
                "fraud_assessment": {
                    "fraud_signal_version": "1.0.4",
                    "level": "none",
                    "highest_severity": "none",
                    "review_priority": "normal",
                    "signal_count": 0,
                    "severe_signal_count": 0,
                    "summary": "level=none",
                },
            },
        )
    )
    client = GatewayFraudClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token=_api_key(),
    )
    try:
        with pytest.raises(RuntimeError, match="fraud tenant mismatch"):
            await client.get_fraud_assessment("did:example:alpha")
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_list_fraud_review_queue_filters_by_severity() -> None:
    respx.get(
        "https://gateway.test/signal/v1/review-queue?state=all&fraud_severity=high&limit=25&score_version=1.0"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "tenant-a",
                "score_model_version": "1.0",
                "items": [],
            },
        )
    )
    client = GatewayFraudClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token=_api_key(),
    )
    try:
        queue = await client.list_fraud_review_queue(
            state="all",
            severity="high",
            limit=25,
            score_version="1.0",
        )
        assert queue["tenant_id"] == "tenant-a"
        assert queue["items"] == []
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_get_fraud_metrics_checks_tenant_binding() -> None:
    respx.get("https://gateway.test/signal/v1/fraud/metrics?window=7d").mock(
        return_value=httpx.Response(
            200,
            json={
                "schema_version": 1,
                "tenant_id": "tenant-a",
                "score_model_version": "1.0",
                "fraud_signal_version": "1.0.4",
                "window": "7d",
                "window_started_at": "2026-05-16T00:00:00Z",
                "window_ended_at": "2026-05-23T00:00:00Z",
                "generated_at": "2026-05-23T00:00:00Z",
                "flagged_operator_count": 2,
                "critical_signal_count": 1,
                "high_signal_count": 1,
                "elevated_signal_count": 0,
                "review_open_count": 1,
                "review_load_count": 1,
                "reviewed_count": 2,
                "labeled_outcome_count": 1,
                "confirmed_risk_count": 1,
                "false_positive_count": 0,
                "needs_more_evidence_count": 1,
                "review_precision_bps": 10000,
                "false_positive_rate_bps": 0,
                "confirmed_risk_rate_bps": 5000,
                "labeled_coverage_bps": 5000,
                "median_time_to_review_seconds": 300,
                "refund_burst_count": 1,
                "dispute_cluster_count": 0,
                "replay_appeal_abuse_count": 0,
                "critical_signal_hold_candidate_count": 1,
                "provider_signal_count": 0,
                "stale_label_gap_seconds": 900,
                "stale_signal_family_label_gap_count": 0,
                "backtest_summary": "precision_bps=10000",
            },
        )
    )
    client = GatewayFraudClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token=_api_key(),
    )
    try:
        metrics = await client.get_fraud_metrics(window="7d")
        assert metrics["tenant_id"] == "tenant-a"
        assert metrics["flagged_operator_count"] == 2
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_fraud_release_gate_config_round_trip() -> None:
    gate_body = {
        "schema_version": 1,
        "tenant_id": "tenant-a",
        "score_model_version": "1.0",
        "fraud_signal_version": "1.0.7",
        "generated_at": "2026-05-23T00:00:00Z",
        "config": {"mode": "critical_hold"},
        "metrics_reliability": {
            "reliable": True,
            "reviewed_count": 10,
            "labeled_outcome_count": 5,
            "review_precision_bps": 9000,
            "min_reviewed_count": 10,
            "min_labeled_outcome_count": 5,
            "min_review_precision_bps": 8000,
            "reasons": [],
            "summary": "reliable",
        },
    }
    respx.get("https://gateway.test/signal/v1/fraud/release-gate?score_version=1.0").mock(
        return_value=httpx.Response(200, json=gate_body)
    )
    route = respx.put("https://gateway.test/signal/v1/fraud/release-gate").mock(
        return_value=httpx.Response(202, json=gate_body)
    )
    client = GatewayFraudClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token=_api_key(),
    )
    try:
        gate = await client.get_fraud_release_gate_config(score_version="1.0")
        assert gate["config"]["mode"] == "critical_hold"
        updated = await client.set_fraud_release_gate_mode("critical_hold")
        assert updated["metrics_reliability"]["reliable"] is True
        assert json.loads(route.calls.last.request.content.decode("utf-8")) == {
            "mode": "critical_hold"
        }
        with pytest.raises(ValueError, match="release gate mode"):
            await client.set_fraud_release_gate_mode("enforce_all")
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_record_fraud_review_event_allows_only_review_event_types() -> None:
    captured: dict[str, object] = {}

    def handle_event(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            202,
            json={
                "schema_version": 1,
                "tenant_id": "tenant-a",
                "operator_did": "did:example:alpha",
                "score_model_version": "1.0",
                "requested_event_type": "review_outcome_recorded",
                "recorded_event_type": "review_outcome_recorded",
                "review_outcome": "confirmed_risk",
                "signal_code": "PROVIDER_STRIPE_EARLY_FRAUD_WARNING",
                "intent_id": "00000000-0000-4000-8000-000000000123",
                "provider_event_id": "evt_review_signal",
                "accepted": True,
                "friction": {"band": "normal"},
            },
        )

    respx.post(
        "https://gateway.test/signal/v1/operators/did%3Aexample%3Aalpha/review-events"
    ).mock(side_effect=handle_event)
    client = GatewayFraudClient(
        "https://gateway.test",
        "tenant-a",
        static_gateway_bearer_token=_api_key(),
    )
    try:
        result = await client.record_fraud_review_event(
            "did:example:alpha",
            {
                "eventType": "confirmed_risk",
                "signalCode": "PROVIDER_STRIPE_EARLY_FRAUD_WARNING",
                "intentId": "00000000-0000-4000-8000-000000000123",
                "providerEventId": "evt_review_signal",
                "summary": "Developer supplied appeal context",
            },
        )
        assert result["accepted"] is True
        assert result.get("signal_code") == "PROVIDER_STRIPE_EARLY_FRAUD_WARNING"
        assert result.get("intent_id") == "00000000-0000-4000-8000-000000000123"
        assert result.get("provider_event_id") == "evt_review_signal"
        assert captured["body"] == {
            "event_type": "review_outcome_recorded",
            "review_outcome": "confirmed_risk",
            "signal_code": "PROVIDER_STRIPE_EARLY_FRAUD_WARNING",
            "intent_id": "00000000-0000-4000-8000-000000000123",
            "provider_event_id": "evt_review_signal",
            "summary": "Developer supplied appeal context",
        }
        with pytest.raises(ValueError, match="fraud review eventType"):
            await client.record_fraud_review_event(
                "did:example:alpha",
                {
                    "eventType": "settlement_refunded",
                    "summary": "not a review event",
                },
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_service_account_fraud_session_binds_tenant_from_principal() -> None:
    respx.get("https://gateway.test/v1/auth/principal").mock(
        return_value=httpx.Response(200, json={"tenant_id": "realm-z"})
    )
    session = await ServiceAccountFraudSession.open(
        gateway_base_url="https://gateway.test",
        api_key=_api_key(),
    )
    try:
        assert session.fraud.tenant_id == "realm-z"
    finally:
        await session.aclose()
