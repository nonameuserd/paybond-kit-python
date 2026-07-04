from paybond_kit.cli.http_error_message import (
    format_sdk_http_error_message,
    resolve_cli_gateway_error_message,
    summarize_gateway_http_error,
)
from paybond_kit.harbor import HarborHttpError

CLOUDFLARE_502 = """{
  "title": "Error 502: Bad gateway",
  "status": 502,
  "cloudflare_error": true,
  "retry_after": 60,
  "ray_id": "a1538c5f4cc5c6f0",
  "zone": "api.paybond.ai"
}"""

HARBOR_EVIDENCE_REJECT = """{
  "error": {
    "code": "harbor_evidence_failed",
    "message": "sandbox guardrail Harbor evidence rejected: predicate evaluation error: missing key \\"status\\"",
    "harbor_status": 422,
    "harbor_code": "predicate_error"
  }
}"""


def test_summarize_gateway_http_error_redacts_cloudflare_payload() -> None:
    message, details = summarize_gateway_http_error(502, CLOUDFLARE_502)
    assert message == (
        "gateway edge error (HTTP 502); upstream response was masked by the edge proxy. "
        "Retry after 60 seconds"
    )
    assert "ray_id" not in message
    assert "api.paybond.ai" not in message
    assert "Bad gateway" not in message
    assert details == {"gateway_status": 502, "cloudflare_error": True, "retry_after": 60}


def test_summarize_gateway_http_error_surfaces_harbor_rejection() -> None:
    message, details = summarize_gateway_http_error(422, HARBOR_EVIDENCE_REJECT)
    assert message.startswith("sandbox guardrail Harbor evidence rejected")
    assert details["harbor_rejection"] is True
    assert details["harbor_code"] == "predicate_error"


def test_format_sdk_http_error_message_for_harbor_rejection() -> None:
    raw = f"Gateway sandbox guardrail evidence HTTP 422: {HARBOR_EVIDENCE_REJECT}"
    message = format_sdk_http_error_message(raw, 422, HARBOR_EVIDENCE_REJECT)
    assert message.startswith("sandbox guardrail Harbor evidence rejected")
    assert "Gateway sandbox guardrail evidence HTTP" not in message


def test_format_sdk_http_error_message_for_sandbox_bootstrap_cloudflare() -> None:
    raw = f"Gateway sandbox guardrail bootstrap HTTP 502: {CLOUDFLARE_502}"
    message = format_sdk_http_error_message(raw, 502, CLOUDFLARE_502)
    assert message == (
        "sandbox guardrail Harbor bootstrap rejected "
        "(gateway unavailable; check sandbox guardrail bootstrap inputs)"
    )


def test_format_sdk_http_error_message_for_generic_gateway_cloudflare() -> None:
    raw = f"Gateway intent create HTTP 502: {CLOUDFLARE_502}"
    message = format_sdk_http_error_message(raw, 502, CLOUDFLARE_502)
    assert message == (
        "Gateway intent create: gateway edge error (HTTP 502); "
        "upstream response was masked by the edge proxy. Retry after 60 seconds"
    )
    assert "Bad gateway" not in message


def test_resolve_cli_gateway_error_message_from_harbor_cause() -> None:
    harbor = HarborHttpError(
        f"Gateway sandbox guardrail evidence HTTP 502: {CLOUDFLARE_502}",
        status_code=502,
        url="https://api.paybond.ai/v1/sandbox/guardrails/x/evidence",
        body_text=CLOUDFLARE_502,
    )
    try:
        raise harbor
    except HarborHttpError as exc:
        wrapper = RuntimeError("auto-evidence submission failed")
        wrapper.__cause__ = exc
        message = resolve_cli_gateway_error_message(wrapper)
    assert message == (
        "sandbox guardrail Harbor evidence rejected "
        "(gateway unavailable; check --result-body includes top-level status and cost_cents)"
    )
    assert "cloudflare.com" not in message
    assert "Bad gateway" not in message


def test_resolve_cli_gateway_error_message_from_legacy_embedded_body() -> None:
    legacy = RuntimeError(f"Gateway sandbox guardrail evidence HTTP 502: {CLOUDFLARE_502}")
    message = resolve_cli_gateway_error_message(legacy)
    assert message.startswith("sandbox guardrail Harbor evidence rejected")
    assert "Bad gateway" not in message
