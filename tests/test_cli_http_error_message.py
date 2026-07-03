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


def test_summarize_gateway_http_error_redacts_cloudflare_payload() -> None:
    message, details = summarize_gateway_http_error(502, CLOUDFLARE_502)
    assert message == "Gateway unavailable (HTTP 502): Bad gateway. Retry after 60 seconds."
    assert "ray_id" not in message
    assert "api.paybond.ai" not in message
    assert details == {"gateway_status": 502, "retry_after": 60}


def test_format_sdk_http_error_message_for_sandbox_bootstrap() -> None:
    raw = f"Gateway sandbox guardrail bootstrap HTTP 502: {CLOUDFLARE_502}"
    message = format_sdk_http_error_message(raw, 502, CLOUDFLARE_502)
    assert message == (
        "Gateway sandbox guardrail bootstrap: "
        "Gateway unavailable (HTTP 502): Bad gateway. Retry after 60 seconds."
    )


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
        "Gateway sandbox guardrail evidence: "
        "Gateway unavailable (HTTP 502): Bad gateway. Retry after 60 seconds."
    )
    assert "cloudflare.com" not in message


def test_resolve_cli_gateway_error_message_from_legacy_embedded_body() -> None:
    legacy = RuntimeError(f"Gateway sandbox guardrail evidence HTTP 502: {CLOUDFLARE_502}")
    message = resolve_cli_gateway_error_message(legacy)
    assert "cloudflare.com" not in message
    assert "Retry after 60 seconds" in message
