from __future__ import annotations

from paybond_kit.dev.trace_security_headers import (
    DEV_TRACE_SECURITY_HEADERS,
    dev_trace_response_headers,
)


def test_dev_trace_security_headers_include_baseline_hardening() -> None:
    assert DEV_TRACE_SECURITY_HEADERS["x-content-type-options"] == "nosniff"
    assert DEV_TRACE_SECURITY_HEADERS["x-frame-options"] == "DENY"
    assert DEV_TRACE_SECURITY_HEADERS["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in DEV_TRACE_SECURITY_HEADERS["content-security-policy"]
    assert "connect-src 'self'" in DEV_TRACE_SECURITY_HEADERS["content-security-policy"]


def test_dev_trace_response_headers_merge_content_type() -> None:
    headers = dev_trace_response_headers("application/json; charset=utf-8")
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert headers["x-content-type-options"] == "nosniff"
