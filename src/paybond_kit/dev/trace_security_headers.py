"""Security headers applied to every dev trace dashboard HTTP response."""

from __future__ import annotations

from typing import Final

DEV_TRACE_SECURITY_HEADERS: Final[dict[str, str]] = {
    "cache-control": "no-store",
    "content-security-policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


def dev_trace_response_headers(content_type: str) -> dict[str, str]:
    """Merge dev trace security headers with a response content type."""
    return {**DEV_TRACE_SECURITY_HEADERS, "content-type": content_type}
