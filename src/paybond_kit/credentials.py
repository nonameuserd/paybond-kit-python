"""Gateway service-account credential helpers."""

from __future__ import annotations

import ipaddress
from typing import Final, Literal
from urllib.parse import urlparse


class GatewayAuthError(RuntimeError):
    """Raised when Gateway rejects credentials or returns an unexpected tenant-principal payload."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body_text: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body_text = body_text


DEFAULT_PAYBOND_GATEWAY_BASE_URL: Final[str] = "https://api.paybond.ai"
LOCAL_GATEWAY_HOSTS: Final[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "::1"})
PaybondEnvironment = Literal["live", "sandbox"]


class InsecureGatewayURLError(ValueError):
    """Raised when a gateway URL does not meet Kit HTTPS requirements."""


def is_local_gateway_host(hostname: str) -> bool:
    lowered = hostname.strip().lower()
    if lowered in LOCAL_GATEWAY_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


def normalize_gateway_base_url(url: str) -> str:
    """Return a normalized gateway base URL or raise InsecureGatewayURLError."""
    trimmed = url.strip()
    if not trimmed:
        raise InsecureGatewayURLError("gateway URL is required")
    parsed = urlparse(trimmed)
    if not parsed.scheme or not parsed.netloc:
        raise InsecureGatewayURLError("gateway URL must be an absolute URL")
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    if scheme == "https":
        return trimmed.rstrip("/")
    if scheme == "http" and is_local_gateway_host(hostname):
        return trimmed.rstrip("/")
    raise InsecureGatewayURLError(
        "gateway URL must use https:// (http:// is allowed only for loopback and private networks)"
    )


def _normalize_expected_environment(
    expected_environment: PaybondEnvironment | None,
) -> PaybondEnvironment | None:
    if expected_environment is None:
        return None
    env = str(expected_environment).strip()
    if env not in ("live", "sandbox"):
        raise GatewayAuthError(
            f"expected_environment must be 'live' or 'sandbox', got {expected_environment!r}"
        )
    return env  # type: ignore[return-value]


def _assert_expected_environment(
    *,
    source: str,
    body: dict[str, object],
    expected_environment: PaybondEnvironment | None,
    body_text: str | None = None,
) -> None:
    if expected_environment is None:
        return
    actual = str(body.get("environment", "")).strip()
    if not actual:
        raise GatewayAuthError(
            f"{source} response missing environment",
            body_text=body_text,
        )
    if actual != expected_environment:
        raise GatewayAuthError(
            f"{source} environment mismatch: expected={expected_environment} gateway={actual}",
            body_text=body_text,
        )
