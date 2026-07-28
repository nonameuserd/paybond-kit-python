"""Gateway service-account credential helpers."""

from __future__ import annotations

import ipaddress
import os
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
PAYBOND_ALLOW_INSECURE_GATEWAY_ENV: Final[str] = "PAYBOND_ALLOW_INSECURE_GATEWAY"
PaybondEnvironment = Literal["live", "sandbox"]


class InsecureGatewayURLError(ValueError):
    """Raised when a gateway URL does not meet Kit HTTPS requirements."""


def _is_rfc1918_ipv4(addr: ipaddress._BaseAddress) -> bool:
    """True for RFC 1918 private IPv4 ranges (10/8, 172.16/12, 192.168/16)."""
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    first, second = addr.packed[0], addr.packed[1]
    if first == 10:
        return True
    if first == 192 and second == 168:
        return True
    return first == 172 and 16 <= second <= 31


def is_loopback_gateway_host(hostname: str) -> bool:
    """True for loopback hostnames only (``localhost``, ``127/8``, ``::1``)."""
    lowered = hostname.strip().lower()
    if lowered in LOCAL_GATEWAY_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(lowered)
    except ValueError:
        return lowered.startswith("127.")
    return bool(addr.is_loopback)


def is_local_gateway_host(hostname: str) -> bool:
    """
    Whether the host is loopback or RFC 1918 private IPv4.

    Cleartext ``http://`` is permitted for loopback by default. RFC 1918
    cleartext requires an explicit opt-in (see :func:`normalize_gateway_base_url`).
    """
    lowered = hostname.strip().lower()
    if is_loopback_gateway_host(lowered):
        return True
    try:
        addr = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return _is_rfc1918_ipv4(addr)


def _allow_insecure_private_network(*, allow_insecure_private_network: bool = False) -> bool:
    if allow_insecure_private_network:
        return True
    raw = os.environ.get(PAYBOND_ALLOW_INSECURE_GATEWAY_ENV, "").strip().lower()
    return raw in {"1", "true", "yes"}


def normalize_gateway_base_url(
    url: str,
    *,
    allow_insecure_private_network: bool = False,
) -> str:
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
    if scheme == "http" and is_loopback_gateway_host(hostname):
        return trimmed.rstrip("/")
    if (
        scheme == "http"
        and _allow_insecure_private_network(
            allow_insecure_private_network=allow_insecure_private_network
        )
        and is_local_gateway_host(hostname)
    ):
        return trimmed.rstrip("/")
    raise InsecureGatewayURLError(
        "gateway URL must use https:// (http:// is allowed only for loopback; "
        f"set {PAYBOND_ALLOW_INSECURE_GATEWAY_ENV}=1 for private-network cleartext)"
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
