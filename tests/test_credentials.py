from __future__ import annotations

import pytest

from paybond_kit import DEFAULT_PAYBOND_GATEWAY_BASE_URL
from paybond_kit.credentials import (
    GatewayAuthError,
    InsecureGatewayURLError,
    _normalize_expected_environment,
    is_local_gateway_host,
    normalize_gateway_base_url,
)


def test_default_gateway_base_url_is_hosted_gateway() -> None:
    assert DEFAULT_PAYBOND_GATEWAY_BASE_URL == "https://api.paybond.ai"


def test_normalize_gateway_base_url_accepts_https() -> None:
    assert normalize_gateway_base_url("https://api.paybond.ai/") == "https://api.paybond.ai"


def test_normalize_gateway_base_url_allows_local_http() -> None:
    assert normalize_gateway_base_url("http://127.0.0.1:18089") == "http://127.0.0.1:18089"
    assert normalize_gateway_base_url("http://localhost:18089") == "http://localhost:18089"
    with pytest.raises(InsecureGatewayURLError):
        normalize_gateway_base_url("http://192.168.1.5:18089")
    assert (
        normalize_gateway_base_url(
            "http://192.168.1.5:18089",
            allow_insecure_private_network=True,
        )
        == "http://192.168.1.5:18089"
    )


def test_normalize_gateway_base_url_rejects_insecure_remote_http() -> None:
    with pytest.raises(InsecureGatewayURLError, match="https://"):
        normalize_gateway_base_url("http://api.paybond.ai")


def test_is_local_gateway_host() -> None:
    assert is_local_gateway_host("localhost")
    assert is_local_gateway_host("127.0.0.1")
    assert is_local_gateway_host("10.0.0.5")
    assert is_local_gateway_host("172.16.1.1")
    assert is_local_gateway_host("192.168.0.42")
    assert not is_local_gateway_host("api.paybond.ai")
    assert not is_local_gateway_host("172.15.0.1")


def test_is_local_gateway_host_rejects_link_local_and_ipv6_private() -> None:
    # Cleartext http is only for loopback + RFC 1918 IPv4, matching the TS twin.
    # Link-local, CGNAT, and IPv6 ULA/link-local must fall back to https.
    assert not is_local_gateway_host("169.254.1.1")
    assert not is_local_gateway_host("100.64.0.1")
    assert not is_local_gateway_host("fc00::1")
    assert not is_local_gateway_host("fe80::1")


def test_normalize_gateway_base_url_rejects_link_local_http() -> None:
    with pytest.raises(InsecureGatewayURLError, match="https://"):
        normalize_gateway_base_url("http://169.254.1.1:18089")


def test_expected_environment_rejects_unknown_value() -> None:
    with pytest.raises(GatewayAuthError, match="expected_environment"):
        _normalize_expected_environment("dev")  # type: ignore[arg-type]
