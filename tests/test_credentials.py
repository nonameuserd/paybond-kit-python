from __future__ import annotations

import pytest

from paybond_kit import DEFAULT_PAYBOND_GATEWAY_BASE_URL
from paybond_kit.credentials import GatewayAuthError, _normalize_expected_environment


def test_default_gateway_base_url_is_hosted_gateway() -> None:
    assert DEFAULT_PAYBOND_GATEWAY_BASE_URL == "https://api.paybond.ai"


def test_expected_environment_rejects_unknown_value() -> None:
    with pytest.raises(GatewayAuthError, match="expected_environment"):
        _normalize_expected_environment("dev")  # type: ignore[arg-type]
