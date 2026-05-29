"""Gateway service-account credential helpers."""

from __future__ import annotations

from typing import Final, Literal


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
PaybondEnvironment = Literal["live", "sandbox"]


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
