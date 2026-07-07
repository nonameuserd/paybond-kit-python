"""Payment Auth transport headers for MPP funding through the Paybond Gateway."""

from __future__ import annotations

import re
from typing import Final, TypedDict

# Gateway-facing Payment Auth credential header (avoids clashing with Bearer auth).
PAYBOND_PAYMENT_AUTHORIZATION_HEADER: Final = "x-paybond-payment-authorization"

PAYMENT_TRANSPORT_RESPONSE_HEADERS: Final[tuple[str, ...]] = (
    "www-authenticate",
    "payment-receipt",
    "cache-control",
)

_PAYMENT_PREFIX_RE = re.compile(r"^payment\s+", re.IGNORECASE)


def format_payment_authorization_value(credential: str) -> str:
    """
    Normalize a Payment Auth credential for HTTP headers.

    Accepts either a raw credential token or a value already prefixed with ``Payment ``.
    """
    trimmed = credential.strip()
    if not trimmed:
        raise ValueError("payment authorization credential must be non-empty")
    if _PAYMENT_PREFIX_RE.match(trimmed):
        return trimmed
    return f"Payment {trimmed}"


def payment_authorization_gateway_header(credential: str) -> dict[str, str]:
    """Header entry for gateway Harbor fund/verify retries."""
    return {
        PAYBOND_PAYMENT_AUTHORIZATION_HEADER: format_payment_authorization_value(credential),
    }


def append_direct_harbor_payment_authorization(
    headers: list[tuple[str, str]],
    credential: str,
) -> None:
    """Append ``Authorization: Payment …`` for direct Harbor calls that already carry Bearer auth."""
    headers.append(("authorization", format_payment_authorization_value(credential)))


class FundPaymentTransportHeaders(TypedDict, total=False):
    www_authenticate: list[str]
    payment_receipt: str
    cache_control: str


def read_fund_payment_transport_headers(headers: object) -> FundPaymentTransportHeaders:
    """Read Payment Auth transport headers from a fund response."""
    get_list = getattr(headers, "get_list", None)
    get = getattr(headers, "get", None)
    if get_list is None or get is None:
        return {}

    www_authenticate = [value for value in get_list("www-authenticate") if value.strip()]
    out: FundPaymentTransportHeaders = {}
    if www_authenticate:
        out["www_authenticate"] = www_authenticate
    payment_receipt = get("payment-receipt")
    if isinstance(payment_receipt, str) and payment_receipt.strip():
        out["payment_receipt"] = payment_receipt
    cache_control = get("cache-control")
    if isinstance(cache_control, str) and cache_control.strip():
        out["cache_control"] = cache_control
    return out
