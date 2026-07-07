from paybond_kit.payment_transport import (
    PAYBOND_PAYMENT_AUTHORIZATION_HEADER,
    format_payment_authorization_value,
    payment_authorization_gateway_header,
    read_fund_payment_transport_headers,
)


def test_payment_authorization_header_name() -> None:
    assert PAYBOND_PAYMENT_AUTHORIZATION_HEADER == "x-paybond-payment-authorization"


def test_format_payment_authorization_value_prefixes_raw_credential() -> None:
    assert format_payment_authorization_value("eyJ0ZXN0IjoidHJ1ZSJ9") == "Payment eyJ0ZXN0IjoidHJ1ZSJ9"


def test_format_payment_authorization_value_preserves_existing_prefix() -> None:
    assert format_payment_authorization_value("Payment eyJ0ZXN0IjoidHJ1ZSJ9") == "Payment eyJ0ZXN0IjoidHJ1ZSJ9"


def test_payment_authorization_gateway_header() -> None:
    assert payment_authorization_gateway_header("eyJ0ZXN0IjoidHJ1ZSJ9") == {
        "x-paybond-payment-authorization": "Payment eyJ0ZXN0IjoidHJ1ZSJ9",
    }


class _FakeHeaders:
    def __init__(self, values: dict[str, list[str]]) -> None:
        self._values = values

    def get_list(self, name: str) -> list[str]:
        return list(self._values.get(name, []))

    def get(self, name: str) -> str | None:
        values = self._values.get(name)
        if not values:
            return None
        return values[0]


def test_read_fund_payment_transport_headers() -> None:
    headers = _FakeHeaders(
        {
            "www-authenticate": [
                'Payment id="abc", realm="api.example.com", method="stripe", intent="charge", request="eyJ0ZXN0IjoidHJ1ZSJ9"'
            ],
            "payment-receipt": ["eyJyZWNlaXB0Ijp0cnVlfQ"],
            "cache-control": ["no-store"],
        }
    )
    assert read_fund_payment_transport_headers(headers) == {
        "www_authenticate": [
            'Payment id="abc", realm="api.example.com", method="stripe", intent="charge", request="eyJ0ZXN0IjoidHJ1ZSJ9"'
        ],
        "payment_receipt": "eyJyZWNlaXB0Ijp0cnVlfQ",
        "cache_control": "no-store",
    }
