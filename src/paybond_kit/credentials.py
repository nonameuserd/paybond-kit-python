"""Gateway service-account flows: API key exchange, Harbor JWT cache, tenant derivation."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from urllib.parse import urljoin

import httpx

if TYPE_CHECKING:
    from paybond_kit.harbor import HarborClient


class GatewayAuthError(RuntimeError):
    """Raised when the gateway rejects credentials or returns an unexpected harbor-access payload."""

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


_DEFAULT_HARBOR_ACCESS_PATH: Final[str] = "/v1/auth/harbor-access"


def _normalize_base(url: str) -> str:
    return url.strip().rstrip("/")


@dataclass
class HarborAccessToken:
    """Short-lived Harbor JWT minted by the gateway."""

    access_token: str
    expires_in: int
    tenant_id: str


class GatewayHarborTokenProvider:
    """
    Exchanges a ``paybond_sk_`` service-account API key for short-lived Harbor JWTs via
    ``POST /v1/auth/harbor-access``.

    Tenant realm (``tid`` claim / gateway principal) is taken from the JSON response so SDK users
    do not supply a separate ``PAYBOND_TENANT_ID`` for the happy path.

    Tokens are refreshed under a lock with a configurable skew before ``exp`` so concurrent Harbor
    calls do not race on expiry.
    """

    def __init__(
        self,
        *,
        gateway_base_url: str,
        api_key: str,
        harbor_access_path: str = _DEFAULT_HARBOR_ACCESS_PATH,
        clock_skew_seconds: float = 90.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._gateway = _normalize_base(gateway_base_url)
        self._api_key = api_key.strip()
        self._path = harbor_access_path if harbor_access_path.startswith("/") else f"/{harbor_access_path}"
        self._skew = max(0.0, clock_skew_seconds)
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=30.0)
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._tenant_id: str | None = None
        self._not_after: float = 0.0

    @property
    def tenant_id(self) -> str | None:
        return self._tenant_id

    async def ensure_initial(self) -> str:
        """Perform the first token exchange and return the tenant realm id."""
        async with self._lock:
            await self._refresh_locked(force=True)
        if not self._tenant_id:
            raise GatewayAuthError(
                "harbor-access response missing tenant_id; upgrade gateway or pass tenant explicitly"
            )
        return self._tenant_id

    async def bearer(self) -> str:
        """Return a valid Harbor JWT, refreshing when near expiry."""
        async with self._lock:
            await self._refresh_locked(force=False)
        if not self._token:
            raise GatewayAuthError("harbor-access did not return access_token")
        return self._token

    async def force_rotate(self) -> None:
        """Invalidate the cached JWT and obtain a new one (credential rotation drills)."""
        async with self._lock:
            await self._refresh_locked(force=True)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def _refresh_locked(self, *, force: bool) -> None:
        now = time.monotonic()
        if not force and self._token and now < self._not_after:
            return
        url = urljoin(self._gateway + "/", self._path.lstrip("/"))
        response = await self._http.post(
            url,
            headers={
                "authorization": f"Bearer {self._api_key}",
                "accept": "application/json",
            },
        )
        if response.status_code >= 400:
            raise GatewayAuthError(
                f"harbor-access HTTP {response.status_code}",
                status_code=response.status_code,
                body_text=response.text,
            )
        body: dict[str, Any] = response.json()
        token = str(body.get("access_token", "")).strip()
        if not token:
            raise GatewayAuthError(
                "harbor-access JSON missing access_token",
                body_text=response.text,
            )
        exp_in = int(body.get("expires_in", 0) or 0)
        if exp_in <= 0:
            raise GatewayAuthError(
                "harbor-access JSON missing or invalid expires_in",
                body_text=response.text,
            )
        tenant_raw = body.get("tenant_id")
        if tenant_raw is not None:
            t = str(tenant_raw).strip()
            if t:
                self._tenant_id = t
        if not self._tenant_id:
            raise GatewayAuthError(
                "harbor-access response missing tenant_id; upgrade gateway (PAYBOND-V1-008) "
                "or configure an older gateway with explicit tenant binding",
                body_text=response.text,
            )
        self._token = token
        self._not_after = now + max(1.0, float(exp_in) - self._skew)


@dataclass
class ServiceAccountHarborSession:
    """
    A Harbor client plus gateway token lifecycle for one service account.

    Use :meth:`open` to construct; always :meth:`aclose` when done to release HTTP connections.
    """

    harbor: HarborClient
    _tokens: GatewayHarborTokenProvider

    @classmethod
    async def open(
        cls,
        *,
        gateway_base_url: str,
        api_key: str,
        harbor_base_url: str,
        harbor_access_path: str = _DEFAULT_HARBOR_ACCESS_PATH,
        clock_skew_seconds: float = 90.0,
        max_retries: int = 3,
    ) -> ServiceAccountHarborSession:
        from paybond_kit.harbor import HarborClient

        prov = GatewayHarborTokenProvider(
            gateway_base_url=gateway_base_url,
            api_key=api_key,
            harbor_access_path=harbor_access_path,
            clock_skew_seconds=clock_skew_seconds,
        )
        tenant = await prov.ensure_initial()
        client = HarborClient(
            harbor_base_url,
            tenant,
            harbor_bearer_supplier=prov.bearer,
            max_retries=max_retries,
        )
        return cls(harbor=client, _tokens=prov)

    async def rotate_harbor_token(self) -> None:
        """Force a new Harbor JWT from the gateway (key rotation / incident response)."""
        await self._tokens.force_rotate()

    async def aclose(self) -> None:
        await self.harbor.aclose()
        await self._tokens.aclose()
