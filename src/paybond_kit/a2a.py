"""A2A discovery client for the public Paybond protocol-trust delegation surface."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from paybond_kit.credentials import normalize_gateway_base_url
from paybond_kit.gateway_retry import httpx_with_gateway_retries


class A2AHttpError(RuntimeError):
    """Raised for non-success HTTP status codes from gateway A2A discovery routes."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        url: str,
        body_text: str,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.url = url
        self.body_text = body_text


class GatewayA2AClient:
    """Async reader for the gateway's published A2A agent card and task contracts."""

    def __init__(
        self,
        gateway_base_url: str,
        *,
        static_gateway_bearer_token: str | None = None,
        max_retries: int = 3,
        request_timeout_sec: float = 30.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base = normalize_gateway_base_url(gateway_base_url) + "/"
        self._bearer = (
            static_gateway_bearer_token.strip()
            if static_gateway_bearer_token and static_gateway_bearer_token.strip()
            else None
        )
        self._max_retries = max(1, int(max_retries))
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=request_timeout_sec)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _get_json_with_retries(self, path: str) -> httpx.Response:
        url = f"{self._base}{path.lstrip('/')}"
        headers = {"accept": "application/json"}
        if self._bearer is not None:
            headers["authorization"] = f"Bearer {self._bearer}"

        return await httpx_with_gateway_retries(
            lambda: self._client.get(url, headers=headers),
            max_retries=self._max_retries,
        )

    async def get_agent_card(self) -> dict[str, Any]:
        path = ".well-known/agent-card.json"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise A2AHttpError(
                f"A2A agent card HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("A2A agent card response was not a JSON object")
        return body

    async def get_task_contracts(self) -> dict[str, Any]:
        path = "protocol/v2/a2a/task-contracts"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise A2AHttpError(
                f"A2A task contracts HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("A2A task contracts response was not a JSON object")
        return body

    async def get_task_contract(self, contract_id: str) -> dict[str, Any]:
        path = f"protocol/v2/a2a/task-contracts/{quote(contract_id, safe='')}"
        url = f"{self._base}{path}"
        response = await self._get_json_with_retries(path)
        if response.status_code >= 400:
            raise A2AHttpError(
                f"A2A task contract HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                url=url,
                body_text=response.text,
            )
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("A2A task contract response was not a JSON object")
        return body
