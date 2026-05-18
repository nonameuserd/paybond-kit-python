"""A2A discovery client for the public Paybond protocol-trust delegation surface."""

from __future__ import annotations

import asyncio
import random
from typing import Any
from urllib.parse import quote

import httpx


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
        self._base = gateway_base_url.strip().rstrip("/") + "/"
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

        last_exc: BaseException | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.get(url, headers=headers)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt + 1 >= self._max_retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            if response.status_code in (429, 500, 502, 503, 504):
                if attempt + 1 >= self._max_retries:
                    break
                delay = _parse_retry_after(response.headers.get("retry-after"))
                if delay is None:
                    delay = _backoff_seconds(attempt)
                await asyncio.sleep(delay)
                continue
            return response
        if last_exc is not None:
            raise last_exc
        return response

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


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        parsed = float(value.strip())
    except ValueError:
        return None
    if parsed < 0:
        return None
    return min(parsed, 30.0)


def _backoff_seconds(attempt: int) -> float:
    base = 0.2 * (2**attempt)
    jitter = random.random() * 0.1
    return min(base + jitter, 5.0)
