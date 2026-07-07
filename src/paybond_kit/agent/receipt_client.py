from __future__ import annotations

from typing import TYPE_CHECKING, Any

from paybond_kit.agent_receipt import verify_agent_receipt_v1

if TYPE_CHECKING:
    from paybond_kit.agent.facade import PaybondAgentResult
    from paybond_kit.paybond import Paybond


class PaybondAgentFacade:
    """Callable quickstart plus tenant-bound agent receipt fetch and verify helpers."""

    def __init__(self, host: Paybond, protocol: Any) -> None:
        self._host = host
        self._protocol = protocol

    async def __call__(
        self,
        *,
        policy: Any,
        tools: Any,
        framework: Any | None = None,
        bootstrap: Any | None = None,
        attach: Any | None = None,
        run_id: str | None = None,
        validate_policy: bool | dict[str, Any] | None = None,
    ) -> PaybondAgentResult:
        from paybond_kit.agent.facade import create_paybond_agent

        return await create_paybond_agent(
            self._host,
            policy=policy,
            tools=tools,
            framework=framework,
            bootstrap=bootstrap,
            attach=attach,
            run_id=run_id,
            validate_policy=validate_policy,
        )

    async def get_receipt(
        self,
        *,
        receipt_id: str | None = None,
        intent_id: str | None = None,
        tool_call_id: str | None = None,
    ) -> dict[str, Any]:
        if receipt_id and receipt_id.strip():
            return await self._protocol.get_agent_receipt_v1_by_id(receipt_id.strip())
        if intent_id and intent_id.strip() and tool_call_id and tool_call_id.strip():
            return await self._protocol.get_agent_receipt_v1_by_intent_tool_call(
                intent_id=intent_id.strip(),
                tool_call_id=tool_call_id.strip(),
            )
        raise ValueError("get_receipt requires receipt_id or intent_id + tool_call_id")

    async def verify_receipt(
        self,
        receipt: dict[str, Any],
        *,
        offline: bool = False,
    ) -> dict[str, Any] | dict[str, Any]:
        if offline:
            return verify_agent_receipt_v1(receipt)
        return await self._protocol.verify_agent_receipt_v1(receipt)
