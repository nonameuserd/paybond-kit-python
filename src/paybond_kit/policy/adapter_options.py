"""Map paybond.policy.yaml adapter settings to framework runner options."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from paybond_kit.policy.schema import PaybondPolicyDocumentV1


@dataclass(frozen=True, slots=True)
class PaybondPolicyAdapterOptions:
    deny_provider_executed_tools: bool | None = None

    def to_vercel_options(self) -> dict[str, Any]:
        if self.deny_provider_executed_tools is True:
            return {"denyProviderExecutedTools": True}
        return {}


def policy_to_adapter_options(document: PaybondPolicyDocumentV1) -> PaybondPolicyAdapterOptions:
    """Map policy adapter.deny_provider_executed_tools to AI SDK adapter options."""
    if document.adapter is None or document.adapter.deny_provider_executed_tools is not True:
        return PaybondPolicyAdapterOptions()
    return PaybondPolicyAdapterOptions(deny_provider_executed_tools=True)
