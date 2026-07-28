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
    """Map adapter / default_deny posture to AI SDK adapter options.

    When ``default_deny`` is true and the adapter flag is unset, provider-executed
    tools are denied so policy posture matches runtime (they never reach the
    interceptor). Explicit ``adapter.deny_provider_executed_tools: false`` opts out.
    """
    deny = None if document.adapter is None else document.adapter.deny_provider_executed_tools
    if deny is True:
        return PaybondPolicyAdapterOptions(deny_provider_executed_tools=True)
    if deny is False:
        return PaybondPolicyAdapterOptions()
    if document.default_deny is True:
        return PaybondPolicyAdapterOptions(deny_provider_executed_tools=True)
    return PaybondPolicyAdapterOptions()
