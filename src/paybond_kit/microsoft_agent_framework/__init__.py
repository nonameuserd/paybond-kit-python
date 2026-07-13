"""Microsoft Agent Framework integration — function middleware spend gates for Paybond Harbor."""

from paybond_kit.microsoft_agent_framework._peer import (
    microsoft_agent_framework_runtime_available,
)
from paybond_kit.microsoft_agent_framework.config import (
    PaybondMicrosoftAgentFrameworkConfig,
    create_paybond_microsoft_agent_framework_config,
    create_paybond_microsoft_agent_framework_middleware,
    process_paybond_function_invocation,
)
from paybond_kit.microsoft_agent_framework.sandbox_demo import (
    run_microsoft_agent_framework_sandbox_demo,
)

__all__ = [
    "PaybondMicrosoftAgentFrameworkConfig",
    "create_paybond_microsoft_agent_framework_config",
    "create_paybond_microsoft_agent_framework_middleware",
    "microsoft_agent_framework_runtime_available",
    "process_paybond_function_invocation",
    "run_microsoft_agent_framework_sandbox_demo",
]
