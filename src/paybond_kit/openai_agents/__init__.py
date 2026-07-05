"""OpenAI Agents SDK integration — guard ``FunctionTool`` execution with Paybond middleware."""

from paybond_kit.openai_agents._peer import is_openai_function_tool, openai_agents_runtime_available
from paybond_kit.openai_agents.config import (
    PaybondOpenAIAgentsAdapterOptions,
    PaybondOpenAIAgentsConfig,
    create_openai_agents_adapter,
    create_paybond_openai_agents_config,
    map_paybond_decision_to_openai_tool_guardrail,
    paybond_openai_agents_adapter,
    paybond_openai_agents_run_config,
)
from paybond_kit.openai_agents.sandbox_demo import run_openai_agents_sandbox_demo

__all__ = [
    "PaybondOpenAIAgentsAdapterOptions",
    "PaybondOpenAIAgentsConfig",
    "create_openai_agents_adapter",
    "create_paybond_openai_agents_config",
    "is_openai_function_tool",
    "map_paybond_decision_to_openai_tool_guardrail",
    "openai_agents_runtime_available",
    "paybond_openai_agents_adapter",
    "paybond_openai_agents_run_config",
    "run_openai_agents_sandbox_demo",
]
