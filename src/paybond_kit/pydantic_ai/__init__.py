"""Pydantic AI integration — guard ``Tool`` / callable execution with Paybond middleware."""

from paybond_kit.pydantic_ai._peer import pydantic_ai_runtime_available
from paybond_kit.pydantic_ai.config import PaybondPydanticAIConfig, create_paybond_pydantic_ai_config
from paybond_kit.pydantic_ai.sandbox_demo import run_pydantic_ai_sandbox_demo

__all__ = [
    "PaybondPydanticAIConfig",
    "create_paybond_pydantic_ai_config",
    "pydantic_ai_runtime_available",
    "run_pydantic_ai_sandbox_demo",
]
