"""CrewAI integration — guard ``@tool`` / ``BaseTool`` execution with Paybond middleware."""

from paybond_kit.crewai._peer import crewai_runtime_available
from paybond_kit.crewai.config import PaybondCrewAIConfig, create_paybond_crewai_config
from paybond_kit.crewai.sandbox_demo import run_crewai_sandbox_demo

__all__ = [
    "PaybondCrewAIConfig",
    "create_paybond_crewai_config",
    "crewai_runtime_available",
    "run_crewai_sandbox_demo",
]
