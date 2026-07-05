"""Lazy OpenAI Agents SDK peer imports — importing paybond_kit.openai_agents must not require openai-agents."""

from __future__ import annotations

import importlib
from typing import Any


def openai_agents_runtime_available() -> bool:
    """Return True when the optional OpenAI Agents SDK dependency is importable."""

    try:
        importlib.import_module("agents")
    except ImportError:
        return False
    return True


def _require_openai_agents() -> Any:
    try:
        return importlib.import_module("agents")
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "openai-agents is required for paybond_kit.openai_agents. "
            'Install with `pip install "paybond-kit[openai-agents]"`.'
        ) from exc


def is_openai_function_tool(value: Any) -> bool:
    """Return True when ``value`` is an OpenAI Agents SDK ``FunctionTool`` instance."""

    if not openai_agents_runtime_available():
        return False
    function_tool = getattr(_require_openai_agents(), "FunctionTool", None)
    if function_tool is None:
        return False
    return isinstance(value, function_tool)
