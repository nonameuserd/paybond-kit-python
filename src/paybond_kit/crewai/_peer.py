"""Lazy CrewAI peer imports — importing paybond_kit.crewai must not require crewai installed."""

from __future__ import annotations

import importlib
from typing import Any


def crewai_runtime_available() -> bool:
    """Return True when the optional CrewAI dependency is importable."""

    try:
        importlib.import_module("crewai.tools")
    except ImportError:
        return False
    return True


def _require_crewai_tools() -> Any:
    try:
        return importlib.import_module("crewai.tools")
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "crewai is required for paybond_kit.crewai. "
            'Install with `pip install "paybond-kit[crewai]"`.'
        ) from exc


def is_crewai_base_tool(value: Any) -> bool:
    """Return True when ``value`` is a CrewAI ``BaseTool`` instance."""

    if not crewai_runtime_available():
        return False
    base_tool = getattr(_require_crewai_tools(), "BaseTool", None)
    if base_tool is None:
        return False
    return isinstance(value, base_tool)
