"""Lazy Pydantic AI peer imports — importing paybond_kit.pydantic_ai must not require pydantic_ai installed."""

from __future__ import annotations

import importlib
from typing import Any


def pydantic_ai_runtime_available() -> bool:
    """Return True when the optional Pydantic AI dependency is importable."""

    try:
        importlib.import_module("pydantic_ai")
    except ImportError:
        return False
    return True


def _require_pydantic_ai() -> Any:
    try:
        return importlib.import_module("pydantic_ai")
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "pydantic-ai is required for paybond_kit.pydantic_ai. "
            'Install with `pip install "paybond-kit[pydantic-ai]"`.'
        ) from exc


def is_pydantic_ai_tool(value: Any) -> bool:
    """Return True when ``value`` is a Pydantic AI ``Tool`` instance."""

    if not pydantic_ai_runtime_available():
        return False
    tool_cls = getattr(_require_pydantic_ai(), "Tool", None)
    if tool_cls is None:
        return False
    return isinstance(value, tool_cls)
