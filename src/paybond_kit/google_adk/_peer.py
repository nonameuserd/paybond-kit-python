"""Lazy Google ADK peer imports — importing paybond_kit.google_adk must not require google-adk."""

from __future__ import annotations

import importlib
from typing import Any


def google_adk_runtime_available() -> bool:
    """Return True when the optional Google ADK dependency is importable."""

    try:
        importlib.import_module("google.adk")
    except ImportError:
        return False
    return True


def _require_google_adk() -> Any:
    try:
        return importlib.import_module("google.adk")
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "google-adk is required for paybond_kit.google_adk. "
            'Install with `pip install "paybond-kit[google-adk]"`.'
        ) from exc


def _require_function_tool() -> Any:
    try:
        module = importlib.import_module("google.adk.tools")
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "google-adk is required for paybond_kit.google_adk. "
            'Install with `pip install "paybond-kit[google-adk]"`.'
        ) from exc
    function_tool = getattr(module, "FunctionTool", None)
    if function_tool is None:
        raise ImportError(
            "google.adk.tools.FunctionTool is unavailable; upgrade google-adk "
            'or install with `pip install "paybond-kit[google-adk]"`.'
        )
    return function_tool


def is_google_adk_function_tool(value: Any) -> bool:
    """Return True when ``value`` is a Google ADK ``FunctionTool`` instance."""

    if not google_adk_runtime_available():
        return False
    try:
        function_tool = _require_function_tool()
    except ImportError:
        return False
    return isinstance(value, function_tool)
