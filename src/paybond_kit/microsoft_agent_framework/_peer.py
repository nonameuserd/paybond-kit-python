"""Lazy Microsoft Agent Framework peer imports — importing this package must not require agent-framework-core."""

from __future__ import annotations

import importlib
from typing import Any


def microsoft_agent_framework_runtime_available() -> bool:
    """Return True when the optional ``agent_framework`` dependency is importable."""

    try:
        importlib.import_module("agent_framework")
    except ImportError:
        return False
    return True


def _require_agent_framework() -> Any:
    try:
        return importlib.import_module("agent_framework")
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "agent-framework-core is required for paybond_kit.microsoft_agent_framework. "
            'Install with `pip install "paybond-kit[microsoft-agent-framework]"`.'
        ) from exc


def _require_function_middleware() -> Any:
    module = _require_agent_framework()
    function_middleware = getattr(module, "FunctionMiddleware", None)
    if function_middleware is None:
        raise ImportError(
            "agent_framework.FunctionMiddleware is unavailable; upgrade agent-framework-core "
            'or install with `pip install "paybond-kit[microsoft-agent-framework]"`.'
        )
    return function_middleware
