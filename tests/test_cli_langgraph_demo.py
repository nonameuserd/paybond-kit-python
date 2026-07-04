from __future__ import annotations

import io

import pytest

from paybond_kit.cli.router import run_cli
from paybond_kit.langgraph_hooks import langgraph_runtime_available


def test_langgraph_runtime_available_matches_import() -> None:
    try:
        import langchain_core.messages  # noqa: F401
        import langgraph  # noqa: F401

        expected = True
    except ImportError:
        expected = False
    assert langgraph_runtime_available() is expected


@pytest.mark.asyncio
async def test_langgraph_smoke_fails_fast_without_optional_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "paybond_kit.langgraph_hooks.langgraph_runtime_available",
        lambda: False,
    )
    stderr = io.StringIO()
    code = await run_cli(
        [
            "agent",
            "demo",
            "langgraph",
            "smoke",
            "--operation",
            "paid-tool",
            "--requested-spend-cents",
            "100",
            "--evidence-preset",
            "cost_and_completion",
        ],
        stderr=stderr,
    )
    assert code != 0
    message = stderr.getvalue()
    assert "langgraph extra" in message
    assert 'paybond-kit[langgraph]' in message
