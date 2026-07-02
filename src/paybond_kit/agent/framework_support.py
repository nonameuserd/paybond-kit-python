"""Framework availability helpers shared across agent facade and guarded agent."""

from __future__ import annotations

from typing import Final

TYPESCRIPT_ONLY_FRAMEWORK_DOCS: Final[dict[str, str]] = {
    "vercel-ai": "https://docs.paybond.ai/kit/vercel-ai",
    "openai-agents": "https://docs.paybond.ai/kit/openai-agents",
}


def raise_typescript_only_framework_error(framework: str) -> None:
    """Raise when a TypeScript-only framework is requested from paybond-kit Python."""
    docs_url = TYPESCRIPT_ONLY_FRAMEWORK_DOCS.get(framework)
    if docs_url is None:
        raise ValueError(f"unsupported TypeScript-only framework: {framework}")
    raise ValueError(
        f'framework "{framework}" is not supported in paybond-kit Python; '
        f"use @paybond/kit TypeScript — see {docs_url}"
    )
