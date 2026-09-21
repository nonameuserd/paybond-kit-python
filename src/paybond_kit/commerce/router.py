"""Multi-provider commerce.checkout router."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping

from paybond_kit.commerce.provider import (
    CommerceCheckoutProvider,
    require_commerce_session_binding,
)
from paybond_kit.commerce.types import (
    CommerceCheckoutSessionBinding,
    CommerceCheckoutToolArgs,
    CommerceCheckoutToolResult,
    CommerceProviderId,
)

KNOWN_PROVIDERS: frozenset[CommerceProviderId] = frozenset({"shopify", "stripe", "zinc"})

CommerceCheckoutProviderMap = Mapping[CommerceProviderId, CommerceCheckoutProvider]
CommerceCheckoutHandler = Callable[
    [CommerceCheckoutToolArgs], Awaitable[CommerceCheckoutToolResult]
]


def resolve_commerce_checkout_provider(
    args: CommerceCheckoutToolArgs,
    *,
    providers: CommerceCheckoutProviderMap,
    default_provider: CommerceProviderId,
) -> tuple[CommerceProviderId, CommerceCheckoutProvider]:
    """Resolve which provider id/adapter to use for a checkout call.

    Raises:
        ValueError: on unknown provider ids or missing adapters.
    """

    raw_provider = args.get("provider")
    if isinstance(raw_provider, str) and raw_provider.strip() == "":
        raise ValueError(
            "commerce.checkout: unknown provider ''; expected shopify, stripe, or zinc"
        )
    provider_id = raw_provider if raw_provider is not None else default_provider
    if provider_id not in KNOWN_PROVIDERS:
        raise ValueError(
            f"commerce.checkout: unknown provider {provider_id!r}; "
            "expected shopify, stripe, or zinc"
        )

    provider = providers.get(provider_id)  # type: ignore[arg-type]
    if provider is None:
        raise ValueError(
            f"commerce.checkout: no adapter registered for provider {provider_id!r}"
        )

    if provider.id != provider_id:
        raise ValueError(
            f"commerce.checkout: provider map key {provider_id!r} does not match "
            f"adapter id {provider.id!r}"
        )

    return provider_id, provider


def create_commerce_checkout_router(
    *,
    providers: CommerceCheckoutProviderMap,
    default_provider: CommerceProviderId,
    binding: Callable[[], CommerceCheckoutSessionBinding],
) -> CommerceCheckoutHandler:
    """Build a thin multi-provider ``commerce.checkout`` tool handler.

    Routes by ``args["provider"]`` (or ``default_provider``), injects session
    binding into each adapter, and returns the canonical completion envelope.

    This is a Kit product surface — not a Gateway HTTP buy-proxy.
    """

    if default_provider not in providers:
        raise ValueError(
            f"create_commerce_checkout_router: default_provider {default_provider!r} "
            "has no registered adapter"
        )

    for key, adapter in providers.items():
        if key not in KNOWN_PROVIDERS:
            raise ValueError(
                f"create_commerce_checkout_router: unknown provider key {key!r}"
            )
        if adapter.id != key:
            raise ValueError(
                f"create_commerce_checkout_router: providers[{key!r}] adapter id is "
                f"{adapter.id!r}"
            )

    async def handler(args: CommerceCheckoutToolArgs) -> CommerceCheckoutToolResult:
        session = require_commerce_session_binding(binding())
        _provider_id, provider = resolve_commerce_checkout_provider(
            args,
            providers=providers,
            default_provider=default_provider,
        )
        return await provider.checkout(args, session)

    return handler


# Re-export Callable for typing convenience without pulling typing into callers.
__all__ = [
    "KNOWN_PROVIDERS",
    "CommerceCheckoutHandler",
    "CommerceCheckoutProviderMap",
    "create_commerce_checkout_router",
    "resolve_commerce_checkout_provider",
]
