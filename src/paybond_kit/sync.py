"""Optional synchronous wrappers for read-only Paybond SDK paths (notebooks, REPL)."""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import Awaitable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL, PaybondEnvironment

if TYPE_CHECKING:
    from paybond_kit.audit.wire import AuditExportJobGetResponse, AuditExportListPage
    from paybond_kit.paybond import Paybond
    from paybond_kit.signal import (
        SignalPortfolioSummary,
        SignalReceiptEnvelope,
        SignalSignedPortfolioArtifact,
    )

T = TypeVar("T")


def _run_async(coro: Awaitable[T]) -> T:
    """
    Run a coroutine from synchronous code.

    Uses :func:`asyncio.run` when no loop is active; otherwise runs in a worker
    thread so Jupyter and other notebook hosts with a running loop keep working.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


class PaybondSync:
    """
    Read-only synchronous façade over :class:`~paybond_kit.paybond.Paybond`.

    Mutation paths (intent create, evidence submit, middleware bind) remain
    async-only. Use this optional module in notebooks and short scripts; keep
    agent middleware async.
    """

    def __init__(self, paybond: Paybond) -> None:
        self._paybond = paybond

    @classmethod
    def open(
        cls,
        *,
        api_key: str,
        gateway_base_url: str = DEFAULT_PAYBOND_GATEWAY_BASE_URL,
        principal_path: str = "/v1/auth/principal",
        expected_environment: PaybondEnvironment | None = None,
        max_retries: int = 3,
    ) -> PaybondSync:
        """Open a hosted Gateway session and return a sync read façade."""
        from paybond_kit.paybond import Paybond

        paybond = _run_async(
            Paybond.open(
                api_key=api_key,
                gateway_base_url=gateway_base_url,
                principal_path=principal_path,
                expected_environment=expected_environment,
                max_retries=max_retries,
            )
        )
        return cls(paybond)

    def close(self) -> None:
        """Release HTTP resources held by the underlying async session."""
        _run_async(self._paybond.aclose())

    def __enter__(self) -> PaybondSync:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def paybond(self) -> Paybond:
        """Underlying async :class:`~paybond_kit.paybond.Paybond` session."""
        return self._paybond

    def audit_exports_list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> AuditExportListPage:
        """List compliance audit export jobs for the authenticated tenant."""
        return _run_async(
            self._paybond.audit.exports.list(limit=limit, cursor=cursor)
        )

    def audit_exports_get(
        self,
        job_id: str,
        *,
        issue_download: bool = False,
    ) -> AuditExportJobGetResponse:
        """Fetch one audit export job; optionally mint a download token."""
        return _run_async(
            self._paybond.audit.exports.get(
                job_id,
                issue_download=issue_download,
            )
        )

    def audit_exports_verify(
        self,
        manifest_or_path: Mapping[str, Any] | str,
        *,
        cwd: str | Path = ".",
    ) -> dict[str, Any]:
        """Verify an audit export manifest object or on-disk bundle directory."""
        return _run_async(
            self._paybond.audit.exports.verify(manifest_or_path, cwd=cwd)
        )

    def audit_verify_manifest(self, manifest: Mapping[str, Any]) -> bool:
        """Validate manifest shape and Ed25519 signatures (no network I/O)."""
        return self._paybond.audit.exports.verify_manifest(manifest)

    def get_reputation_receipt(
        self,
        operator_did: str,
        *,
        score_version: str | None = None,
    ) -> SignalReceiptEnvelope | None:
        """Fetch a tenant-bound Signal reputation receipt for one operator."""
        return _run_async(
            self._paybond.signal.get_reputation_receipt(
                operator_did,
                score_version=score_version,
            )
        )

    def get_portfolio_summary(
        self,
        *,
        score_version: str | None = None,
    ) -> SignalPortfolioSummary:
        """Fetch the tenant portfolio summary from Signal."""
        return _run_async(
            self._paybond.signal.get_portfolio_summary(score_version=score_version)
        )

    def get_signed_portfolio_artifact(
        self,
        *,
        score_version: str | None = None,
    ) -> SignalSignedPortfolioArtifact:
        """Fetch the signed Signal portfolio artifact for compliance review."""
        return _run_async(
            self._paybond.signal.get_signed_portfolio_artifact(
                score_version=score_version
            )
        )


__all__ = ["PaybondSync"]
