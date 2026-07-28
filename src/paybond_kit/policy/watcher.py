"""Background file watcher and Gateway poll scheduler for policy hot-reload."""

from __future__ import annotations

import asyncio
import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from paybond_kit.policy.reload import (
    PaybondPolicyReloadBindConfig,
    PaybondPolicyReloadOptions,
    PaybondPolicyReloadPollConfig,
    PaybondPolicyReloadResult,
)

if TYPE_CHECKING:
    from paybond_kit.agent.run import PaybondAgentRun

DEFAULT_WATCH_DEBOUNCE_MS = 500
DEFAULT_POLL_INTERVAL_MS = 60_000


class PolicyReloadRunner(Protocol):
    async def reload_policy(
        self,
        options: PaybondPolicyReloadOptions | None = None,
    ) -> PaybondPolicyReloadResult: ...


@dataclass
class PaybondPolicyReloadControllerState:
    watch: bool = False
    poll: bool = False
    policy_file_path: str | None = None
    last_reload_at: str | None = None
    last_reload_error: str | None = None


class PaybondPolicyReloadController:
    """File watcher and Gateway poll scheduler for policy hot-reload."""

    def __init__(
        self,
        runner: PolicyReloadRunner,
        *,
        policy_file_path: str,
        reload_defaults: PaybondPolicyReloadOptions,
        state: PaybondPolicyReloadControllerState,
    ) -> None:
        self._runner = runner
        self._policy_file_path = policy_file_path
        self._reload_defaults = reload_defaults
        self.state = state
        self._watch_task: asyncio.Task[None] | None = None
        self._poll_task: asyncio.Task[None] | None = None
        self._reload_in_flight = False
        self._stop_event = asyncio.Event()

    @classmethod
    def start(
        cls,
        runner: PolicyReloadRunner | PaybondAgentRun,
        config: PaybondPolicyReloadBindConfig,
        policy_file_path: str,
    ) -> PaybondPolicyReloadController | None:
        watch_cfg = config.get("watch")
        watch_enabled = watch_cfg is True or isinstance(watch_cfg, dict)
        poll_enabled = config.get("poll") is not None
        if not watch_enabled and not poll_enabled:
            return None

        resolved_path = str(Path(policy_file_path).resolve())
        poll_cfg: PaybondPolicyReloadPollConfig = config.get("poll") or {}
        reload_defaults: PaybondPolicyReloadOptions = {"file": resolved_path}
        poll_remote = poll_cfg.get("remote")
        if poll_remote is not None:
            reload_defaults["remote"] = poll_remote
        poll_resolve_inheritance = poll_cfg.get("resolve_inheritance")
        if poll_resolve_inheritance is not None:
            reload_defaults["resolve_inheritance"] = poll_resolve_inheritance
        poll_gateway = poll_cfg.get("gateway")
        if poll_gateway is not None:
            reload_defaults["gateway"] = poll_gateway
        controller = cls(
            runner,
            policy_file_path=resolved_path,
            reload_defaults=reload_defaults,
            state=PaybondPolicyReloadControllerState(
                watch=watch_enabled,
                poll=poll_enabled,
                policy_file_path=resolved_path,
            ),
        )
        if watch_enabled:
            debounce_ms = DEFAULT_WATCH_DEBOUNCE_MS
            if isinstance(watch_cfg, dict):
                watch_debounce_ms = watch_cfg.get("debounce_ms")
                if watch_debounce_ms is not None:
                    debounce_ms = int(watch_debounce_ms)
            controller._start_file_watch(debounce_ms)
        if poll_enabled:
            interval_ms = int(poll_cfg.get("interval_ms") or DEFAULT_POLL_INTERVAL_MS)
            controller._start_gateway_poll(poll_cfg, interval_ms)
        return controller

    def _start_file_watch(self, debounce_ms: int) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._watch_task = loop.create_task(self._file_watch_loop(debounce_ms))

    def _start_gateway_poll(self, poll_cfg: PaybondPolicyReloadPollConfig, interval_ms: int) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._poll_task = loop.create_task(self._gateway_poll_loop(poll_cfg, interval_ms))

    async def _file_watch_loop(self, debounce_ms: int) -> None:
        try:
            # Optional performance dependency; falls back to mtime polling when absent.
            awatch = importlib.import_module("watchfiles").awatch
        except ImportError:
            await self._mtime_poll_fallback(debounce_ms)
            return

        debounce_s = debounce_ms / 1000.0
        async for _changes in awatch(self._policy_file_path, stop_event=self._stop_event):
            await asyncio.sleep(debounce_s)
            await self._trigger_reload({"remote": False})

    async def _mtime_poll_fallback(self, debounce_ms: int) -> None:
        path = Path(self._policy_file_path)
        last_mtime = path.stat().st_mtime if path.exists() else 0.0
        interval_s = max(debounce_ms / 1000.0, 0.25)
        while not self._stop_event.is_set():
            await asyncio.sleep(interval_s)
            if not path.exists():
                continue
            mtime = path.stat().st_mtime
            if mtime != last_mtime:
                last_mtime = mtime
                await self._trigger_reload({"remote": False})

    async def _gateway_poll_loop(self, poll_cfg: PaybondPolicyReloadPollConfig, interval_ms: int) -> None:
        interval_s = interval_ms / 1000.0
        while not self._stop_event.is_set():
            await asyncio.sleep(interval_s)
            await self._trigger_reload(
                {
                    "remote": bool(poll_cfg.get("remote", True)),
                    "resolve_inheritance": bool(poll_cfg.get("resolve_inheritance", True)),
                    "gateway": poll_cfg.get("gateway") or self._reload_defaults.get("gateway"),
                }
            )

    async def _trigger_reload(self, overrides: PaybondPolicyReloadOptions) -> None:
        if self._reload_in_flight:
            return
        self._reload_in_flight = True
        try:
            merged: PaybondPolicyReloadOptions = {
                **self._reload_defaults,
                **overrides,
                "file": self._policy_file_path,
            }
            result = await self._runner.reload_policy(merged)
            if result.applied:
                from datetime import UTC, datetime

                self.state.last_reload_at = datetime.now(UTC).isoformat()
                self.state.last_reload_error = None
        except Exception as exc:
            self.state.last_reload_error = str(exc)
        finally:
            self._reload_in_flight = False

    def stop(self) -> None:
        self._stop_event.set()
        for task in (self._watch_task, self._poll_task):
            if task is not None and not task.done():
                task.cancel()
