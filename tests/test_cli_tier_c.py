"""Focused Tier C CLI UX coverage (status/open/shell/control/next-actions)."""

from __future__ import annotations

import asyncio
import json

from paybond_kit.cli.next_actions import format_human_error_lines, with_next_actions
from paybond_kit.cli.control_plane import resolve_open_target
from paybond_kit.cli.core import CliError
from paybond_kit.cli.router import run_cli
from paybond_kit.cli.tty import must_be_non_interactive
from paybond_kit.cli.core import default_globals


def test_format_human_error_lines() -> None:
    lines = format_human_error_lines(
        "missing key",
        with_next_actions(None, what="missing API key", why="no credentials", next="paybond login"),
    )
    assert lines == [
        "missing key",
        "what: missing API key",
        "why: no credentials",
        "next: paybond login",
    ]


def test_open_resolves_billing() -> None:
    target = resolve_open_target("billing")
    assert "/console/configuration/billing" in target["url"]


def test_open_intent_requires_id() -> None:
    try:
        resolve_open_target("intent")
        raise AssertionError("expected CliError")
    except CliError as exc:
        assert exc.code == "cli.usage.missing_intent_id"


def test_status_json_unauthenticated() -> None:
    class Buf:
        def __init__(self) -> None:
            self.chunks: list[str] = []

        def write(self, chunk: str) -> int:
            self.chunks.append(chunk)
            return len(chunk)

    stdout = Buf()
    code = asyncio.run(run_cli(["status", "--format", "json"], stdout=stdout, stderr=Buf()))
    assert code == 0
    envelope = json.loads("".join(stdout.chunks))
    assert envelope["ok"] is True
    assert envelope["data"]["auth"]["authenticated"] is False
    assert envelope["data"]["happy_path"][0] == "paybond login"


def test_shell_json_refuses_without_exec() -> None:
    class Buf:
        def __init__(self) -> None:
            self.chunks: list[str] = []

        def write(self, chunk: str) -> int:
            self.chunks.append(chunk)
            return len(chunk)

    stdout = Buf()
    code = asyncio.run(run_cli(["shell", "--format", "json"], stdout=stdout, stderr=Buf()))
    assert code == 1
    envelope = json.loads("".join(stdout.chunks))
    assert envelope["error"]["code"] == "cli.shell.non_interactive"


def test_must_be_non_interactive_for_json() -> None:
    globals_ = default_globals()
    globals_.format = "json"
    assert must_be_non_interactive(globals_) is True


def test_open_help() -> None:
    class Buf:
        def __init__(self) -> None:
            self.chunks: list[str] = []

        def write(self, chunk: str) -> int:
            self.chunks.append(chunk)
            return len(chunk)

    stdout = Buf()
    code = asyncio.run(run_cli(["open", "--help"], stdout=stdout, stderr=Buf()))
    assert code == 0
    assert "Usage: paybond open" in "".join(stdout.chunks)


def test_control_once_json_unauthenticated() -> None:
    class Buf:
        def __init__(self) -> None:
            self.chunks: list[str] = []

        def write(self, chunk: str) -> int:
            self.chunks.append(chunk)
            return len(chunk)

    stdout = Buf()
    code = asyncio.run(run_cli(["control", "--once", "--format", "json"], stdout=stdout, stderr=Buf()))
    assert code == 0
    envelope = json.loads("".join(stdout.chunks))
    assert envelope["ok"] is True
    assert envelope["data"]["mode"] == "snapshot"
    assert envelope["data"]["panels"]["spend"]["source"] == "unavailable"
    assert any("not authenticated" in line for line in envelope["data"]["limitations"])


def test_control_help() -> None:
    class Buf:
        def __init__(self) -> None:
            self.chunks: list[str] = []

        def write(self, chunk: str) -> int:
            self.chunks.append(chunk)
            return len(chunk)

    stdout = Buf()
    code = asyncio.run(run_cli(["control", "--help"], stdout=stdout, stderr=Buf()))
    assert code == 0
    assert "Usage: paybond control" in "".join(stdout.chunks)


def test_audit_exports_create_help() -> None:
    class Buf:
        def __init__(self) -> None:
            self.chunks: list[str] = []

        def write(self, chunk: str) -> int:
            self.chunks.append(chunk)
            return len(chunk)

    stdout = Buf()
    code = asyncio.run(run_cli(["audit", "exports", "create", "--help"], stdout=stdout, stderr=Buf()))
    assert code == 0
    text = "".join(stdout.chunks)
    assert "Usage: paybond audit exports create" in text
    assert "--wait" in text
