from __future__ import annotations

import io

import pytest

from paybond_kit.cli.color import should_use_color
from paybond_kit.cli.core import GlobalOptions
from paybond_kit.cli.router import run_cli


@pytest.mark.asyncio
async def test_cli_suggests_command_for_typos() -> None:
    stderr = io.StringIO()
    code = await run_cli(["logn"], stderr=stderr)
    assert code == 1
    assert 'did you mean "login"' in stderr.getvalue()


@pytest.mark.asyncio
async def test_cli_suggests_global_flag_for_typos() -> None:
    stderr = io.StringIO()
    code = await run_cli(["--formt", "json", "whoami"], stderr=stderr)
    assert code == 1
    assert "did you mean --format" in stderr.getvalue()


@pytest.mark.asyncio
async def test_cli_help_command_prints_subcommand_help() -> None:
    stdout = io.StringIO()
    code = await run_cli(["help", "login"], stdout=stdout)
    assert code == 0
    output = stdout.getvalue()
    assert "Usage: paybond login" in output
    assert "Examples:" in output


@pytest.mark.asyncio
async def test_cli_examples_filters_by_command() -> None:
    stdout = io.StringIO()
    code = await run_cli(["examples", "doctor"], stdout=stdout)
    assert code == 0
    assert "paybond doctor" in stdout.getvalue()


@pytest.mark.asyncio
async def test_cli_completion_bash_script() -> None:
    stdout = io.StringIO()
    code = await run_cli(["completion", "bash"], stdout=stdout)
    assert code == 0
    assert "complete -F _paybond_completion paybond" in stdout.getvalue()


def test_cli_json_output_disables_color() -> None:
    globals_ = GlobalOptions(format="json", color="always")
    assert should_use_color(globals_) is False
