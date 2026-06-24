from __future__ import annotations

from paybond_kit.cli.core import CliError, consume_boolean_flag, consume_flag, read_json_file


def resolve_json_body(
    argv: list[str],
    *,
    stdin,
    required: bool = True,
    missing_message: str = "missing JSON body; pass --body <json-file> or --stdin",
) -> tuple[dict, list[str]]:
    stdin_present, rest = consume_boolean_flag(argv, "--stdin")
    if stdin_present:
        return read_json_file("-", stdin=stdin), rest
    _, body_path, rest = consume_flag(rest, "--body")
    if not body_path:
        if not required:
            return {}, rest
        raise CliError(missing_message, code="cli.usage.missing_body")
    return read_json_file(body_path, stdin=stdin), rest
