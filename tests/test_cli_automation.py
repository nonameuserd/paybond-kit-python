from __future__ import annotations

import json
import stat
from io import StringIO
from pathlib import Path

from paybond_kit.cli.automation import (
    apply_jq_filter,
    apply_json_field_selection,
    format_warning,
    parse_json_fields,
    read_json_body,
    select_json_fields,
    write_atomic_file,
)


def test_parse_json_fields() -> None:
    assert parse_json_fields("key_id,role") == ["key_id", "role"]


def test_select_json_fields() -> None:
    rows = [{"key_id": "k1", "role": "operator", "secret": "x"}]
    assert select_json_fields(rows, ["key_id", "role"]) == [{"key_id": "k1", "role": "operator"}]


def test_apply_json_field_selection_for_list_commands() -> None:
    data = {"keys": [{"key_id": "k1", "role": "operator"}]}
    assert apply_json_field_selection("keys list", data, ["key_id"]) == [{"key_id": "k1"}]


def test_apply_simple_jq_paths() -> None:
    data = {"keys": [{"key_id": "k1"}]}
    assert apply_jq_filter(data, ".keys") == [{"key_id": "k1"}]
    assert apply_jq_filter(data, ".keys[].key_id") == ["k1"]


def test_format_stable_warnings() -> None:
    assert format_warning("cli.warn.partial_results", "more items available") == (
        "cli.warn.partial_results: more items available"
    )


def test_read_json_body_from_stdin() -> None:
    payload = read_json_body("-", stdin=StringIO('{"intent_id":"i1"}'))
    assert payload == {"intent_id": "i1"}


def test_write_atomic_file_uses_0600(tmp_path: Path) -> None:
    target = tmp_path / "secret.json"
    write_atomic_file(target, json.dumps({"ok": True}), mode=0o600)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
