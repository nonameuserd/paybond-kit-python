from __future__ import annotations

from paybond_kit.cli.core import GlobalOptions, prepare_command_output


def test_prepare_command_output_plain_json_mode() -> None:
    globals_ = GlobalOptions(json_fields="key_id")
    data = {"keys": [{"key_id": "k1", "role": "operator"}]}
    output, warnings, automation_plain = prepare_command_output("keys list", globals_, data)
    assert automation_plain is True
    assert output == [{"key_id": "k1"}]
    assert warnings == []


def test_prepare_command_output_envelope_mode() -> None:
    globals_ = GlobalOptions(format="json", json_fields="key_id")
    data = {"keys": [{"key_id": "k1", "role": "operator"}]}
    output, warnings, automation_plain = prepare_command_output("keys list", globals_, data)
    assert automation_plain is False
    assert output == [{"key_id": "k1"}]
    assert warnings == []
