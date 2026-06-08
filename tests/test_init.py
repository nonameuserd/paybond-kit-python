from __future__ import annotations

import pytest

from paybond_kit.init import main


def assert_contains_all(text: str, fragments: tuple[str, ...]) -> None:
    for fragment in fragments:
        assert fragment in text


def test_init_scaffolds_provider_agnostic_guardrail_integration(tmp_path, capsys) -> None:
    out = tmp_path / "paybond_paid_tool_guard.py"

    assert main(["--preset", "paid-tool-guard", "--framework", "provider-agnostic", "--out", str(out)]) == 0

    captured = capsys.readouterr()
    assert "Created Paybond guardrail integration" in captured.out
    assert str(out) in captured.out
    assert_contains_all(
        out.read_text(encoding="utf-8"),
        (
            "Production integration helpers only.",
            "def load_paybond_env_file",
            "async def open_paybond_from_env(env_file: str | None = \".env.local\") -> Paybond",
            "os.environ.get(\"PAYBOND_GATEWAY_URL\")",
            "os.environ.get(\"PAYBOND_GATEWAY_BASE_URL\")",
            "async def bootstrap_sandbox_guardrail_intent",
            "def wrap_paid_tool",
            "async def submit_sandbox_evidence",
            "paybond.guardrails.bootstrap_sandbox",
            "paybond.spend_guard(guardrail.intent_id, guardrail.capability_token)",
            "paybond.guardrails.submit_sandbox_evidence",
            "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
        ),
    )
    body = out.read_text(encoding="utf-8")
    for fragment in (
        "replaceable_smoke_test_paid_tool",
        "run_sandbox_smoke_path",
        "sandbox-confirmation",
        "if __name__",
        "asyncio.run",
    ):
        assert fragment not in body


def test_init_refuses_overwrite_without_force(tmp_path, capsys) -> None:
    out = tmp_path / "paybond_paid_tool_guard.py"
    out.write_text("existing", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(["--out", str(out)])

    assert excinfo.value.code == 2
    assert out.read_text(encoding="utf-8") == "existing"
    assert "already exists" in capsys.readouterr().err


def test_init_defaults_match_one_command_guardrails_doc(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "paybond_paid_tool_guard.py"

    assert main([]) == 0

    captured = capsys.readouterr()
    assert "paybond_paid_tool_guard.py" in captured.out
    assert out.exists()
    assert "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime." in out.read_text(
        encoding="utf-8"
    )


def test_init_supports_vercel_ai_framework_note(tmp_path) -> None:
    out = tmp_path / "paybond_paid_tool_guard.py"

    assert main(["--framework", "vercel-ai", "--out", str(out)]) == 0

    assert "Call the guarded handler from your Vercel AI SDK tool execute function." in out.read_text(
        encoding="utf-8"
    )


def test_init_force_overwrites_with_framework_note(tmp_path) -> None:
    out = tmp_path / "paybond_paid_tool_guard.py"
    out.write_text("existing", encoding="utf-8")

    assert main(["--framework", "mcp", "--out", str(out), "--force"]) == 0

    assert_contains_all(
        out.read_text(encoding="utf-8"),
        (
            "def wrap_paid_tool",
            "Use the same operation name in your MCP tool handler before executing paid work.",
        ),
    )
