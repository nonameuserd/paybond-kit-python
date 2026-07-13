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
            "Paid-tool guardrail preset maps to completion catalog archetype",
            "def load_paybond_env_file",
            "async def open_paybond_from_env(env_file: str | None = \".env.local\") -> Paybond",
            "os.environ.get(\"PAYBOND_GATEWAY_URL\")",
            "os.environ.get(\"PAYBOND_GATEWAY_BASE_URL\")",
            "async def bootstrap_sandbox_guardrail_intent",
            "def wrap_paid_tool",
            "async def submit_sandbox_evidence",
            "def build_completion_evidence",
            "cost_and_completion",
            "completion_budget_v1",
            "status",
            "cost_cents",
            "paybond.guardrails.bootstrap_sandbox",
            "paybond.spend_guard(guardrail.intent_id, guardrail.capability_token)",
            "paybond.guardrails.submit_sandbox_evidence",
            "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
            "create_with_policy_binding",
            "Production (signing v7)",
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


def test_init_scaffolds_agent_middleware_with_registry(tmp_path, capsys) -> None:
    out = tmp_path / "paybond_agent_middleware.py"

    assert main(["--preset", "agent-middleware", "--out", str(out)]) == 0

    captured = capsys.readouterr()
    assert "Created Paybond agent middleware integration" in captured.out
    assert_contains_all(
        out.read_text(encoding="utf-8"),
        (
            "Agent middleware preset maps to completion catalog archetype",
            "create_paybond_tool_registry",
            "create_agent_tool_registry",
            "bind_agent_run",
            "paybond.agent_run.bind",
            '"default_deny": True',
            "create_paybond_generic_agent_config",
            "create_generic_agent_config",
            "wrap_agent_tools",
            "travel.book_hotel",
            "cost_and_completion",
            "create_with_policy_binding",
            "Production (signing v7)",
        ),
    )
    assert "def wrap_paid_tool" not in out.read_text(encoding="utf-8")


def test_init_accepts_provider_agnostic_alias_for_generic_agent_middleware(tmp_path) -> None:
    out = tmp_path / "paybond_agent_middleware_alias.py"

    assert main(["--preset", "agent-middleware", "--framework", "provider-agnostic", "--out", str(out)]) == 0

    assert "create_paybond_generic_agent_config" in out.read_text(encoding="utf-8")


def test_init_scaffolds_agent_middleware_claude_agents_framework(tmp_path) -> None:
    out = tmp_path / "paybond_claude_agents.py"

    assert main(["--preset", "agent-middleware", "--framework", "claude-agents", "--out", str(out)]) == 0

    body = out.read_text(encoding="utf-8")
    assert "claude_agent_sdk" in body
    assert "create_guarded_agent" in body
    assert "create_claude_agents_guarded_runner" in body
    assert "create_guarded_agent_runner" in body
    assert 'framework="claude-agents"' in body


def test_init_scaffolds_agent_middleware_crewai_framework(tmp_path) -> None:
    out = tmp_path / "paybond_crewai.py"

    assert main(["--preset", "agent-middleware", "--framework", "crewai", "--out", str(out)]) == 0

    body = out.read_text(encoding="utf-8")
    assert "crewai.tools" in body
    assert "create_paybond_crewai_config" in body
    assert 'framework="crewai"' in body
    assert "agent demo crewai smoke" in body
    assert "Paybond for paid tools" in body
    assert "paybond.policy.yaml" in body


def test_init_scaffolds_agent_middleware_pydantic_ai_framework(tmp_path) -> None:
    out = tmp_path / "paybond_pydantic_ai.py"

    assert main(["--preset", "agent-middleware", "--framework", "pydantic-ai", "--out", str(out)]) == 0

    body = out.read_text(encoding="utf-8")
    assert "pydantic_ai" in body
    assert "create_paybond_pydantic_ai_config" in body
    assert 'framework="pydantic-ai"' in body
    assert "agent demo pydantic-ai smoke" in body
    assert "Paybond for paid tools" in body
    assert "paybond.policy.yaml" in body


def test_init_scaffolds_agent_middleware_google_adk_framework(tmp_path) -> None:
    out = tmp_path / "paybond_google_adk.py"

    assert main(["--preset", "agent-middleware", "--framework", "google-adk", "--out", str(out)]) == 0

    body = out.read_text(encoding="utf-8")
    assert "google_adk" in body
    assert "create_paybond_google_adk_config" in body
    assert 'framework="google-adk"' in body
    assert "agent demo google-adk smoke" in body
    assert "Paybond for paid tools" in body
    assert "paybond.policy.yaml" in body


def test_init_scaffolds_agent_middleware_microsoft_agent_framework(tmp_path) -> None:
    out = tmp_path / "paybond_microsoft_agent_framework.py"

    assert main(
        [
            "--preset",
            "agent-middleware",
            "--framework",
            "microsoft-agent-framework",
            "--out",
            str(out),
        ]
    ) == 0

    body = out.read_text(encoding="utf-8")
    assert "microsoft_agent_framework" in body
    assert "create_paybond_microsoft_agent_framework_config" in body
    assert 'framework="microsoft-agent-framework"' in body
    assert "agent demo microsoft-agent-framework smoke" in body
    assert "never_require" in body
    assert "Paybond for paid tools" in body
    assert "paybond.policy.yaml" in body


def test_init_scaffolds_agent_middleware_mcp_framework(tmp_path) -> None:
    out = tmp_path / "paybond_mcp.py"

    assert main(["--preset", "agent-middleware", "--framework", "mcp", "--out", str(out)]) == 0

    body = out.read_text(encoding="utf-8")
    assert "create_paybond_mcp_tool_surface" in body
    assert "create_mcp_tool_surface" in body
    assert "agent demo mcp smoke" in body
    assert "Paybond for paid tools" in body
    assert "paybond.policy.yaml" in body


def test_init_scaffolds_agent_middleware_openai_framework(tmp_path) -> None:
    out = tmp_path / "paybond_agent_middleware_openai.py"

    assert main(["--preset", "agent-middleware", "--framework", "openai", "--out", str(out)]) == 0

    body = out.read_text(encoding="utf-8")
    assert "from agents import FunctionTool" in body
    assert "create_paybond_openai_agents_config" in body
    assert "create_guarded_agent" in body
    assert "create_openai_agents_guarded_runner" in body
    assert 'framework="openai-agents"' in body
    assert "wrap_openai_agents_tools" in body
    assert "agent demo openai smoke" in body
    assert "Paybond for paid tools" in body
    assert "paybond.policy.yaml" in body


def test_init_scaffolds_agent_middleware_langgraph_framework(tmp_path) -> None:
    out = tmp_path / "paybond_agent_middleware_langgraph.py"

    assert main(["--preset", "agent-middleware", "--framework", "langgraph", "--out", str(out)]) == 0

    body = out.read_text(encoding="utf-8")
    assert "paybond_awrap_tool_call" in body
    assert "create_langgraph_tool_call_wrapper" in body


def test_init_scaffolds_agent_middleware_vercel_ai_framework(tmp_path) -> None:
    out = tmp_path / "paybond_agent_middleware_vercel.py"

    assert main(["--preset", "agent-middleware", "--framework", "vercel-ai", "--out", str(out)]) == 0

    body = out.read_text(encoding="utf-8")
    assert "execute_guarded_vercel_tool" in body
    assert "create_guarded_vercel_book_hotel_tool" in body


def test_init_rejects_invalid_framework_for_agent_middleware(tmp_path) -> None:
    out = tmp_path / "paybond_agent_middleware.py"

    assert main(["--preset", "agent-middleware", "--framework", "claude", "--out", str(out)]) == 1
