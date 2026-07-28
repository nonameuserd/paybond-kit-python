"""Security regression coverage for Kit High findings."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import httpx
import pytest
import respx

from paybond_kit.cli.agent_run_id import assert_valid_agent_run_id
from paybond_kit.cli.agent_run_store import PersistedAgentRunContext, persist_agent_run_context
from paybond_kit.cli.core import CliError
from paybond_kit.cli.secret_argv import resolve_secret_from_file_or_env
from paybond_kit.harbor import HarborClient


INTENT = UUID("550e8400-e29b-41d4-a716-446655440000")
AUDIT = UUID("550e8400-e29b-41d4-a716-446655440001")


@pytest.mark.asyncio
@respx.mock
async def test_verify_capability_rejects_string_allow() -> None:
    respx.post("https://harbor.test/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "allow": "false",
                "audit_id": str(AUDIT),
                "tenant": "tenant-a",
                "intent_id": str(INTENT),
            },
        )
    )
    client = HarborClient(
        "https://harbor.test",
        "tenant-a",
        static_harbor_bearer_token="test-bearer",
    )
    with pytest.raises(ValueError, match="allow must be a JSON boolean"):
        await client.verify_capability(
            intent_id=INTENT,
            token="Cg==",
            operation="demo.tool",
        )


def test_run_id_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(CliError) as exc_info:
        assert_valid_agent_run_id("../../package")
    assert exc_info.value.code == "cli.agent.invalid_run_id"

    with pytest.raises(CliError) as persist_exc:
        persist_agent_run_context(
            tmp_path,
            PersistedAgentRunContext(
                run_id="../../package",
                tenant_id="tenant-a",
                intent_id="intent-1",
                capability_token="cap-1",
                operation="paid-tool",
                allowed_tools=["paid-tool"],
                sandbox=True,
            ),
        )
    assert persist_exc.value.code == "cli.agent.invalid_run_id"


def test_harbor_client_requires_bearer_for_non_local() -> None:
    with pytest.raises(ValueError, match="static_harbor_bearer_token"):
        HarborClient("https://harbor.test", "tenant-a")

    HarborClient(
        "http://127.0.0.1:18089",
        "tenant-a",
        allow_unauthenticated_local=True,
    )


def test_secret_argv_rejected(tmp_path: Path) -> None:
    with pytest.raises(CliError) as exc_info:
        resolve_secret_from_file_or_env(
            argv=["--capability-token", "leaked"],
            cwd=tmp_path,
            rejected_flag="--capability-token",
            file_flag="--capability-token-file",
            env_name="PAYBOND_CAPABILITY_TOKEN",
            alternatives="--capability-token-file or PAYBOND_CAPABILITY_TOKEN",
        )
    assert exc_info.value.code == "cli.secret.argv_rejected"

    (tmp_path / "cap.token").write_text("cap-from-file\n", encoding="utf-8")
    value, _rest = resolve_secret_from_file_or_env(
        argv=["--capability-token-file", "cap.token"],
        cwd=tmp_path,
        rejected_flag="--capability-token",
        file_flag="--capability-token-file",
        env_name="PAYBOND_CAPABILITY_TOKEN",
        alternatives="--capability-token-file or PAYBOND_CAPABILITY_TOKEN",
    )
    assert value == "cap-from-file"
