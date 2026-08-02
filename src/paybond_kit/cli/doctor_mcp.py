"""`paybond doctor --mcp` credential checks.

Mirrors ``kit/ts/src/cli/doctor-mcp.ts``; the check names, messages, and details
must stay byte-identical so the CLI parity contract holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from paybond_kit.cli.mcp_install import (
    McpInstallHost,
    default_mcp_install_format,
    detect_env_file_api_key_kind,
)
from paybond_kit.cli.mcp_verify_config import verify_mcp_install_plan
from paybond_kit.mcp_policy import (
    DEFAULT_MCP_TOOL_POLICY,
    MCP_TOOL_ALLOWLIST_ENV,
    MCP_TOOL_POLICY_ENV,
)
from paybond_kit.mcp_scope_catalog import PaybondApiKeyKind

#: Command that mints the credential this check recommends. Kept as one string so
#: the TypeScript and Python doctors emit byte-identical guidance.
MCP_RESTRICTED_KEY_HINT = (
    "paybond keys create --name mcp-agent --role operator --kind restricted --preset mcp-readonly"
)


@dataclass(frozen=True)
class McpDoctorCheck:
    """One `doctor --mcp` result row."""

    name: str
    ok: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def evaluate_mcp_credential_checks(
    *,
    key_kind: PaybondApiKeyKind,
    tool_policy: str | None,
    tool_allowlist: str | None,
    config_path: str | None,
    env_file: str,
) -> list[McpDoctorCheck]:
    """Grade the credential an MCP host config will use.

    The load-bearing check is ``mcp_credential_kind``: a standard ``paybond_sk_*``
    key gives an MCP host the full role surface, so the key stops being a boundary
    and only host-side config stands between an agent and settlement. A restricted
    ``paybond_rk_*`` key carries a scope grant the gateway enforces, which is why
    it is the only configuration this check passes.

    ``mcp_credential_tool_policy`` is the mitigation check: an unrestricted key
    explicitly narrowed to ``readonly`` or an allowlist is a dev-grade guardrail,
    while one left on the default policy exposes every non-settlement tool the
    role allows.
    """

    details: dict[str, Any] = {
        "key_kind": key_kind,
        "env_file": env_file,
        "config_path": config_path,
    }
    checks: list[McpDoctorCheck] = []

    if key_kind == "restricted":
        checks.append(
            McpDoctorCheck(
                name="mcp_credential_kind",
                ok=True,
                message="MCP host config uses a restricted paybond_rk_ key",
                details=dict(details),
            )
        )
    elif key_kind == "standard":
        checks.append(
            McpDoctorCheck(
                name="mcp_credential_kind",
                ok=False,
                message=(
                    "MCP host config uses an unrestricted paybond_sk_ key; the gateway cannot "
                    "cap its MCP surface. Mint a restricted key: " + MCP_RESTRICTED_KEY_HINT
                ),
                details={**details, "severity": "warning", "remediation": MCP_RESTRICTED_KEY_HINT},
            )
        )
    else:
        checks.append(
            McpDoctorCheck(
                name="mcp_credential_kind",
                ok=False,
                message="skipped MCP credential check (no readable Paybond API key)",
                details={**details, "severity": "warning"},
            )
        )

    policy = (tool_policy or "").strip()
    allowlist = (tool_allowlist or "").strip()
    policy_details = {
        **details,
        "tool_policy": policy or None,
        "tool_allowlist": allowlist or None,
    }
    if key_kind == "restricted":
        message = (
            f"{MCP_TOOL_POLICY_ENV}/{MCP_TOOL_ALLOWLIST_ENV} is ignored for restricted keys; "
            "the key's scopes decide the tool surface"
            if policy or allowlist
            else "tool surface comes from the restricted key's MCP scopes"
        )
        checks.append(
            McpDoctorCheck(
                name="mcp_credential_tool_policy",
                ok=True,
                message=message,
                details=policy_details,
            )
        )
        return checks

    if key_kind != "standard":
        checks.append(
            McpDoctorCheck(
                name="mcp_credential_tool_policy",
                ok=True,
                message="skipped tool-policy check (no readable Paybond API key)",
                details=policy_details,
            )
        )
        return checks

    # ``spend-write`` is the default the MCP server falls back to when no policy is
    # set, so it is not evidence that anyone narrowed anything: only an explicit
    # readonly or allowlist policy counts as a host-side guardrail.
    narrowed = policy in ("readonly", "allowlist") or bool(allowlist)
    if narrowed:
        checks.append(
            McpDoctorCheck(
                name="mcp_credential_tool_policy",
                ok=True,
                message=(
                    f"unrestricted key narrowed to {policy or 'allowlist'} by "
                    f"{MCP_TOOL_POLICY_ENV} (dev override; a restricted key is enforced at the "
                    "gateway)"
                ),
                details=policy_details,
            )
        )
        return checks

    checks.append(
        McpDoctorCheck(
            name="mcp_credential_tool_policy",
            ok=False,
            message=(
                f"unrestricted key on the default {MCP_TOOL_POLICY_ENV}="
                f"{DEFAULT_MCP_TOOL_POLICY} surface: every non-settlement tool this role allows "
                "is exposed and the gateway cannot cap it"
            ),
            details={
                **policy_details,
                "severity": "warning",
                "remediation": MCP_RESTRICTED_KEY_HINT,
            },
        )
    )
    return checks


def run_mcp_doctor_checks(
    *,
    env_file: str,
    cwd: Path,
    home: Path,
    host: McpInstallHost,
    config_path: str | None = None,
) -> list[McpDoctorCheck]:
    """Read one host's MCP config and grade the credential it will use.

    When ``config_path`` is omitted the config ``paybond mcp install`` would
    generate is graded instead, so the check works before a host config exists.
    Read or parse failures surface as one failed check rather than an exception:
    `doctor` must always produce a report.
    """

    payload: str | None = None
    try:
        if config_path:
            payload = Path(config_path).read_text(encoding="utf-8")
        result = verify_mcp_install_plan(
            host=host,
            scope="local",
            fmt=default_mcp_install_format(host),
            env_file=env_file,
            cwd=cwd,
            home=home,
            config_path=config_path,
            payload=payload,
        )
    except OSError as exc:
        return [
            McpDoctorCheck(
                name="mcp_credential_kind",
                ok=False,
                message=f"unable to read MCP host config: {exc}",
                details={"config_path": config_path, "severity": "warning"},
            )
        ]
    # Without an entry there is no credential to grade, and falling back to the
    # workspace env file would report a pass for a config the host cannot use.
    if result.entry is None:
        return [
            McpDoctorCheck(
                name="mcp_credential_kind",
                ok=False,
                message=(
                    "no usable Paybond MCP server entry in the host config: "
                    f"{result.message}"
                ),
                details={
                    "config_path": result.config_path,
                    "issues": [
                        {"field": issue.field, "message": issue.message}
                        for issue in result.issues
                    ],
                    "severity": "warning",
                },
            )
        ]
    entry_env = dict(result.entry.env)
    resolved_env_file = (entry_env.get("PAYBOND_ENV_FILE") or "").strip() or env_file
    key_kind = detect_env_file_api_key_kind(resolved_env_file, cwd)
    env_path = Path(resolved_env_file)
    if not env_path.is_absolute():
        env_path = cwd / env_path
    return evaluate_mcp_credential_checks(
        key_kind=key_kind,
        tool_policy=entry_env.get(MCP_TOOL_POLICY_ENV),
        tool_allowlist=entry_env.get(MCP_TOOL_ALLOWLIST_ENV),
        config_path=result.config_path,
        env_file=str(env_path),
    )
