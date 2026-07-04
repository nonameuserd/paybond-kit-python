from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

import httpx

from paybond_kit.cli.color import parse_color_mode, resolve_color_mode_from_env
from paybond_kit.cli.suggest import format_unknown_global_flag_message
from paybond_kit.credentials import DEFAULT_PAYBOND_GATEWAY_BASE_URL, InsecureGatewayURLError, normalize_gateway_base_url
from paybond_kit.login import mask_api_key
from paybond_kit.cli.redact import redact_config_value

EXIT_SUCCESS = 0
EXIT_INTERRUPT = 130
EXIT_FAILURE = 1
EXIT_AUTH = 2
EXIT_FORBIDDEN = 3
EXIT_CONFIRMATION = 4
EXIT_GATEWAY = 5
EXIT_ENVIRONMENT = 6

DEFAULT_ENV_FILE = ".env.local"
DEFAULT_GATEWAY = DEFAULT_PAYBOND_GATEWAY_BASE_URL

GLOBAL_FLAGS = frozenset(
    {
        "--gateway",
        "--env-file",
        "--format",
        "--json",
        "--jq",
        "--profile",
        "--request-id",
        "--yes",
        "--no-open",
        "--color",
        "--no-color",
    }
)

TENANT_OVERRIDE_FLAGS = ("--tenant-id", "--tenant", "--tenant_id")


def rejects_tenant_override_flag(arg: str) -> bool:
    for flag in TENANT_OVERRIDE_FLAGS:
        if arg == flag or arg.startswith(f"{flag}="):
            return True
    return False


def parse_required_non_negative_int(raw: str, *, field: str) -> int:
    text = raw.strip()
    if not text:
        raise CliError(f"invalid {field} (expected non-negative integer)", category="validation", code="cli.validation.invalid_integer")
    try:
        value = int(text, 10)
    except ValueError as exc:
        raise CliError(f"invalid {field} (expected non-negative integer)", category="validation", code="cli.validation.invalid_integer") from exc
    if value < 0:
        raise CliError(f"invalid {field} (expected non-negative integer)", category="validation", code="cli.validation.invalid_integer")
    return value


def parse_optional_non_negative_int(raw: str | None, *, field: str) -> int:
    if raw is None or not str(raw).strip():
        return 0
    return parse_required_non_negative_int(str(raw), field=field)


@dataclass
class CliError(Exception):
    message: str
    category: str = "usage"
    code: str = "cli.usage"
    exit_code: int = EXIT_FAILURE
    details: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


@dataclass
class GlobalOptions:
    gateway: str = DEFAULT_GATEWAY
    env_file: str = DEFAULT_ENV_FILE
    format: str = "table"
    color: str = "auto"
    profile: str | None = None
    request_id: str = field(default_factory=lambda: f"01{uuid.uuid4().hex[:24].upper()}")
    yes: bool = False
    no_open: bool = False
    json_fields: str | None = None
    jq_expr: str | None = None
    credential_warnings: list[str] = field(default_factory=list)


@dataclass
class CliContext:
    globals: GlobalOptions
    cwd: Path
    stdout: TextIO
    stderr: TextIO
    stdin: TextIO = field(default_factory=lambda: sys.stdin)
    client: httpx.Client | None = None


def generate_request_id() -> str:
    return f"01{uuid.uuid4().hex[:24].upper()}"


def default_globals() -> GlobalOptions:
    return GlobalOptions(request_id=generate_request_id(), color=resolve_color_mode_from_env())


def output_format_from_argv(argv: list[str]) -> str:
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--format" and index + 1 < len(argv) and argv[index + 1] == "json":
            return "json"
        if arg == "--format=json":
            return "json"
        index += 1
    return "table"


def request_id_from_argv(argv: list[str]) -> str:
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--request-id" and index + 1 < len(argv) and argv[index + 1].strip():
            return argv[index + 1].strip()
        if arg.startswith("--request-id="):
            value = arg[len("--request-id=") :].strip()
            if value:
                return value
        index += 1
    return generate_request_id()


def exit_code_for_http_status(status: int) -> tuple[int, str]:
    if status == 401:
        return EXIT_AUTH, "auth"
    if status == 403:
        return EXIT_FORBIDDEN, "forbidden"
    if status == 404:
        return EXIT_FAILURE, "not_found"
    if status == 410:
        return EXIT_FAILURE, "gone"
    if status == 429:
        return EXIT_GATEWAY, "rate_limit"
    if status >= 500:
        return EXIT_GATEWAY, "gateway"
    return EXIT_FAILURE, "validation"


def parse_cli_argv(argv: list[str]) -> tuple[GlobalOptions, list[str]]:
    for arg in argv:
        if rejects_tenant_override_flag(arg):
            raise CliError(
                "tenant scope comes from authenticated credentials; do not pass --tenant-id",
                category="usage",
                code="cli.usage.tenant_override_forbidden",
            )
    globals_ = default_globals()
    command: list[str] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("--help", "-h"):
            command.append(arg)
            index += 1
            continue
        if arg == "--yes":
            globals_.yes = True
            index += 1
            continue
        if arg == "--no-open":
            globals_.no_open = True
            index += 1
            continue
        if arg == "--no-color":
            globals_.color = "never"
            index += 1
            continue
        if arg == "--color" or arg.startswith("--color="):
            value = _flag_value(argv, index, "--color")
            index += 2 if arg == "--color" else 1
            try:
                globals_.color = parse_color_mode(value)
            except ValueError as exc:
                raise CliError(str(exc), code="cli.usage.invalid_color") from exc
            continue
        if arg == "--gateway" or arg.startswith("--gateway="):
            value = _flag_value(argv, index, "--gateway")
            index += 2 if arg == "--gateway" else 1
            if not value.strip():
                raise CliError("invalid --gateway", code="cli.usage.invalid_gateway")
            globals_.gateway = _validate_cli_gateway(value.strip())
            continue
        if arg == "--env-file" or arg.startswith("--env-file="):
            value = _flag_value(argv, index, "--env-file")
            index += 2 if arg == "--env-file" else 1
            if not value.strip():
                raise CliError("invalid --env-file", code="cli.usage.invalid_env_file")
            globals_.env_file = value.strip()
            continue
        if arg == "--format" or arg.startswith("--format="):
            value = _flag_value(argv, index, "--format")
            index += 2 if arg == "--format" else 1
            fmt = value.strip().lower()
            if fmt not in ("table", "json"):
                raise CliError("invalid --format (expected table|json)", code="cli.usage.invalid_format")
            globals_.format = fmt
            continue
        if arg == "--profile" or arg.startswith("--profile="):
            value = _flag_value(argv, index, "--profile")
            index += 2 if arg == "--profile" else 1
            if not value.strip():
                raise CliError("invalid --profile", code="cli.usage.invalid_profile")
            globals_.profile = value.strip()
            continue
        if arg == "--request-id" or arg.startswith("--request-id="):
            value = _flag_value(argv, index, "--request-id")
            index += 2 if arg == "--request-id" else 1
            if not value.strip():
                raise CliError("invalid --request-id", code="cli.usage.invalid_request_id")
            globals_.request_id = value.strip()
            continue
        if arg == "--json" or arg.startswith("--json="):
            value = _flag_value(argv, index, "--json")
            index += 2 if arg == "--json" else 1
            if not value.strip():
                raise CliError("invalid --json (expected comma-separated field names)", code="cli.usage.invalid_json_fields")
            globals_.json_fields = value.strip()
            continue
        if arg == "--jq" or arg.startswith("--jq="):
            value = _flag_value(argv, index, "--jq")
            index += 2 if arg == "--jq" else 1
            if not value.strip():
                raise CliError("invalid --jq (expected filter expression)", code="cli.usage.invalid_jq")
            globals_.jq_expr = value.strip()
            continue
        if arg.startswith("--") and arg.split("=", 1)[0] not in GLOBAL_FLAGS and not command:
            raise CliError(format_unknown_global_flag_message(arg), code="cli.usage.unknown_flag")
        command.append(arg)
        index += 1
    return globals_, command


def _flag_value(argv: list[str], index: int, flag: str) -> str:
    arg = argv[index]
    if arg.startswith(f"{flag}="):
        return arg[len(flag) + 1 :]
    if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
        raise CliError(f"missing value for {flag}", code="cli.usage.missing_flag_value")
    return argv[index + 1]


def consume_boolean_flag(argv: list[str], flag: str) -> tuple[bool, list[str]]:
    rest: list[str] = []
    present = False
    for arg in argv:
        if arg == flag:
            present = True
            continue
        rest.append(arg)
    return present, rest


def assert_api_key_shape(api_key: str) -> None:
    if not api_key.startswith("paybond_sk_"):
        raise CliError(
            "PAYBOND_API_KEY has an unexpected shape",
            category="auth",
            code="cli.auth.invalid_api_key_shape",
            exit_code=EXIT_AUTH,
        )


def consume_flag(argv: list[str], flag: str) -> tuple[bool, str | None, list[str]]:
    rest: list[str] = []
    present = False
    value: str | None = None
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == flag:
            present = True
            if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                raise CliError(f"missing value for {flag}", code="cli.usage.missing_flag_value")
            value = argv[index + 1]
            index += 2
            continue
        if arg.startswith(f"{flag}="):
            present = True
            value = arg[len(flag) + 1 :]
            index += 1
            continue
        rest.append(arg)
        index += 1
    return present, value, rest


def config_file_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME", "").strip() or str(Path.home() / ".config")
    return Path(base) / "paybond" / "config.json"


def load_config_file() -> dict[str, Any]:
    path = config_file_path()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(f"unable to read CLI config: {exc}", category="environment", code="cli.environment.config_read_failed") from exc


def save_config_file(config: dict[str, Any]) -> None:
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{json.dumps(config, indent=2)}\n", encoding="utf-8")
    os.chmod(path, 0o600)


def resolve_config_value(key: str, profile: str | None) -> str | None:
    config = load_config_file()
    if profile:
        profile_values = config.get("profiles", {}).get(profile, {})
        value = profile_values.get(key)
        return value if isinstance(value, str) else None
    values = config.get("values", {})
    value = values.get(key)
    return value if isinstance(value, str) else None


def _validate_cli_gateway(url: str) -> str:
    try:
        return normalize_gateway_base_url(url)
    except InsecureGatewayURLError as exc:
        raise CliError(str(exc), category="validation", code="cli.validation.insecure_gateway") from exc


def set_config_value(key: str, value: str, profile: str | None) -> None:
    if key.lower() == "gateway":
        value = _validate_cli_gateway(value)
    config = load_config_file()
    if profile:
        config.setdefault("profiles", {}).setdefault(profile, {})[key] = value
    else:
        config.setdefault("values", {})[key] = value
    save_config_file(config)


def unset_config_value(key: str, profile: str | None) -> bool:
    config = load_config_file()
    if profile:
        profile_values = config.get("profiles", {}).get(profile)
        if not isinstance(profile_values, dict) or key not in profile_values:
            return False
        del profile_values[key]
        save_config_file(config)
        return True
    values = config.get("values", {})
    if not isinstance(values, dict) or key not in values:
        return False
    del values[key]
    save_config_file(config)
    return True


def list_config_entries(profile: str | None) -> dict[str, str]:
    config = load_config_file()
    entries: dict[str, str] = {}
    if profile:
        for key, value in config.get("profiles", {}).get(profile, {}).items():
            if isinstance(value, str):
                entries[key] = redact_config_value(key, value)
        return entries
    for key, value in config.get("values", {}).items():
        if isinstance(value, str):
            entries[key] = redact_config_value(key, value)
    for profile_name, profile_values in config.get("profiles", {}).items():
        if not isinstance(profile_values, dict):
            continue
        for key, value in profile_values.items():
            if isinstance(value, str):
                entries[f"profiles.{profile_name}.{key}"] = redact_config_value(key, value)
    return entries


def read_env_file_value(body: str, key: str) -> str | None:
    prefix = f"{key}="
    export_prefix = f"export {key}="
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith(export_prefix):
            value = line[len(export_prefix) :].strip()
        elif line.startswith(prefix):
            value = line[len(prefix) :].strip()
        else:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        return value.strip() or None
    return None


def resolve_api_key_with_meta(globals_: GlobalOptions, cwd: Path) -> tuple[str, list[str]]:
    warnings: list[str] = []
    from_process = os.environ.get("PAYBOND_API_KEY", "").strip()
    if from_process:
        warnings.append("cli.warn.env_fallback: using PAYBOND_API_KEY from process environment")
        return from_process, warnings
    env_file = globals_.env_file
    gateway = globals_.gateway
    if globals_.profile:
        profile_env_file = resolve_config_value("env_file", globals_.profile)
        profile_gateway = resolve_config_value("gateway", globals_.profile)
        if profile_env_file:
            env_file = profile_env_file
            warnings.append(f"cli.warn.env_fallback: using profile {globals_.profile} env_file")
        if profile_gateway:
            gateway = _validate_cli_gateway(profile_gateway)
            warnings.append(f"cli.warn.env_fallback: using profile {globals_.profile} gateway")
    globals_.env_file = env_file
    globals_.gateway = gateway
    env_path = Path(env_file) if Path(env_file).is_absolute() else cwd / env_file
    try:
        body = env_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        body = ""
    except OSError as exc:
        raise CliError(f"unable to read env file {env_path}", category="environment", code="cli.environment.env_file_read_failed") from exc
    from_file = read_env_file_value(body, "PAYBOND_API_KEY")
    if from_file:
        return from_file, warnings
    raise CliError(
        "missing PAYBOND_API_KEY; run paybond login or set PAYBOND_API_KEY",
        category="auth",
        code="cli.auth.missing_api_key",
        exit_code=EXIT_AUTH,
        details={"env_file": str(env_path.resolve())},
    )


def resolve_api_key(globals_: GlobalOptions, cwd: Path) -> str:
    api_key, _ = resolve_api_key_with_meta(globals_, cwd)
    return api_key


def describe_credential_source(globals_: GlobalOptions, cwd: Path) -> dict[str, Any]:
    from_process = os.environ.get("PAYBOND_API_KEY", "").strip()
    if from_process:
        return {"source": "process_env", "key_masked": mask_api_key(from_process)}
    env_file = globals_.env_file
    profile = globals_.profile
    if globals_.profile:
        profile_env_file = resolve_config_value("env_file", globals_.profile)
        if profile_env_file:
            env_file = profile_env_file
    env_path = Path(env_file) if Path(env_file).is_absolute() else cwd / env_file
    try:
        body = env_path.read_text(encoding="utf-8")
    except OSError:
        body = ""
    from_file = read_env_file_value(body, "PAYBOND_API_KEY")
    if from_file:
        return {
            "source": "env_file",
            "env_file": str(env_path.resolve()),
            "profile": profile,
            "key_masked": mask_api_key(from_file),
        }
    return {
        "source": "missing",
        "env_file": str(env_path.resolve()),
        "profile": profile,
    }


def gateway_url(base: str, path: str) -> str:
    return normalize_gateway_base_url(base) + (path if path.startswith("/") else f"/{path}")


def gateway_request(ctx: CliContext, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    api_key, credential_warnings = resolve_api_key_with_meta(ctx.globals, ctx.cwd)
    if credential_warnings:
        ctx.globals.credential_warnings = credential_warnings
    headers = {
        "authorization": f"Bearer {api_key}",
        "content-type": "application/json",
        "x-request-id": ctx.globals.request_id,
    }
    url = gateway_url(ctx.globals.gateway, path)
    client = ctx.client or httpx.Client(timeout=30.0)
    owns_client = ctx.client is None
    try:
        try:
            response = client.request(method, url, headers=headers, json=payload)
        except httpx.RequestError as exc:
            raise CliError(str(exc), category="network", code="cli.network.request_failed", exit_code=EXIT_GATEWAY) from exc
        try:
            body = response.json()
        except ValueError as exc:
            raise CliError(
                f"Gateway returned non-JSON response ({response.status_code}).",
                category="gateway",
                code="cli.gateway.non_json",
                exit_code=EXIT_GATEWAY,
            ) from exc
        if not isinstance(body, dict):
            body = {}
        if not response.is_success:
            nested = body.get("error")
            gateway_code = nested.get("code") if isinstance(nested, dict) else str(body.get("code") or "")
            gateway_message = nested.get("message") if isinstance(nested, dict) else str(body.get("message") or "gateway request failed")
            exit_code, category = exit_code_for_http_status(response.status_code)
            raise CliError(
                str(gateway_message or f"Gateway HTTP {response.status_code}"),
                category=category,
                code=str(gateway_code or f"cli.gateway.http_{response.status_code}"),
                exit_code=exit_code,
                details={"gateway_status": response.status_code, "gateway_code": gateway_code or None},
            )
        return body
    finally:
        if owns_client:
            client.close()


def require_confirmation(globals_: GlobalOptions, action: str) -> None:
    if not globals_.yes:
        raise CliError(
            f"confirmation required; re-run with --yes to {action}",
            category="confirmation_required",
            code="cli.confirmation.required",
            exit_code=EXIT_CONFIRMATION,
        )


def read_json_file(path: str, *, stdin: TextIO | None = None) -> dict[str, Any]:
    from paybond_kit.cli.automation import read_json_body

    return read_json_body(path, stdin)


def success_envelope(command: str, globals_: GlobalOptions, data: Any, warnings: list[str] | None = None) -> dict[str, Any]:
    return {
        "ok": True,
        "command": command,
        "data": data,
        "warnings": warnings or [],
        "request_id": globals_.request_id,
        "error": None,
    }


def failure_envelope(command: str, globals_: GlobalOptions, error: CliError) -> dict[str, Any]:
    return {
        "ok": False,
        "command": command,
        "data": None,
        "warnings": [],
        "request_id": globals_.request_id,
        "error": {
            "category": error.category,
            "code": error.code,
            "message": error.message,
            "details": error.details or {},
        },
    }


def prepare_command_output(
    command: str,
    globals_: GlobalOptions,
    data: dict[str, Any],
    warnings: list[str] | None = None,
) -> tuple[Any, list[str], bool]:
    from paybond_kit.cli.automation import apply_automation_transforms

    warning_lines: list[str] = []
    if warnings:
        warning_lines.extend(warnings)
    warning_lines.extend(globals_.credential_warnings)
    merged: list[str] = list(dict.fromkeys(warning_lines))
    automation_requested = bool(globals_.json_fields or globals_.jq_expr)
    transformed = apply_automation_transforms(
        command,
        data,
        json_fields=globals_.json_fields,
        jq_expr=globals_.jq_expr,
    )
    return transformed, merged, automation_requested and globals_.format != "json"


def write_success_output(
    ctx: CliContext,
    canonical: str,
    data: dict[str, Any],
    *,
    warnings: list[str] | None = None,
) -> None:
    output, merged_warnings, automation_plain = prepare_command_output(canonical, ctx.globals, data, warnings)
    if ctx.globals.format == "json":
        ctx.stdout.write(f"{json.dumps(success_envelope(canonical, ctx.globals, output if isinstance(output, dict) else {'value': output}, merged_warnings), indent=2)}\n")
    elif automation_plain:
        ctx.stdout.write(f"{json.dumps(output, indent=2)}\n")
        for warning in merged_warnings:
            ctx.stderr.write(f"{warning}\n")
    elif canonical in ("help", "examples"):
        ctx.stdout.write(f"{data.get('text', '')}\n")
    elif canonical == "completion":
        ctx.stdout.write(str(data.get("script", "")))
    elif canonical == "version" and "package_name" not in data:
        ctx.stdout.write(f"{data.get('version', '')}\n")
    elif canonical == "diagnose":
        for line in data.get("lines", []):
            ctx.stdout.write(f"{line}\n")
    elif canonical == "agent sandbox smoke" and isinstance(data.get("checklist_lines"), list):
        for line in data["checklist_lines"]:
            ctx.stdout.write(f"{line}\n")
        for warning in merged_warnings:
            ctx.stderr.write(f"{warning}\n")
    elif canonical == "agent production attach smoke" and isinstance(data.get("checklist_lines"), list):
        for line in data["checklist_lines"]:
            ctx.stdout.write(f"{line}\n")
        for warning in merged_warnings:
            ctx.stderr.write(f"{warning}\n")
    elif canonical == "agent harbor evidence smoke" and isinstance(data.get("checklist_lines"), list):
        for line in data["checklist_lines"]:
            ctx.stdout.write(f"{line}\n")
        for warning in merged_warnings:
            ctx.stderr.write(f"{warning}\n")
    elif canonical in ("dev smoke", "dev loop") and isinstance(data.get("checklist_lines"), list):
        if canonical == "dev loop" and isinstance(data.get("banner_lines"), list):
            for line in data["banner_lines"]:
                ctx.stdout.write(f"{line}\n")
        for line in data["checklist_lines"]:
            ctx.stdout.write(f"{line}\n")
        for warning in merged_warnings:
            ctx.stderr.write(f"{warning}\n")
    elif canonical == "agent run trace" and isinstance(data.get("trace_lines"), list):
        for line in data["trace_lines"]:
            ctx.stdout.write(f"{line}\n")
        for warning in merged_warnings:
            ctx.stderr.write(f"{warning}\n")
    elif canonical == "policy presets show" and isinstance(data.get("yaml_lines"), list):
        for line in data["yaml_lines"]:
            ctx.stdout.write(f"{line}\n")
        for warning in merged_warnings:
            ctx.stderr.write(f"{warning}\n")
    elif canonical not in ("login", "mcp serve", "dev trace"):
        table_data = output if isinstance(output, dict) else {"value": output}
        for line in render_table(canonical, table_data, ctx.globals, ctx.stdout):
            ctx.stdout.write(f"{line}\n")
        for warning in merged_warnings:
            ctx.stderr.write(f"{warning}\n")


def render_table(command: str, data: dict[str, Any], globals_: GlobalOptions, stdout: TextIO | None = None) -> list[str]:
    from paybond_kit.cli.color import colorize, should_use_color

    use_color = should_use_color(globals_, stdout)
    lines = [colorize(f"{command}: ok", "green", use_color)]
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            lines.append(f"{key}: {json.dumps(value)}")
        else:
            lines.append(f"{key}: {value}")
    return lines
