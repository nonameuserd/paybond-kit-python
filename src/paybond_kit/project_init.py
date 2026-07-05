"""Interactive `paybond init` project scaffold wizard."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from paybond_kit.solution_catalog import get_solution_smoke_defaults, is_known_solution_id, load_solution_manifest

ProjectInitSolution = Literal["shopping", "travel", "saas", "mcp-server", "aws"]
ProjectInitFramework = Literal["openai", "langgraph", "mcp", "generic"]
ProjectInitLanguage = Literal["typescript", "python"]

SOLUTION_CHOICES: list[tuple[ProjectInitSolution, str, str]] = [
    ("shopping", "Shopping", "shopping"),
    ("travel", "Travel", "travel"),
    ("saas", "SaaS", "saas"),
    ("mcp-server", "MCP server", "travel"),
    ("aws", "AWS operator", "aws"),
]

FRAMEWORK_CHOICES: list[tuple[ProjectInitFramework, str]] = [
    ("openai", "OpenAI Agents"),
    ("langgraph", "LangGraph"),
    ("mcp", "MCP"),
    ("generic", "Generic"),
]

SOLUTION_ALIASES: dict[str, ProjectInitSolution] = {
    "shopping": "shopping",
    "shop": "shopping",
    "travel": "travel",
    "saas": "saas",
    "mcp-server": "mcp-server",
    "mcp": "mcp-server",
    "aws": "aws",
    "aws-operator": "aws",
}

FRAMEWORK_ALIASES: dict[str, ProjectInitFramework] = {
    "openai": "openai",
    "openai-agents": "openai",
    "langgraph": "langgraph",
    "mcp": "mcp",
    "generic": "generic",
}


@dataclass(frozen=True, slots=True)
class ProjectInitOptions:
    cwd: str | Path
    solution: ProjectInitSolution | None = None
    max_spend_usd: float | None = None
    framework: ProjectInitFramework | None = None
    language: ProjectInitLanguage | None = None
    non_interactive: bool = False
    force: bool = False
    write_stdout: Callable[[str], None] | None = None
    prompt: Callable[[str], str] | None = None


def _preset_id_for_solution(solution: ProjectInitSolution) -> str:
    for entry in SOLUTION_CHOICES:
        if entry[0] == solution:
            return entry[2]
    return "travel"


def _default_max_spend_usd(solution: ProjectInitSolution) -> float:
    preset_id = _preset_id_for_solution(solution)
    if not is_known_solution_id(preset_id):
        return 200.0
    manifest = load_solution_manifest(preset_id)
    for guardrail in manifest["policy_default"]["guardrails"]:
        if guardrail.startswith("max_spend_usd_"):
            return float(guardrail.removeprefix("max_spend_usd_"))
    return 200.0


def _default_framework_for_solution(solution: ProjectInitSolution) -> ProjectInitFramework:
    return "mcp" if solution == "mcp-server" else "generic"


def _detect_language(cwd: Path) -> ProjectInitLanguage:
    if (cwd / "pyproject.toml").exists() or (cwd / "requirements.txt").exists():
        return "python"
    if (cwd / "package.json").exists():
        return "typescript"
    return "typescript"


def _write_file_if_allowed(path: Path, body: str, force: bool) -> None:
    if path.exists() and not force:
        raise RuntimeError(f"{path} already exists (pass --force to overwrite)")
    path.write_text(body, encoding="utf-8")


def _env_example_body() -> str:
    return "\n".join(
        [
            "# Copy to .env.local after paybond login",
            "PAYBOND_API_KEY=",
            "PAYBOND_GATEWAY_URL=https://api.paybond.ai",
            "",
        ]
    )


def _typescript_config_template() -> str:
    return '''import { Paybond } from "@paybond/kit";

declare const process: {
  env: Record<string, string | undefined>;
};

function readEnvValue(body: string, key: string): string | undefined {
  const pattern = new RegExp("^\\\\s*(?:export\\\\s+)?" + key + "\\\\s*=\\\\s*(.*)$", "m");
  const match = body.match(pattern);
  if (!match) return undefined;
  let value = (match[1] ?? "").trim();
  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      value = JSON.parse(value);
    } catch {
      value = value.slice(1, -1);
    }
  } else if (value.startsWith("'") && value.endsWith("'")) {
    value = value.slice(1, -1);
  }
  return value.trim() || undefined;
}

export async function loadPaybondEnvFile(envFile = ".env.local"): Promise<void> {
  if (process.env.PAYBOND_API_KEY?.trim()) return;
  let body: string;
  try {
    const { readFile } = await import("node:fs/promises");
    body = await readFile(envFile, "utf8");
  } catch (err) {
    if ((err as { code?: unknown })?.code === "ENOENT") return;
    throw err;
  }
  const apiKey = readEnvValue(body, "PAYBOND_API_KEY");
  if (apiKey) {
    process.env.PAYBOND_API_KEY = apiKey;
  }
}

export async function createPaybondClient(): Promise<Paybond> {
  await loadPaybondEnvFile(".env.local");
  const apiKey = process.env.PAYBOND_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("PAYBOND_API_KEY is required; run paybond login");
  }
  return Paybond.open({
    apiKey,
    gatewayBaseUrl: process.env.PAYBOND_GATEWAY_URL ?? process.env.PAYBOND_GATEWAY_BASE_URL,
    expectedEnvironment: "sandbox",
  });
}
'''


def _python_config_template() -> str:
    return '''import os
from pathlib import Path

from paybond_kit import Paybond


def _read_env_value(body: str, key: str) -> str | None:
    for raw_line in body.splitlines():
        line = raw_line.strip()
        for prefix in (f"export {key}=", f"{key}="):
            if line.startswith(prefix):
                value = line[len(prefix):].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\\"":
                    value = value[1:-1]
                return value.strip() or None
    return None


def load_paybond_env_file(env_file: str = ".env.local") -> None:
    if os.environ.get("PAYBOND_API_KEY", "").strip():
        return
    path = Path(env_file)
    try:
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    api_key = _read_env_value(body, "PAYBOND_API_KEY")
    if api_key:
        os.environ["PAYBOND_API_KEY"] = api_key


async def create_paybond_client() -> Paybond:
    load_paybond_env_file(".env.local")
    api_key = os.environ.get("PAYBOND_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("PAYBOND_API_KEY is required; run paybond login")
    return await Paybond.open(
        api_key=api_key,
        gateway_base_url=(
            os.environ.get("PAYBOND_GATEWAY_URL")
            or os.environ.get("PAYBOND_GATEWAY_BASE_URL")
            or "https://api.paybond.ai"
        ),
        expected_environment="sandbox",
    )
'''


def _instrument_method(framework: ProjectInitFramework) -> str:
    return {
        "openai": "instrumentOpenAI",
        "langgraph": "instrumentLangGraph",
        "mcp": "instrumentMCP",
        "generic": "instrument",
    }[framework]


def _typescript_instrument_template(
    solution: ProjectInitSolution,
    framework: ProjectInitFramework,
    max_spend_usd: float,
) -> str:
    preset_id = _preset_id_for_solution(solution)
    manifest = load_solution_manifest(preset_id) if is_known_solution_id(preset_id) else None
    completion_preset = manifest["completion_preset"] if manifest else "cost_and_completion"
    primary_operation = manifest["primary_operation"] if manifest else "travel.book_hotel"
    requested_spend_cents = int(round(max_spend_usd * 100))
    return f'''import {{ createPaybondClient }} from "./paybond.config.js";
import {{ Paybond, createPaybondToolRegistry }} from "@paybond/kit";

const POLICY_FILE = "./paybond.policy.yaml";
const COMPLETION_PRESET_ID = "{completion_preset}";
const DEFAULT_OPERATION = "{primary_operation}";
const DEFAULT_REQUESTED_SPEND_CENTS = {requested_spend_cents};

async function bookHotel(args: {{ city: string; estimatedPriceCents: number }}) {{
  return {{
    reservation: {{
      status: "confirmed" as const,
      price_cents: args.estimatedPriceCents,
      city: args.city,
    }},
  }};
}}

async function searchWeb(args: {{ query: string }}) {{
  return {{ hits: [{{ title: args.query, url: "https://example.com" }}] }};
}}

export function createAgentToolRegistry() {{
  return createPaybondToolRegistry({{
    sideEffecting: {{
      "travel.book_hotel": {{
        spendCents: (args: {{ estimatedPriceCents: number }}) => args.estimatedPriceCents,
        evidencePreset: COMPLETION_PRESET_ID,
        evidenceMapper: (result: Awaited<ReturnType<typeof bookHotel>>) => ({{
          status: result.reservation.status === "confirmed" ? "completed" : result.reservation.status,
          cost_cents: result.reservation.price_cents,
        }}),
      }},
    }},
    defaultDeny: true,
  }});
}}

export async function createInstrumentedAgent() {{
  const paybond = await createPaybondClient();
  const tools = {{
    "travel.book_hotel": async (args: {{ city: string; estimatedPriceCents: number }}) => bookHotel(args),
    searchWeb: async (args: {{ query: string }}) => searchWeb(args),
  }};
  return paybond.{_instrument_method(framework)}({{
    policy: POLICY_FILE,
    tools,
    sandbox: true,
  }});
}}

// Production (signing v7): publish managed template head, then:
// import {{ PaybondPolicy }} from "@paybond/kit";
// const policy = await PaybondPolicy.load(POLICY_FILE);
// const created = await paybond.intents.createWithPolicyBinding(
//   policy.toIntentCreateInput({{ principalDid, principalSigningSeed, payeeDid, payeeSigningSeed, deadlineRfc3339, settlementRail: "stripe_connect", recognitionProof, publishedPolicyHead }}),
// );
// Attach middleware: instrumented.bind({{ intentId, capabilityToken, productionEvidence }}) or agentRun.bind({{ attach: ... }})
'''


def _python_instrument_template(
    solution: ProjectInitSolution,
    framework: ProjectInitFramework,
    max_spend_usd: float,
) -> str:
    preset_id = _preset_id_for_solution(solution)
    manifest = load_solution_manifest(preset_id) if is_known_solution_id(preset_id) else None
    completion_preset = manifest["completion_preset"] if manifest else "cost_and_completion"
    primary_operation = manifest["primary_operation"] if manifest else "travel.book_hotel"
    requested_spend_cents = int(round(max_spend_usd * 100))
    instrument_call = {
        "generic": "await paybond.instrument(policy=POLICY_FILE, tools=TOOLS, sandbox=True)",
        "langgraph": "await paybond.instrument_langgraph(policy=POLICY_FILE, tools=TOOLS, sandbox=True)",
        "openai": "await paybond.instrument_openai(policy=POLICY_FILE, tools=TOOLS, sandbox=True)",
        "mcp": "await paybond.instrument_mcp(policy=POLICY_FILE, tools=TOOLS, sandbox=True)",
    }[framework]
    return f'''from paybond_config import create_paybond_client
from paybond_kit.agent import create_paybond_tool_registry

POLICY_FILE = "./paybond.policy.yaml"
COMPLETION_PRESET_ID = "{completion_preset}"
DEFAULT_OPERATION = "{primary_operation}"
DEFAULT_REQUESTED_SPEND_CENTS = {requested_spend_cents}


async def book_hotel(args: dict[str, object]) -> dict[str, object]:
    price_cents = int(args["estimated_price_cents"])
    return {{
        "reservation": {{
            "status": "confirmed",
            "price_cents": price_cents,
            "city": str(args["city"]),
        }},
    }}


async def search_web(args: dict[str, object]) -> dict[str, object]:
    return {{"hits": [{{"title": str(args["query"]), "url": "https://example.com"}}]}}


def create_agent_tool_registry() -> object:
    return create_paybond_tool_registry(
        {{
            "side_effecting": {{
                "travel.book_hotel": {{
                    "spend_cents": lambda args: int(args["estimated_price_cents"]),
                    "evidence_preset": COMPLETION_PRESET_ID,
                    "evidence_mapper": lambda result, _ctx: {{
                        "status": (
                            "completed"
                            if result["reservation"]["status"] == "confirmed"
                            else result["reservation"]["status"]
                        ),
                        "cost_cents": result["reservation"]["price_cents"],
                    }},
                }},
            }},
            "default_deny": True,
        }}
    )


TOOLS = {{
    "travel.book_hotel": book_hotel,
    "search.web": search_web,
}}


async def create_instrumented_agent():
    paybond = await create_paybond_client()
    return {instrument_call}


# Production (signing v7): publish managed template head, then:
# from paybond_kit.policy import PaybondPolicy
# policy = await PaybondPolicy.load(POLICY_FILE)
# created = await paybond.intents.create_with_policy_binding(
#     **policy.to_intent_create_input(principal_did=..., principal_signing_seed=..., ...).__dict__
# )
# Attach middleware: await instrumented.bind(intent_id=..., capability_token=..., production_evidence=...)
'''


def _smoke_command(preset_id: str) -> str:
    if not is_known_solution_id(preset_id):
        preset_id = "travel"
    defaults = get_solution_smoke_defaults(preset_id)
    result_body = json.dumps(defaults["result_body"], separators=(",", ":"))
    return " ".join(
        [
            "paybond agent sandbox smoke",
            "--policy-file paybond.policy.yaml",
            f"--operation {defaults['operation']}",
            f"--requested-spend-cents {defaults['requested_spend_cents']}",
            f"--evidence-preset {defaults['evidence_preset']}",
            f"--result-body '{result_body}'",
            "--format json",
        ]
    )


def _upsert_package_json_smoke_script(cwd: Path, smoke_command: str, force: bool) -> Path | None:
    package_json_path = cwd / "package.json"
    if package_json_path.exists():
        payload = json.loads(package_json_path.read_text(encoding="utf-8"))
        scripts = dict(payload.get("scripts") or {})
        if scripts.get("smoke") and scripts["smoke"] != smoke_command and not force:
            raise RuntimeError(f"{package_json_path} already defines scripts.smoke (pass --force to overwrite)")
        scripts["smoke"] = smoke_command
        payload["scripts"] = scripts
        package_json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return package_json_path
    body = json.dumps({"private": True, "type": "module", "scripts": {"smoke": smoke_command}}, indent=2) + "\n"
    _write_file_if_allowed(package_json_path, body, force)
    return package_json_path


def _resolve_interactive_options(options: ProjectInitOptions) -> tuple[
    ProjectInitSolution,
    float,
    ProjectInitFramework,
    ProjectInitLanguage,
]:
    cwd = Path(options.cwd)
    prompt = options.prompt or (lambda question: input(question).strip())
    interactive = not options.non_interactive and sys.stdin.isatty() and sys.stdout.isatty()
    language = options.language or _detect_language(cwd)

    solution = options.solution
    if solution is None:
        if interactive:
            labels = "  ".join(f"[{index + 1}] {label}" for index, (_, label, _) in enumerate(SOLUTION_CHOICES))
            options.write_stdout and options.write_stdout(f"What are you building?  {labels}")
            answer = prompt("> ")
            index = int(answer) - 1 if answer.isdigit() else 1
            solution = SOLUTION_CHOICES[index][0]
        else:
            solution = "travel"

    max_spend_usd = options.max_spend_usd if options.max_spend_usd is not None else _default_max_spend_usd(solution)
    if options.max_spend_usd is None and interactive:
        answer = prompt(f"Maximum spend? [${max_spend_usd}] ")
        if answer.strip():
            max_spend_usd = float(answer)

    framework = options.framework or _default_framework_for_solution(solution)
    if options.framework is None and solution != "mcp-server" and interactive:
        labels = "  ".join(f"[{index + 1}] {label}" for index, (_, label) in enumerate(FRAMEWORK_CHOICES))
        options.write_stdout and options.write_stdout(f"Framework?  {labels}")
        answer = prompt("> ")
        index = int(answer) - 1 if answer.isdigit() else 3
        framework = FRAMEWORK_CHOICES[index][0]

    return solution, max_spend_usd, framework, language


def run_project_init(options: ProjectInitOptions) -> dict[str, object]:
    import paybond_kit.cli.policy as _policy_cli  # noqa: F401 — establish import order for policy.init
    from paybond_kit.policy.init import ScaffoldPolicyFromPresetOptions, scaffold_policy_from_preset

    cwd = Path(options.cwd)
    solution, max_spend_usd, framework, language = _resolve_interactive_options(options)
    preset_id = _preset_id_for_solution(solution)
    files: list[str] = []

    scaffold_policy_from_preset(
        ScaffoldPolicyFromPresetOptions(
            out=cwd / "paybond.policy.yaml",
            preset_id=preset_id,
            max_spend_usd=max_spend_usd,
            force=options.force,
        )
    )
    files.append("paybond.policy.yaml")

    config_name = "paybond.config.py" if language == "python" else "paybond.config.ts"
    instrument_name = "paybond.instrument.py" if language == "python" else "paybond.instrument.ts"
    _write_file_if_allowed(
        cwd / config_name,
        _python_config_template() if language == "python" else _typescript_config_template(),
        options.force,
    )
    files.append(config_name)
    _write_file_if_allowed(
        cwd / instrument_name,
        _python_instrument_template(solution, framework, max_spend_usd)
        if language == "python"
        else _typescript_instrument_template(solution, framework, max_spend_usd),
        options.force,
    )
    files.append(instrument_name)
    _write_file_if_allowed(cwd / ".env.example", _env_example_body(), options.force)
    files.append(".env.example")

    smoke_command = _smoke_command(preset_id)
    if language == "typescript":
        _upsert_package_json_smoke_script(cwd, smoke_command, options.force)
        files.append("package.json")

    write_stdout = options.write_stdout or (lambda line: sys.stdout.write(f"{line}\n"))
    for file_name in files:
        write_stdout(f"Created {file_name}")
    write_stdout("")
    write_stdout("Ready to run:")
    write_stdout("  paybond login")
    write_stdout("  npm run smoke" if language == "typescript" else f"  {smoke_command}")

    return {
        "solution": solution,
        "preset_id": preset_id,
        "max_spend_usd": max_spend_usd,
        "framework": framework,
        "language": language,
        "files": files,
        "smoke_command": smoke_command,
    }


def parse_project_init_argv(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--help", "-h", action="store_true")
    parser.add_argument("--solution")
    parser.add_argument("--max-spend-usd", type=float)
    parser.add_argument("--max-spend", type=float, dest="max_spend_usd")
    parser.add_argument("--framework")
    parser.add_argument("--language")
    parser.add_argument("--template")
    parser.add_argument("--repo", dest="template")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)
