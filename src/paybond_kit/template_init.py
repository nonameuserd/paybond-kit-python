"""Copy bundled starter templates for `paybond init --template`."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, TypedDict

TemplateId = Literal[
    "travel-agent",
    "mastra-travel-agent",
    "vercel-shopping-agent",
    "openai-agents-demo",
    "openai-shopping-agent",
    "claude-agents-demo",
    "mcp-coding-agent",
    "procurement-agent",
    "invoice-agent",
    "crewai-procurement-agent",
    "microsoft-agent-framework-procurement-agent",
    "aws-operator",
    "shopify-shopping-agent",
]

TEMPLATE_ALIASES: dict[str, TemplateId] = {
    "travel-agent": "travel-agent",
    "paybond-travel-agent": "travel-agent",
    "mastra-travel-agent": "mastra-travel-agent",
    "paybond-mastra-travel-agent": "mastra-travel-agent",
    "vercel-shopping-agent": "vercel-shopping-agent",
    "paybond-vercel-shopping-agent": "vercel-shopping-agent",
    "openai-agents-demo": "openai-agents-demo",
    "paybond-openai-agents-demo": "openai-agents-demo",
    "openai-shopping-agent": "openai-shopping-agent",
    "claude-agents-demo": "claude-agents-demo",
    "paybond-claude-agents-demo": "claude-agents-demo",
    "mcp-coding-agent": "mcp-coding-agent",
    "paybond-mcp-coding-agent": "mcp-coding-agent",
    "procurement-agent": "procurement-agent",
    "paybond-procurement-agent": "procurement-agent",
    "invoice-agent": "invoice-agent",
    "paybond-invoice-agent": "invoice-agent",
    "crewai-procurement-agent": "crewai-procurement-agent",
    "paybond-crewai-procurement-agent": "crewai-procurement-agent",
    "microsoft-agent-framework-procurement-agent": "microsoft-agent-framework-procurement-agent",
    "paybond-microsoft-agent-framework-procurement-agent": "microsoft-agent-framework-procurement-agent",
    "aws-operator": "aws-operator",
    "paybond-aws-operator": "aws-operator",
    "shopify-shopping-agent": "shopify-shopping-agent",
    "paybond-shopify-shopping-agent": "shopify-shopping-agent",
}


class TemplateManifestEntry(TypedDict):
    id: str
    repo: str
    title: str
    language: str
    framework: str
    preset: str | None
    primary_operation: str
    requested_spend_cents: int
    evidence_preset: str
    smoke_result_body: dict[str, Any]


class TemplateManifest(TypedDict):
    version: int
    templates: list[TemplateManifestEntry]


TEMPLATE_FRAMEWORK_ALIASES = {
    "generic": "generic",
    "langgraph": "langgraph",
    "vercel-ai": "vercel-ai",
    "vercel": "vercel-ai",
    "openai": "openai-agents",
    "openai-agents": "openai-agents",
    "claude": "claude-agents",
    "claude-agents": "claude-agents",
    "mcp": "mcp",
    "mastra": "mastra",
    "crewai": "crewai",
    "microsoft-agent-framework": "microsoft-agent-framework",
    "maf": "microsoft-agent-framework",
}


def normalize_template_framework(raw: str) -> str:
    normalized = TEMPLATE_FRAMEWORK_ALIASES.get(raw.strip().lower())
    if not normalized:
        raise ValueError(f"invalid --framework for template init: {raw}")
    return normalized


def _framework_for_entry(entry: TemplateManifestEntry) -> str:
    return normalize_template_framework(entry["framework"])


@dataclass(frozen=True, slots=True)
class CopyTemplateOptions:
    cwd: str | Path
    template_id: TemplateId
    framework: str | None = None
    force: bool = False
    write_stdout: Callable[[str], None] | None = None


def _templates_roots() -> list[Path]:
    module_dir = Path(__file__).resolve().parent
    paths = [
        module_dir / "data" / "templates",
        module_dir.parents[3] / "kit" / "ts" / "templates",
        module_dir.parents[2] / "templates",
    ]
    env_root = os.environ.get("PAYBOND_TEMPLATES_DIR", "").strip()
    if env_root:
        paths.insert(0, Path(env_root))
    return paths


def _first_existing_dir(candidates: list[Path]) -> Path:
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise RuntimeError("bundled Paybond templates directory not found")


def load_template_manifest() -> TemplateManifest:
    root = _first_existing_dir(_templates_roots())
    raw = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    return raw


def normalize_template_id(raw: str) -> TemplateId:
    normalized = TEMPLATE_ALIASES.get(raw.strip().lower())
    if not normalized:
        raise ValueError(f"invalid --template: {raw}")
    return normalized


def list_template_entries() -> list[TemplateManifestEntry]:
    return list(load_template_manifest()["templates"])


def resolve_template_entry(template_id: TemplateId) -> TemplateManifestEntry:
    for entry in load_template_manifest()["templates"]:
        if entry["id"] == template_id:
            return entry
    raise ValueError(f"unknown template: {template_id}")


def resolve_template_for_init(template_id: TemplateId, framework: str | None = None) -> TemplateManifestEntry:
    entry = resolve_template_entry(template_id)
    if framework:
        normalized = normalize_template_framework(framework)
        if _framework_for_entry(entry) != normalized:
            raise ValueError(
                f"template {entry['id']} uses framework {entry['framework']}; "
                f"--framework {framework} does not match"
            )
    return entry


def _smoke_command_for_entry(entry: TemplateManifestEntry) -> str:
    result_body = json.dumps(entry["smoke_result_body"], separators=(",", ":"))
    return " ".join(
        [
            "paybond agent sandbox smoke",
            "--policy-file paybond.policy.yaml",
            f"--operation {entry['primary_operation']}",
            f"--requested-spend-cents {entry['requested_spend_cents']}",
            f"--evidence-preset {entry['evidence_preset']}",
            f"--result-body '{result_body}'",
            "--format json",
        ]
    )


def copy_template_to_directory(options: CopyTemplateOptions) -> dict[str, object]:
    entry = resolve_template_for_init(options.template_id, options.framework)
    templates_root = _first_existing_dir(_templates_roots())
    source_dir = templates_root / entry["repo"]
    if not source_dir.is_dir():
        raise RuntimeError(f"template source missing: {entry['repo']}")

    cwd = Path(options.cwd)
    copied: list[str] = []
    write_stdout = options.write_stdout

    for child in source_dir.iterdir():
        target = cwd / child.name
        if target.exists() and not options.force:
            raise RuntimeError(f"{child.name} already exists (pass --force to overwrite)")
        if child.is_dir():
            shutil.copytree(child, target, dirs_exist_ok=options.force)
        else:
            shutil.copy2(child, target)
        copied.append(child.name)
        if write_stdout:
            write_stdout(f"Created {child.name}")

    smoke_command = _smoke_command_for_entry(entry)
    if write_stdout:
        write_stdout("")
        write_stdout("Ready to run:")
        write_stdout("  paybond login")
        if entry["language"] == "python":
            write_stdout("  pip install -r requirements.txt")
        else:
            write_stdout("  npm install")
        write_stdout(
            "  npm run smoke"
            if entry["language"] == "typescript"
            else f"  {smoke_command}"
        )

    return {
        "template_id": entry["id"],
        "repo": entry["repo"],
        "title": entry["title"],
        "language": entry["language"],
        "framework": entry["framework"],
        "preset": entry.get("preset"),
        "files": copied,
        "smoke_command": smoke_command,
    }


def template_init_usage() -> str:
    return "\n".join(
        [
            "Usage: paybond init [--template <id>|--repo <slug>] [--framework <name>] [--force]",
            "       paybond init [--solution ...] [--framework ...]  (wizard scaffold)",
            "",
            "Templates:",
            "  travel-agent, mastra-travel-agent, vercel-shopping-agent, openai-agents-demo, openai-shopping-agent,",
            "  claude-agents-demo, mcp-coding-agent, procurement-agent, invoice-agent, crewai-procurement-agent,",
            "  microsoft-agent-framework-procurement-agent, aws-operator",
            "",
            "Examples:",
            "  paybond init --template travel-agent --framework langgraph",
            "  paybond init --template paybond-invoice-agent --force",
            "  paybond init --solution travel --framework langgraph --non-interactive",
        ]
    )
