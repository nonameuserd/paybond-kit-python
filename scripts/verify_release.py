from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from email.parser import Parser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist-release"
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PROJECT_VERSION = str(PROJECT["project"]["version"])
BANNED_FRAGMENTS = (
    "/.venv/",
    "/.pytest_cache/",
    "/__pycache__/",
    "/rust/target/",
    "/node_modules/",
)


def _is_banned_local_artifact(name: str) -> bool:
    normalized = f"/{name}"
    if any(fragment in normalized for fragment in BANNED_FRAGMENTS):
        return True
    # Accidental template builds only (avoid matching *.dist-info paths).
    if "/templates/" in normalized and "/dist/" in normalized:
        return True
    return False


def run(
    *args: str,
    cwd: Path | None = None,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        args,
        cwd=str(cwd or ROOT),
        check=True,
        text=True,
        capture_output=capture,
        env=env,
    )
    return completed.stdout if capture else ""


def find_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    local = ROOT / ".venv" / "bin" / name
    return str(local) if local.exists() else None


def release_python() -> Path:
    python = ROOT / ".venv" / "bin" / "python"
    return python if python.exists() else Path(sys.executable)


def inspect_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
    for name in names:
        normalized = f"/{name}"
        if _is_banned_local_artifact(name):
            raise RuntimeError(f"sdist should not include local artifact path: {name}")
        if normalized.endswith(("/src/paybond_kit/_native.so", "/src/paybond_kit/_native.pyd")):
            raise RuntimeError(f"sdist should not include prebuilt native extension: {name}")
    if not any(name.endswith("/LICENSE") for name in names):
        raise RuntimeError("sdist must include LICENSE")


def inspect_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
        entry_points_name = next((name for name in names if name.endswith(".dist-info/entry_points.txt")), None)
        entry_points = archive.read(entry_points_name).decode("utf-8") if entry_points_name else ""
    for name in names:
        if _is_banned_local_artifact(name):
            raise RuntimeError(f"wheel should not include local artifact path: {name}")
    if not any(".dist-info/licenses/LICENSE" in name or name.endswith(".dist-info/LICENSE") for name in names):
        raise RuntimeError("wheel must include LICENSE")
    extras = set(metadata.get_all("Provides-Extra", []))
    if {"langgraph", "mcp"} - extras:
        raise RuntimeError(f"missing extras metadata: expected langgraph/mcp, got {sorted(extras)}")
    requires = metadata.get_all("Requires-Dist", [])
    if not any(req.startswith("jsonschema") for req in requires):
        raise RuntimeError("wheel must declare jsonschema runtime dependency")
    for expected in ("langgraph", "langchain-core", "mcp"):
        if not any(req.startswith(expected) for req in requires):
            raise RuntimeError(f"missing wheel dependency metadata for {expected}")
    normalized_entry_points = {line.replace(" ", "") for line in entry_points.splitlines()}
    if "paybond-kit-login=paybond_kit.login:main" not in normalized_entry_points:
        raise RuntimeError("wheel must expose paybond-kit-login console script")
    if "paybond-kit-init=paybond_kit.init:main" not in normalized_entry_points:
        raise RuntimeError("wheel must expose paybond-kit-init console script")
    if "paybond=paybond_kit.cli.router:main" not in normalized_entry_points:
        raise RuntimeError("wheel must expose paybond console script")
    if "paybond-mcp-server=paybond_kit.mcp_server:main" not in normalized_entry_points:
        raise RuntimeError("wheel must expose paybond-mcp-server console script")
    if "paybond_kit/data/policy/presets/travel.yaml" not in names:
        raise RuntimeError("wheel must ship bundled travel policy preset")


def assert_contains_all(text: str, fragments: tuple[str, ...], label: str) -> None:
    for fragment in fragments:
        if fragment not in text:
            raise RuntimeError(f"{label} missing expected fragment: {fragment}")


def run_init_main(python: Path, env: dict[str, str], argv: list[str]) -> None:
    run(
        str(python),
        "-c",
        "import sys; from paybond_kit.init import main; raise SystemExit(main(sys.argv[1:]))",
        *argv,
        env=env,
    )


def smoke_scaffold(python: Path, env: dict[str, str], scratch: Path) -> None:
    out = scratch / "paybond_paid_tool_guard.py"
    run_init_main(
        python,
        env,
        ["--preset", "paid-tool-guard", "--framework", "provider-agnostic", "--out", str(out)],
    )
    assert_contains_all(
        out.read_text(encoding="utf-8"),
        (
            'async def open_paybond_from_env(env_file: str | None = ".env.local") -> Paybond',
            "paybond.intents.create_with_policy_binding",
            'COMPLETION_PRESET_ID = "cost_and_completion"',
            "def build_completion_evidence",
            'os.environ.get("PAYBOND_GATEWAY_URL")',
            'os.environ.get("PAYBOND_GATEWAY_BASE_URL")',
            "async def bootstrap_sandbox_guardrail_intent",
            "completion_preset=COMPLETION_PRESET_ID",
            "def wrap_paid_tool",
            "async def submit_sandbox_evidence",
            "paybond.guardrails.bootstrap_sandbox",
            "paybond.spend_guard(guardrail.intent_id, guardrail.capability_token)",
            "paybond.guardrails.submit_sandbox_evidence",
            "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
        ),
        "paybond-kit-init scaffold",
    )
    scaffold_body = out.read_text(encoding="utf-8")
    for banned in ("replaceable_smoke_test_paid_tool", "run_sandbox_smoke_path", "sandbox-confirmation"):
        if banned in scaffold_body:
            raise RuntimeError(f"paybond-kit-init scaffold should not include generated paid-tool implementation fragment: {banned}")

    blocked = subprocess.run(
        [
            str(python),
            "-c",
            "import sys; from paybond_kit.init import main; raise SystemExit(main(sys.argv[1:]))",
            "--preset",
            "paid-tool-guard",
            "--out",
            str(out),
        ],
        cwd=str(scratch),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    if blocked.returncode == 0 or "already exists" not in blocked.stderr:
        raise RuntimeError("paybond-kit-init must refuse to overwrite scaffolds without --force")

    run_init_main(
        python,
        env,
        ["--preset", "paid-tool-guard", "--framework", "mcp", "--out", str(out), "--force"],
    )
    assert_contains_all(
        out.read_text(encoding="utf-8"),
        ("Use the same operation name in your MCP tool handler before executing paid work.",),
        "paybond-kit-init --force scaffold",
    )


def smoke_completion_evidence_consumer(wheel: Path) -> None:
    scratch_parent = Path("/private/tmp") if Path("/private/tmp").is_dir() and os.access("/private/tmp", os.W_OK) else None
    scratch = Path(tempfile.mkdtemp(prefix="paybond-kit-py-consumer-", dir=scratch_parent))
    try:
        python = release_python()
        uv = find_tool("uv")
        if uv:
            run(
                uv,
                "pip",
                "install",
                "--python",
                str(python),
                "--target",
                str(scratch / "site"),
                str(wheel),
            )
        else:
            run(
                str(python),
                "-m",
                "pip",
                "install",
                "--target",
                str(scratch / "site"),
                str(wheel),
            )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(scratch / "site")
        run(
            str(python),
            "-c",
            (
                "from paybond_kit.completion_validate_evidence import validate_completion_evidence\n"
                "report = validate_completion_evidence("
                'preset_id="cost_and_completion", canonical_payload={"status": "completed", "cost_cents": 100}'
                ")\n"
                "assert report['canonical_schema_ok'], report\n"
                "from paybond_kit.policy.presets import resolve_policy_preset_path\n"
                "travel_path = resolve_policy_preset_path('travel')\n"
                "assert travel_path.endswith('travel.yaml'), travel_path\n"
                "from paybond_kit.cli.router import main\n"
                "print('completion evidence import ok')\n"
            ),
            env=env,
        )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def smoke_install(wheel: Path) -> None:
    scratch_parent = Path("/private/tmp") if Path("/private/tmp").is_dir() and os.access("/private/tmp", os.W_OK) else None
    scratch = Path(tempfile.mkdtemp(prefix="paybond-kit-py-", dir=scratch_parent))
    try:
        python = release_python()
        site_dir = scratch / "site"
        uv = find_tool("uv")
        if uv:
            run(uv, "pip", "install", "--python", str(python), "--target", str(site_dir), "--no-deps", "--no-index", "--no-cache", str(wheel))
        else:
            run(str(python), "-m", "pip", "install", "--no-deps", "--target", str(site_dir), str(wheel))
        env = dict(os.environ)
        env["PYTHONPATH"] = str(site_dir)
        code = (
            "from importlib import metadata\n"
            "from pathlib import Path\n"
            "dist = metadata.distribution('paybond-kit')\n"
            f"assert dist.version == {PROJECT_VERSION!r}\n"
            "site = Path(next(p for p in metadata.files('paybond-kit') if str(p).endswith('__init__.py')).locate())\n"
            "package_dir = site.parent\n"
            "assert any(package_dir.glob('_native*.so')) or any(package_dir.glob('_native*.pyd'))\n"
            "print(dist.version)\n"
        )
        run(str(python), "-c", code, env=env)
        smoke_scaffold(python, env, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def maybe_twine_check(paths: list[Path]) -> None:
    twine = find_tool("twine")
    if twine:
        run(twine, "check", *(str(path) for path in paths))
        return
    print("twine not found; skipped `twine check` and relied on metadata inspection instead.", file=sys.stderr)


def run_pytest() -> None:
    python = release_python()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    run(str(python), "-m", "pytest", cwd=ROOT, env=env)


def main() -> None:
    maturin = find_tool("maturin")
    if not maturin:
        raise SystemExit("maturin not found on PATH or in kit/python/.venv/bin")

    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)

    run_pytest()
    run(maturin, "build", "--sdist", "--release", "--interpreter", str(release_python()), "--out", str(DIST), cwd=ROOT)

    artifacts = sorted(DIST.iterdir())
    wheel = next(path for path in artifacts if path.suffix == ".whl")
    sdist = next(path for path in artifacts if path.suffixes[-2:] == [".tar", ".gz"])

    inspect_wheel(wheel)
    inspect_sdist(sdist)
    maybe_twine_check(artifacts)
    smoke_completion_evidence_consumer(wheel)
    smoke_install(wheel)


if __name__ == "__main__":
    main()
