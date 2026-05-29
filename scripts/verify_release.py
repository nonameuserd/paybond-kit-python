from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
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
)


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


def inspect_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
    for name in names:
        normalized = f"/{name}"
        if any(fragment in normalized for fragment in BANNED_FRAGMENTS):
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
    for name in names:
        normalized = f"/{name}"
        if any(fragment in normalized for fragment in BANNED_FRAGMENTS):
            raise RuntimeError(f"wheel should not include local artifact path: {name}")
    if not any(".dist-info/licenses/LICENSE" in name or name.endswith(".dist-info/LICENSE") for name in names):
        raise RuntimeError("wheel must include LICENSE")
    extras = set(metadata.get_all("Provides-Extra", []))
    if {"langgraph", "mcp"} - extras:
        raise RuntimeError(f"missing extras metadata: expected langgraph/mcp, got {sorted(extras)}")
    requires = metadata.get_all("Requires-Dist", [])
    for expected in ("langgraph", "langchain-core", "mcp"):
        if not any(req.startswith(expected) for req in requires):
            raise RuntimeError(f"missing wheel dependency metadata for {expected}")


def smoke_install(wheel: Path) -> None:
    scratch = Path(tempfile.mkdtemp(prefix="paybond-kit-py-"))
    try:
        venv_dir = scratch / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        python = venv_dir / "bin" / "python"
        run(str(python), "-m", "pip", "install", "--no-deps", str(wheel))
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
        run(str(python), "-c", code)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def maybe_twine_check(paths: list[Path]) -> None:
    twine = find_tool("twine")
    if twine:
        run(twine, "check", *(str(path) for path in paths))
        return
    print("twine not found; skipped `twine check` and relied on metadata inspection instead.", file=sys.stderr)


def run_pytest() -> None:
    python = ROOT / ".venv" / "bin" / "python"
    if not python.exists():
        python = Path(sys.executable)
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
    run(maturin, "build", "--sdist", "--release", "--out", str(DIST), cwd=ROOT)

    artifacts = sorted(DIST.iterdir())
    wheel = next(path for path in artifacts if path.suffix == ".whl")
    sdist = next(path for path in artifacts if path.suffixes[-2:] == [".tar", ".gz"])

    inspect_wheel(wheel)
    inspect_sdist(sdist)
    maybe_twine_check(artifacts)
    smoke_install(wheel)


if __name__ == "__main__":
    main()
