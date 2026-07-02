"""Resolve bundled dev trace dashboard assets."""

from __future__ import annotations

from pathlib import Path


def resolve_dev_trace_ui_dashboard_path(cwd: str | Path | None = None) -> Path:
    """Resolve bundled or monorepo dev trace dashboard HTML."""
    base = Path(cwd or Path.cwd())
    package_data = Path(__file__).resolve().parents[1] / "data/dev/trace-ui/dashboard.html"
    candidates = [
        base / "kit/dev/trace-ui/dashboard.html",
        package_data,
        Path(__file__).resolve().parents[4] / "dev/trace-ui/dashboard.html",
        Path(__file__).resolve().parents[5] / "kit/dev/trace-ui/dashboard.html",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "Dev trace dashboard not found. Run from the Paybond monorepo or install paybond-kit with bundled dev assets."
    )


def load_dev_trace_dashboard_html(cwd: str | Path | None = None) -> str:
    """Load the self-contained dev trace dashboard HTML shell."""
    return resolve_dev_trace_ui_dashboard_path(cwd).read_text(encoding="utf-8")
