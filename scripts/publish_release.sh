#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MATURIN_BIN="${ROOT}/.venv/bin/maturin"

if [[ ! -x "${MATURIN_BIN}" ]]; then
  if command -v maturin >/dev/null 2>&1; then
    MATURIN_BIN="$(command -v maturin)"
  else
    echo "maturin not found on PATH or in ${ROOT}/.venv/bin" >&2
    exit 1
  fi
fi

if [[ -z "${MATURIN_PYPI_TOKEN:-}" ]]; then
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "CI publishes with PyPI Trusted Publishing via pypa/gh-action-pypi-publish; MATURIN_PYPI_TOKEN is not required." >&2
    exit 1
  fi
  echo "MATURIN_PYPI_TOKEN must be set to a PyPI API token for manual publish." >&2
  echo "For CI releases, configure PyPI Trusted Publishing instead (see docs/kit/package-provenance.md)." >&2
  exit 1
fi

python3 "${ROOT}/scripts/verify_release.py"
"${MATURIN_BIN}" publish --non-interactive
