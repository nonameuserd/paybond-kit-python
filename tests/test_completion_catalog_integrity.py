"""Tests for bundled completion catalog SHA-256 integrity verification."""

from __future__ import annotations

import json

import pytest

from paybond_kit.completion_catalog import load_completion_catalog
from paybond_kit.completion_catalog_digest import BUNDLED_COMPLETION_CATALOG_SHA256_HEX
from paybond_kit.completion_catalog_integrity import verify_bundled_completion_catalog_integrity


def test_bundled_catalog_integrity_matches_embedded_digest() -> None:
    catalog = load_completion_catalog()
    raw = json.dumps(catalog, separators=(",", ":"), sort_keys=True).encode("utf-8")
    # Re-read canonical bytes from repo catalog path used by tests.
    from pathlib import Path

    repo_catalog = (
        Path(__file__).resolve().parents[2] / "completion-presets" / "catalog.json"
    )
    verify_bundled_completion_catalog_integrity(repo_catalog.read_bytes())


def test_bundled_catalog_integrity_rejects_tampered_bytes() -> None:
    with pytest.raises(RuntimeError, match="integrity check failed"):
        verify_bundled_completion_catalog_integrity(b'{"version":1,"presets":[]}')


def test_embedded_digest_is_valid_hex() -> None:
    digest = BUNDLED_COMPLETION_CATALOG_SHA256_HEX.strip().lower()
    assert len(digest) == 64
    assert all(ch in "0123456789abcdef" for ch in digest)
