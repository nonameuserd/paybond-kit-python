"""SHA-256 integrity verification for the bundled completion preset catalog."""

from __future__ import annotations

import hashlib
import os

from paybond_kit.completion_catalog_digest import BUNDLED_COMPLETION_CATALOG_SHA256_HEX

_INTEGRITY_SKIP = "skip"


def _integrity_check_skipped() -> bool:
    return os.environ.get("PAYBOND_COMPLETION_CATALOG_INTEGRITY", "").strip().lower() == _INTEGRITY_SKIP


def verify_bundled_completion_catalog_integrity(raw: bytes) -> None:
    """Verify raw catalog bytes against the bundled SHA-256 digest."""
    if _integrity_check_skipped():
        return
    digest = hashlib.sha256(raw).hexdigest()
    expected = BUNDLED_COMPLETION_CATALOG_SHA256_HEX.strip().lower()
    if digest != expected:
        raise RuntimeError(
            "completion preset catalog integrity check failed "
            f"(sha256={digest}, expected={expected})"
        )
