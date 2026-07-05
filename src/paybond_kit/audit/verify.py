"""Local audit export manifest verification."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

MANIFEST_CORE_FIELD_ORDER: tuple[str, ...] = (
    "schema_version",
    "kind",
    "tenant_realm_id",
    "job_id",
    "generated_at_rfc3339",
    "gateway_build_version",
    "score_model_version",
    "disclosure_tier",
    "redaction_profile",
    "checkpoint_last_ledger_seq",
    "export_filter",
    "artifacts",
)


def build_manifest_core(manifest: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the signed manifest core in Gateway field order."""

    core: dict[str, Any] = {}
    for key in MANIFEST_CORE_FIELD_ORDER:
        if key == "checkpoint_last_ledger_seq":
            if key not in manifest:
                continue
            value = manifest[key]
            if value in (None, 0):
                continue
            core[key] = value
            continue
        if key in manifest:
            core[key] = manifest[key]
    return core


def manifest_core_bytes(manifest: dict[str, Any]) -> bytes:
    core = build_manifest_core(manifest)
    return json.dumps(core, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _bytes_to_hex(value: bytes) -> str:
    return value.hex()


def _verify_ed25519_sha256(*, digest: bytes, signature_hex: str, public_key_hex: str) -> bool:
    try:
        from paybond_kit._native import verify_ed25519_sha256_hex
    except (ImportError, AttributeError) as exc:
        raise RuntimeError(
            "ed25519 verification requires the paybond-kit native extension; reinstall paybond-kit"
        ) from exc
    return bool(
        verify_ed25519_sha256_hex(
            _bytes_to_hex(digest),
            signature_hex.strip(),
            public_key_hex.strip(),
        )
    )


def verify_audit_manifest(manifest: dict[str, Any]) -> bool:
    core_bytes = manifest_core_bytes(manifest)
    digest = hashlib.sha256(core_bytes).digest()
    expected_hex = str(manifest.get("signed_payload_sha256_hex", "")).strip().lower()
    if _bytes_to_hex(digest) != expected_hex:
        return False
    signature_hex = str(manifest.get("ed25519_signature_hex", "")).strip()
    public_key_hex = str(manifest.get("signing_public_key_ed25519_hex", "")).strip()
    if not signature_hex or not public_key_hex:
        return False
    return _verify_ed25519_sha256(digest=digest, signature_hex=signature_hex, public_key_hex=public_key_hex)


def audit_verify_result(manifest: dict[str, Any], *, path: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "verified": verify_audit_manifest(manifest),
        "manifest_kind": str(manifest.get("kind", "")),
        "tenant_realm_id": str(manifest.get("tenant_realm_id", "")),
        "job_id": str(manifest.get("job_id", "")),
    }
    if path is not None:
        result["path"] = path
    return result


def read_manifest_from_bundle(path: str, cwd: Path | str = ".") -> str:
    cwd_path = Path(cwd)
    if path.endswith(".zip"):
        result = subprocess.run(
            ["unzip", "-p", path, "manifest.json"],
            cwd=str(cwd_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise RuntimeError(result.stderr.strip() or "unable to read manifest.json from ZIP bundle")
        return result.stdout
    manifest_path = Path(path)
    if manifest_path.name != "manifest.json":
        manifest_path = manifest_path / "manifest.json"
    return manifest_path.read_text(encoding="utf-8")


def verify_audit_bundle_local(path: str, cwd: Path | str = ".") -> dict[str, Any]:
    manifest_raw = read_manifest_from_bundle(path, cwd)
    manifest = json.loads(manifest_raw)
    if not isinstance(manifest, dict):
        raise ValueError("manifest.json must be a JSON object")
    return audit_verify_result(manifest, path=path)
