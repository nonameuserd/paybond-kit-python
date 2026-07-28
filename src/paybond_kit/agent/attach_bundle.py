"""Console-minted production attach bundle helpers.

SECURITY: An attach bundle (the ``ab1.`` string) embeds its AES-256-GCM key next
to the ciphertext, so the whole string is a bearer secret equivalent to the
cleartext payee/recognition signing seeds. Treat it like an API key or private
key: never log it, never place it in a URL or error message, and store it only in
a secrets manager. Use :func:`redact_attach_bundle` before writing anything
derived from a bundle to logs or telemetry.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from paybond_kit.agent.types import PaybondRunProductionEvidenceCredentials

PAYBOND_ATTACH_BUNDLE_PREFIX = "ab1."
PAYBOND_ATTACH_INTENT_ID_ENV = "PAYBOND_ATTACH_INTENT_ID"
PAYBOND_CAPABILITY_TOKEN_ENV = "PAYBOND_CAPABILITY_TOKEN"
PAYBOND_ATTACH_BUNDLE_ENV = "PAYBOND_ATTACH_BUNDLE"

_SEED_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def redact_attach_bundle(bundle: str) -> str:
    """Redact an attach bundle for safe logging.

    Returns a non-secret placeholder that preserves only the ``ab1.`` prefix so
    log lines stay identifiable without leaking the embedded key/ciphertext. Use
    this anywhere a bundle value might otherwise reach logs, telemetry, or error
    strings; the raw ``ab1.`` string must never be emitted.

    :param bundle: A raw attach bundle string (or any value that may contain one).
    :returns: ``"ab1.<redacted>"`` for bundle-shaped input, else ``"<redacted>"``.
    """
    if isinstance(bundle, str) and bundle.strip().startswith(PAYBOND_ATTACH_BUNDLE_PREFIX):
        return f"{PAYBOND_ATTACH_BUNDLE_PREFIX}<redacted>"
    return "<redacted>"


@dataclass(frozen=True)
class AttachBundlePayloadV1:
    payee_did: str
    payee_signing_seed_hex: str
    agent_recognition_key_id: str
    agent_recognition_signing_seed_hex: str


def _parse_seed32_hex(raw: str, field: str) -> bytes:
    hex_value = raw.strip().removeprefix("0x")
    if not _SEED_HEX_RE.fullmatch(hex_value):
        raise ValueError(f"{field} must be a 32-byte Ed25519 seed (64 hex characters)")
    return bytes.fromhex(hex_value)


def seal_attach_bundle(payload: AttachBundlePayloadV1) -> str:
    """Seal production signing material into an opaque attach bundle.

    SECURITY: The returned ``ab1.`` string embeds the AES-256-GCM key next to the
    ciphertext, so it is a bearer secret equivalent to the cleartext signing
    seeds. Deliver it only over a secure channel, store it in a secrets manager,
    and never log it (use :func:`redact_attach_bundle` for diagnostics).
    """
    bundle_key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = json.dumps(
        {
            "v": 1,
            "payee_did": payload.payee_did,
            "payee_signing_seed_hex": payload.payee_signing_seed_hex,
            "agent_recognition_key_id": payload.agent_recognition_key_id,
            "agent_recognition_signing_seed_hex": payload.agent_recognition_signing_seed_hex,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = AESGCM(bundle_key).encrypt(nonce, plaintext, None)
    envelope = {
        "v": 1,
        "alg": "aes-256-gcm",
        "k": base64.urlsafe_b64encode(bundle_key).decode("ascii").rstrip("="),
        "n": base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
        "c": base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("="),
    }
    encoded = base64.urlsafe_b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode(
        "ascii"
    ).rstrip("=")
    return PAYBOND_ATTACH_BUNDLE_PREFIX + encoded


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def open_attach_bundle(bundle: str) -> AttachBundlePayloadV1:
    trimmed = bundle.strip()
    if not trimmed.startswith(PAYBOND_ATTACH_BUNDLE_PREFIX):
        raise ValueError(f"attach bundle must start with {PAYBOND_ATTACH_BUNDLE_PREFIX}")
    encoded = trimmed[len(PAYBOND_ATTACH_BUNDLE_PREFIX) :]
    try:
        envelope = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("attach bundle envelope is not valid base64url JSON") from exc
    if envelope.get("v") != 1 or envelope.get("alg") != "aes-256-gcm":
        raise ValueError("unsupported attach bundle envelope")
    bundle_key = _b64url_decode(str(envelope["k"]))
    nonce = _b64url_decode(str(envelope["n"]))
    ciphertext = _b64url_decode(str(envelope["c"]))
    if len(bundle_key) != 32 or len(nonce) != 12 or len(ciphertext) < 16:
        raise ValueError("attach bundle envelope fields are malformed")
    plaintext = AESGCM(bundle_key).decrypt(nonce, ciphertext, None)
    payload = json.loads(plaintext.decode("utf-8"))
    if payload.get("v") != 1:
        raise ValueError("attach bundle payload version must be 1")
    return AttachBundlePayloadV1(
        payee_did=str(payload["payee_did"]).strip(),
        payee_signing_seed_hex=str(payload["payee_signing_seed_hex"]),
        agent_recognition_key_id=str(payload["agent_recognition_key_id"]).strip(),
        agent_recognition_signing_seed_hex=str(payload["agent_recognition_signing_seed_hex"]),
    )


def production_evidence_from_attach_bundle(
    payload: AttachBundlePayloadV1,
) -> PaybondRunProductionEvidenceCredentials:
    return {
        "payee_did": payload.payee_did,
        "payee_signing_seed": _parse_seed32_hex(payload.payee_signing_seed_hex, "payee_signing_seed_hex"),
        "agent_recognition_key_id": payload.agent_recognition_key_id,
        "agent_recognition_signing_seed": _parse_seed32_hex(
            payload.agent_recognition_signing_seed_hex,
            "agent_recognition_signing_seed_hex",
        ),
    }


def resolve_attach_context_from_env(
    env: Mapping[str, str | None] | None = None,
) -> dict[str, Any]:
    source: Mapping[str, str | None] = os.environ if env is None else env
    intent_id = (source.get(PAYBOND_ATTACH_INTENT_ID_ENV) or "").strip()
    capability_token = (source.get(PAYBOND_CAPABILITY_TOKEN_ENV) or "").strip()
    bundle = (source.get(PAYBOND_ATTACH_BUNDLE_ENV) or "").strip()
    if not intent_id:
        raise ValueError(f'{PAYBOND_ATTACH_INTENT_ID_ENV} is required when attach is "env"')
    if not capability_token:
        raise ValueError(f'{PAYBOND_CAPABILITY_TOKEN_ENV} is required when attach is "env"')
    if not bundle:
        raise ValueError(f'{PAYBOND_ATTACH_BUNDLE_ENV} is required when attach is "env"')
    payload = open_attach_bundle(bundle)
    return {
        "intent_id": intent_id,
        "capability_token": capability_token,
        "production_evidence": production_evidence_from_attach_bundle(payload),
    }


def format_attach_env_snippet(*, intent_id: str, capability_token: str, attach_bundle: str) -> str:
    """Format the console one-time env snippet for a secrets manager.

    SECURITY: The ``PAYBOND_ATTACH_BUNDLE`` line contains the bearer secret
    bundle. Treat the whole snippet as sensitive: paste it directly into a secrets
    manager, never echo it to shared logs, CI output, chat, or shell history.
    """
    return "\n".join(
        [
            f"{PAYBOND_ATTACH_INTENT_ID_ENV}={intent_id.strip()}",
            f"{PAYBOND_CAPABILITY_TOKEN_ENV}={capability_token.strip()}",
            f"{PAYBOND_ATTACH_BUNDLE_ENV}={attach_bundle.strip()}",
        ]
    )
