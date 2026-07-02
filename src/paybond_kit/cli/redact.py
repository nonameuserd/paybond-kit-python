from __future__ import annotations

from typing import Any

from paybond_kit.login import mask_api_key

_SENSITIVE_EXACT_FIELDS = frozenset(
    {
        "capability_token",
        "access_token",
        "refresh_token",
    }
)

_SENSITIVE_CONFIG_KEY_EXACT = frozenset(
    {
        "api_key",
        "paybond_api_key",
        "secret",
        "client_secret",
        "password",
    }
)

_SENSITIVE_CONFIG_KEY_TOKEN_ALLOWLIST = frozenset({"token_type", "token_endpoint"})

_SENSITIVE_SEED_EXACT_FIELDS = frozenset(
    {
        "payee_signing_seed",
        "agent_recognition_signing_seed",
    }
)


def _is_sensitive_seed_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SENSITIVE_SEED_EXACT_FIELDS:
        return True
    return lowered.endswith("_seed") or lowered.endswith("_seed_hex")


def _has_redactable_scalar_content(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (bytes, bytearray)):
        return len(value) > 0
    return False


def is_sensitive_config_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SENSITIVE_CONFIG_KEY_EXACT:
        return True
    if lowered.endswith("_token") and lowered not in _SENSITIVE_CONFIG_KEY_TOKEN_ALLOWLIST:
        return True
    if lowered.endswith("_api_key") or lowered.endswith("_secret") or lowered.endswith("_password"):
        return True
    return False


def redact_config_value(key: str, value: str) -> str:
    if not is_sensitive_config_key(key):
        return value
    return mask_api_key(value) if value.strip() else ""


def _redact_sensitive_scalar(key: str, value: Any) -> Any:
    lowered = key.lower()
    if lowered in _SENSITIVE_EXACT_FIELDS or (
        lowered.endswith("_token") and lowered not in {"token_type"}
    ):
        return "[redacted]" if _has_redactable_scalar_content(value) else value
    if lowered == "api_key" or lowered.endswith("_api_key"):
        return mask_api_key(value) if isinstance(value, str) else value
    if _is_sensitive_seed_key(key):
        return "[redacted]" if _has_redactable_scalar_content(value) else value
    return value


def redact_sensitive_fields(value: Any) -> Any:
    if isinstance(value, list):
        return [redact_sensitive_fields(item) for item in value]
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                redacted[key] = redact_sensitive_fields(child)
            else:
                redacted[key] = _redact_sensitive_scalar(key, child)
        return redacted
    return value
