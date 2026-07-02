"""Canonical JSON normalization and BLAKE3 digest (matches Harbor / paybond-evidence)."""

from __future__ import annotations

import json
from typing import Any

import blake3


def normalize_json(value: Any) -> Any:
    if value is None or not isinstance(value, (dict, list)):
        return value
    if isinstance(value, list):
        return [normalize_json(item) for item in value]
    out: dict[str, Any] = {}
    for key in sorted(value):
        if key in value:
            out[key] = normalize_json(value[key])
    return out


def json_value_digest(value: Any) -> bytes:
    normalized = normalize_json(value)
    text = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False)
    return blake3.blake3(text.encode("utf-8")).digest()
