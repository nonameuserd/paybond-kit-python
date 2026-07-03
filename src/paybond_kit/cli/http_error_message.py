"""Summarize HTTP error bodies for operator-facing CLI output."""

from __future__ import annotations

import json
from typing import Any


def summarize_gateway_http_error(
    status_code: int,
    body_text: str,
) -> tuple[str, dict[str, Any]]:
  """Return a safe message and details dict without raw edge payloads."""
  trimmed = body_text.strip()
  if not trimmed:
    return f"Gateway HTTP {status_code}", {"gateway_status": status_code}

  try:
    body = json.loads(trimmed)
  except json.JSONDecodeError:
    return f"Gateway HTTP {status_code}", {"gateway_status": status_code}

  if not isinstance(body, dict):
    return f"Gateway HTTP {status_code}", {"gateway_status": status_code}

  if body.get("cloudflare_error") is True:
    retry_after = body.get("retry_after")
    title = str(body.get("title") or "service temporarily unavailable")
    if title.lower().startswith("error "):
      title = title.split(":", 1)[-1].strip() or title
    message = f"Gateway unavailable (HTTP {status_code}): {title}"
    details: dict[str, Any] = {"gateway_status": status_code}
    if isinstance(retry_after, int):
      message += f". Retry after {retry_after} seconds."
      details["retry_after"] = retry_after
    return message, details

  nested = body.get("error")
  if isinstance(nested, dict):
    gateway_code = str(nested.get("code") or "")
    gateway_message = str(nested.get("message") or "")
    if gateway_message:
      details = {"gateway_status": status_code}
      if gateway_code:
        details["gateway_code"] = gateway_code
      return gateway_message, details

  flat_message = body.get("message")
  if isinstance(flat_message, str) and flat_message:
    details = {"gateway_status": status_code}
    gateway_code = body.get("code")
    if isinstance(gateway_code, str) and gateway_code:
      details["gateway_code"] = gateway_code
    return flat_message, details

  title = body.get("title")
  if isinstance(title, str):
    detail = body.get("detail")
    combined = f"{title}: {detail}" if isinstance(detail, str) and detail else title
    if len(combined) > 240:
      combined = f"{combined[:237]}..."
    return combined, {"gateway_status": status_code}

  return f"Gateway HTTP {status_code}", {"gateway_status": status_code}


def format_sdk_http_error_message(
    raw_message: str,
    status_code: int,
    body_text: str,
) -> str:
  operation = raw_message.split(" HTTP ", 1)[0].strip() or "Gateway request"
  summary_message, _ = summarize_gateway_http_error(status_code, body_text)
  if summary_message == f"Gateway HTTP {status_code}":
    return f"{operation} HTTP {status_code}"
  if summary_message.startswith("Gateway unavailable"):
    return f"{operation}: {summary_message}"
  return f"{operation} HTTP {status_code}: {summary_message}"
