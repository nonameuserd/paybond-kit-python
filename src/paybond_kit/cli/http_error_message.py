"""Summarize HTTP error bodies for operator-facing CLI output."""

from __future__ import annotations

import json
from typing import Any

_HARBOR_REJECT_PREFIX = "sandbox guardrail Harbor "
_HARBOR_GATEWAY_CODES = frozenset({"harbor_evidence_failed", "harbor_create_failed"})


def _sandbox_guardrail_phase_from_operation(operation: str) -> str | None:
  lowered = operation.lower()
  if "sandbox guardrail evidence" in lowered:
    return "evidence"
  if "sandbox guardrail bootstrap" in lowered:
    return "bootstrap"
  return None


def _sandbox_guardrail_harbor_cloudflare_fallback(operation: str) -> str:
  phase = _sandbox_guardrail_phase_from_operation(operation) or "request"
  if phase == "evidence":
    hint = "check --result-body includes top-level status and cost_cents"
  else:
    hint = "check sandbox guardrail bootstrap inputs"
  return f"sandbox guardrail Harbor {phase} rejected (gateway unavailable; {hint})"


def _cloudflare_edge_summary_message(
    status_code: int,
    retry_after: int | None,
) -> str:
  message = (
      f"gateway edge error (HTTP {status_code}); "
      "upstream response was masked by the edge proxy"
  )
  if retry_after is not None:
    message += f". Retry after {retry_after} seconds"
  return message


def _format_cloudflare_cli_message(
    operation: str,
    status_code: int,
    retry_after: int | None,
) -> str:
  phase = _sandbox_guardrail_phase_from_operation(operation)
  if phase is not None:
    return _sandbox_guardrail_harbor_cloudflare_fallback(operation)
  return f"{operation}: {_cloudflare_edge_summary_message(status_code, retry_after)}"


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
    parsed_retry_after = retry_after if isinstance(retry_after, int) else None
    message = _cloudflare_edge_summary_message(status_code, parsed_retry_after)
    details: dict[str, Any] = {"gateway_status": status_code, "cloudflare_error": True}
    if parsed_retry_after is not None:
      details["retry_after"] = parsed_retry_after
    return message, details

  nested = body.get("error")
  if isinstance(nested, dict):
    gateway_code = str(nested.get("code") or "")
    gateway_message = str(nested.get("message") or "")
    harbor_code = nested.get("harbor_code")
    if gateway_message:
      details = {"gateway_status": status_code}
      if gateway_code:
        details["gateway_code"] = gateway_code
      if isinstance(harbor_code, str) and harbor_code:
        details["harbor_code"] = harbor_code
      if (
          gateway_message.startswith(_HARBOR_REJECT_PREFIX)
          or (isinstance(harbor_code, str) and harbor_code)
          or gateway_code in _HARBOR_GATEWAY_CODES
      ):
        details["harbor_rejection"] = True
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
  summary_message, details = summarize_gateway_http_error(status_code, body_text)
  if details.get("harbor_rejection"):
    return summary_message
  if details.get("cloudflare_error"):
    retry_after = details.get("retry_after")
    parsed_retry_after = retry_after if isinstance(retry_after, int) else None
    return _format_cloudflare_cli_message(operation, status_code, parsed_retry_after)
  if summary_message == f"Gateway HTTP {status_code}":
    return f"{operation} HTTP {status_code}"
  return f"{operation} HTTP {status_code}: {summary_message}"


GATEWAY_AUTH_RECOVERY_HINT = (
    "run paybond login, then paybond doctor (or paybond doctor --agent)"
)


def format_gateway_auth_cli_message(
    raw_message: str,
    status_code: int | None,
    body_text: str | None,
) -> str:
  """Operator-facing message for GatewayAuthError with login/doctor recovery guidance."""
  hint = GATEWAY_AUTH_RECOVERY_HINT
  if status_code is None:
    base = (raw_message or "").strip() or "gateway authentication failed"
    if hint in base:
      return base
    return f"{base}; {hint}"

  summary_message, _ = summarize_gateway_http_error(status_code, body_text or "")
  if summary_message == f"Gateway HTTP {status_code}":
    base = f"gateway authentication failed (HTTP {status_code})"
  else:
    base = f"gateway authentication failed (HTTP {status_code}): {summary_message}"
  return f"{base}; {hint}"


def _parse_embedded_http_error_body(message: str) -> tuple[int, str] | None:
  marker = " HTTP "
  if marker not in message:
    return None
  prefix, rest = message.rsplit(marker, 1)
  if not prefix or not rest:
    return None
  status_text, _, body_text = rest.partition(":")
  if not status_text.isdigit():
    return None
  body_text = body_text.strip()
  if not body_text.startswith("{"):
    return None
  return int(status_text), body_text


def resolve_cli_gateway_error_message(err: BaseException) -> str:
  """Return a CLI-safe gateway message without raw edge or upstream bodies."""
  from paybond_kit.harbor import HarborHttpError

  cause = getattr(err, "__cause__", None)
  for candidate in (err, cause):
    if isinstance(candidate, HarborHttpError):
      return format_sdk_http_error_message(
        str(candidate),
        candidate.status_code,
        candidate.body_text,
      )
  message = str(err)
  embedded = _parse_embedded_http_error_body(message)
  if embedded is not None:
    status_code, body_text = embedded
    operation = message.rsplit(" HTTP ", 1)[0].strip() or "Gateway request"
    return format_sdk_http_error_message(operation, status_code, body_text)
  return message
