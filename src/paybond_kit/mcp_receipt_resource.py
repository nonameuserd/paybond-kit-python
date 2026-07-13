"""MCP resource URI helpers for tenant-bound agent receipt handoff."""

from __future__ import annotations

import re

MCP_AGENT_RECEIPT_RESOURCE_SCHEME = "paybond"
MCP_AGENT_RECEIPT_RESOURCE_HOST = "receipt"
MCP_AGENT_RECEIPT_RESOURCE_URI_TEMPLATE = "paybond://receipt/{receipt_id}"
MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE = "application/json"

_RECEIPT_URI_RE = re.compile(
    r"^paybond://receipt/("
    r"[0-9a-f]{64}|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r")$",
    re.IGNORECASE,
)


def parse_agent_receipt_resource_uri(uri: str) -> str:
    """Parse ``paybond://receipt/{receipt_id}`` into a canonical receipt id."""
    trimmed = uri.strip()
    match = _RECEIPT_URI_RE.match(trimmed)
    if match is None:
        raise ValueError(
            f"unsupported resource URI {trimmed!r}; "
            f"expected {MCP_AGENT_RECEIPT_RESOURCE_URI_TEMPLATE}"
        )
    return match.group(1).lower()


def agent_receipt_resource_uri(receipt_id: str) -> str:
    """Build the MCP resource URI for one signed agent receipt id."""
    normalized = receipt_id.strip().lower()
    if _RECEIPT_URI_RE.match(f"paybond://receipt/{normalized}") is None:
        raise ValueError(
            "receipt_id must be a lowercase SHA-256 hex digest or canonical UUID"
        )
    return f"paybond://receipt/{normalized}"


def agent_receipt_resource_template_definition() -> dict[str, str]:
    return {
        "uriTemplate": MCP_AGENT_RECEIPT_RESOURCE_URI_TEMPLATE,
        "name": "paybond_agent_receipt",
        "title": "Paybond Agent Receipt",
        "description": (
            "Agent-to-agent handoff of signed paybond.agent_receipt_v1 JSON. "
            "resources/read fetches tenant-bound GET /protocol/v2/agent-receipts/{receipt_id} "
            "and runs an operational-tier signature verify before returning contents."
        ),
        "mimeType": MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE,
    }


__all__ = [
    "MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE",
    "MCP_AGENT_RECEIPT_RESOURCE_URI_TEMPLATE",
    "agent_receipt_resource_template_definition",
    "agent_receipt_resource_uri",
    "parse_agent_receipt_resource_uri",
]
