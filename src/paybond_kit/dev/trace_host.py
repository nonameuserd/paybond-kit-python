"""Allowed Host headers for the local-only paybond dev trace dashboard."""

from __future__ import annotations


def is_allowed_dev_trace_host(host_header: str | None, port: int) -> bool:
    """Return True when Host is loopback with an optional matching port.

    Rejects DNS-rebinding hosts that resolve to 127.0.0.1 while presenting a
    different Host header to the browser.
    """
    if not isinstance(host_header, str):
        return False
    host = host_header.strip().lower()
    if not host:
        return False
    allowed = {
        "127.0.0.1",
        f"127.0.0.1:{port}",
        "localhost",
        f"localhost:{port}",
        "[::1]",
        f"[::1]:{port}",
    }
    return host in allowed
