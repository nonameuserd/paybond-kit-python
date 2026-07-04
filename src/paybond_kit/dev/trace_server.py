"""Local HTTP trace dashboard for paybond dev."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from pathlib import Path

from paybond_kit.dev.trace_buffer import (
    DEV_TRACE_DEFAULT_PORT,
    dev_trace_has_credentials,
    list_dev_trace_events,
)
from paybond_kit.dev.trace_security_headers import dev_trace_response_headers
from paybond_kit.dev.trace_ui import load_dev_trace_dashboard_html


class _DevTraceHandler(BaseHTTPRequestHandler):
    server_version = "PaybondDevTrace/1.0"
    dashboard_html = load_dev_trace_dashboard_html()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _send_security_headers(self, content_type: str) -> None:
        for name, value in dev_trace_response_headers(content_type).items():
            self.send_header(name, value)

    def do_GET(self) -> None:  # noqa: N802
        parsed_path = self.path.split("?", 1)[0]
        cwd = getattr(self.server, "cwd", None)
        events = list_dev_trace_events(cwd)
        if parsed_path == "/api/events":
            has_credentials = getattr(self.server, "has_credentials", None)
            if has_credentials is None:
                has_credentials = dev_trace_has_credentials(
                    cwd=getattr(self.server, "cwd", None),
                    env_file=getattr(self.server, "env_file", None),
                )
            payload = json.dumps(
                {"events": events, "has_credentials": has_credentials},
                indent=2,
            ).encode("utf-8")
            self.send_response(200)
            self._send_security_headers("application/json; charset=utf-8")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if parsed_path == "/" or parsed_path.startswith("/runs/"):
            body = self.dashboard_html.encode("utf-8")
            self.send_response(200)
            self._send_security_headers("text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self._send_security_headers("text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Not found")


def start_dev_trace_server(
    *,
    port: int = DEV_TRACE_DEFAULT_PORT,
    host: str = "127.0.0.1",
    cwd: str | Path | None = None,
    env_file: str | None = None,
    has_credentials: bool | None = None,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _DevTraceHandler)
    resolved_cwd = str(cwd or Path.cwd())
    server.cwd = resolved_cwd
    server.env_file = env_file
    server.has_credentials = (
        has_credentials
        if has_credentials is not None
        else dev_trace_has_credentials(cwd=resolved_cwd, env_file=env_file)
    )
    return server
