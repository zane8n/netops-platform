"""Loopback exposition endpoint for VictoriaMetrics to scrape.

Netrune has no server. This is the one exception, and it is kept narrow on
purpose: it binds a loopback address by default, answers GET on two paths,
returns metrics rendered from already-collected readings, and has no route that
runs a command, reads a secret, or changes any state. It talks to no device --
the collector daemon does that on its own schedule, and this only publishes what
the collector already stored.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional, Tuple

from netops_platform.traffic_metrics import MetricsExporter

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


# Tailscale hands out addresses from the CGNAT range. A bind there is reachable
# only by devices that authenticated to the same tailnet, which is a real
# boundary and worth saying out loud -- but it is still not authentication on
# the exposition itself, so it stays behind --confirm.
TAILNET_RANGE = ipaddress.ip_network("100.64.0.0/10")


def is_tailnet(host: str) -> bool:
    try:
        return ipaddress.ip_address(str(host or "").strip().strip("[]")) in TAILNET_RANGE
    except ValueError:
        return False


def is_loopback(host: str) -> bool:
    text = str(host or "").strip().strip("[]")
    if text.lower() in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def split_bind(value: str, default_host: str = "127.0.0.1", default_port: int = 9713) -> Tuple[str, int]:
    """Parse HOST:PORT, [v6]:PORT, a bare port, or a bare host."""
    text = str(value or "").strip()
    if not text:
        return default_host, default_port
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            raise ValueError("an IPv6 bind address needs a closing bracket")
        host = text[1:closing]
        remainder = text[closing + 1:]
        port = int(remainder.lstrip(":")) if remainder.lstrip(":") else default_port
        return host, port
    if text.isdigit():
        return default_host, int(text)
    if ":" in text and text.count(":") == 1:
        host, _, port = text.partition(":")
        return (host or default_host), (int(port) if port else default_port)
    return text, default_port


class _Handler(BaseHTTPRequestHandler):
    server_version = "netrune-exporter"
    sys_version = ""
    exporter: MetricsExporter = None  # type: ignore[assignment]
    logger = None

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's interface
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in {"/metrics", "/"}:
            try:
                body = self.exporter.render().encode("utf-8")
            except Exception as exc:  # pragma: no cover - reported to the scraper
                self._respond(500, f"exposition failed: {exc}\n".encode("utf-8"), "text/plain; charset=utf-8")
                return
            self._respond(200, body, CONTENT_TYPE)
            return
        if path == "/health":
            self._respond(200, b"ok\n", "text/plain; charset=utf-8")
            return
        self._respond(404, b"not found\n", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's interface
        # Health checkers reach for HEAD before GET; answering it costs nothing.
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        code = 200 if path in {"/metrics", "/", "/health"} else 404
        content_type = CONTENT_TYPE if path in {"/metrics", "/"} else "text/plain; charset=utf-8"
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def _respond(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        if self.logger:
            self.logger(format % args)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A scraper that hangs up mid-response is normal and not worth a traceback.
        pass


def build_server(monitor: Any, host: str, port: int, logger: Optional[Any] = None) -> _Server:
    handler = type("NetruneMetricsHandler", (_Handler,), {
        "exporter": MetricsExporter(monitor),
        "logger": logger,
    })
    family = socket.AF_INET
    try:
        if ipaddress.ip_address(host.strip("[]")).version == 6:
            family = socket.AF_INET6
    except ValueError:
        pass
    server = type("NetruneMetricsServer", (_Server,), {"address_family": family})((host, port), handler)
    return server


def serve_forever(monitor: Any, host: str, port: int, logger: Optional[Any] = None) -> _Server:
    """Start the endpoint on a background thread and return the server."""
    server = build_server(monitor, host, port, logger)
    thread = threading.Thread(target=server.serve_forever, name="netrune-exporter", daemon=True)
    thread.start()
    return server
