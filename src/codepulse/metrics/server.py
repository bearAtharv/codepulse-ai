"""Dedicated internal HTTP server for Prometheus scraping (§9.2, DEC-016)."""

from __future__ import annotations

import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import threading
from typing import Any

from codepulse.metrics.registry import generate_prometheus_metrics

logger = logging.getLogger(__name__)


class MetricsHTTPRequestHandler(BaseHTTPRequestHandler):
    """Serve Prometheus exposition metrics on internal port."""

    def do_GET(self) -> None:
        self.close_connection = True
        if self.path in ("/metrics", "/"):
            try:
                metrics_data = generate_prometheus_metrics()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(metrics_data)))
                self.end_headers()
                self.wfile.write(metrics_data)
            except Exception as exc:
                logger.error("Error generating metrics: %s", exc)
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Error generating metrics\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard access logs to avoid polluting application logs."""
        pass


class ThreadedMetricsServer(HTTPServer):
    """Reusable daemon HTTP server."""
    allow_reuse_address = True
    daemon_threads = True


def start_metrics_server(port: int = 9090, host: str = "0.0.0.0") -> ThreadedMetricsServer:
    """Start an internal background HTTP server for Prometheus scraping."""
    server = ThreadedMetricsServer((host, port), MetricsHTTPRequestHandler)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.1},
        daemon=True,
        name=f"MetricsServer-{port}",
    )
    thread.start()
    logger.info("Internal Prometheus metrics server started on %s:%d", host, port)
    return server
