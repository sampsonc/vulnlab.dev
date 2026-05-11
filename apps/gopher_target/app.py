"""Fake "redis-like" TCP service.

Bound to 127.0.0.1:6479 by its systemd unit. Stands in for any non-HTTP
internal service (Redis, memcached, SMTP, etc.) that an SSRF using a
gopher-capable HTTP client could pivot to. Accepts any bytes and replies
with a Redis-style "simple string" containing the flag.

The point isn't faithful Redis emulation; it's proving the SSRF reached a
TCP service it had no business reaching.
"""
from __future__ import annotations

import socketserver

HOST = "127.0.0.1"
PORT = 6479
FLAG_REPLY = b"+VULNLAB{ssrf-gopher-pivot-to-redis-like-service}\r\n"


class Handler(socketserver.StreamRequestHandler):
    timeout = 3

    def handle(self) -> None:
        # Drain whatever the client sent (gopher payload), then reply.
        self.connection.settimeout(1.0)
        try:
            self.connection.recv(4096)
        except OSError:
            pass
        try:
            self.wfile.write(FLAG_REPLY)
        except OSError:
            pass


class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    with ReusableServer((HOST, PORT), Handler) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
