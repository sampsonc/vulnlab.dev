"""Internal service — meant to be unreachable from the public internet.

Bound to 127.0.0.1:8089 by its systemd unit. The SSRF labs reach it because
their service's IPAddressAllow includes 127.0.0.0/8. External scanners cannot
reach it directly (no nginx vhost proxies here).
"""
from __future__ import annotations

from flask import Flask, jsonify, request


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def root():
        return jsonify(
            service="vulnlab-internal",
            note="If you are reading this from outside the lab process, the SSRF worked.",
            endpoints=["/", "/admin", "/secret", "/whoami"],
        )

    @app.get("/admin")
    def admin():
        return jsonify(
            users=[
                {"id": 1, "name": "alice", "role": "admin", "ssh_pub": "ssh-ed25519 AAAA..."},
                {"id": 2, "name": "bob", "role": "admin", "ssh_pub": "ssh-ed25519 AAAA..."},
            ],
            api_key="VULNLAB{admin-panel-leaked-via-ssrf}",
        )

    @app.get("/secret")
    def secret():
        return jsonify(flag="VULNLAB{ssrf-reached-internal-service}")

    @app.get("/whoami")
    def whoami():
        return jsonify(
            host=request.host,
            remote_addr=request.remote_addr,
            note="The remote_addr is the SSRF process. The public never speaks to me directly.",
        )

    return app


app = create_app()
