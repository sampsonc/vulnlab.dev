"""SSRF lab: blind — INTENTIONALLY VULNERABLE.

The server fetches whatever URL you submit, but the response body is discarded
and a fixed `{"ok": true}` is returned regardless of target. No timing leaks,
no length leaks. Detection requires an out-of-band callback (Burp Collaborator,
interactsh, or your own DNS/HTTP listener).
"""
from __future__ import annotations

from pathlib import Path

import httpx
from flask import Blueprint, jsonify, render_template, request

bp = Blueprint("blind", __name__, url_prefix="/blind")

META = {
    "slug": "blind",
    "title": "Blind SSRF",
    "summary": "Server fetches the URL but tells you nothing about the response.",
    "hint": (
        "There's no body, no length, no timing variation. Use Burp Collaborator, "
        "interactsh, or any out-of-band callback you control. The server will hit it."
    ),
    "sink": "httpx.get",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    fetched = bool(url)
    if url:
        try:
            httpx.get(url, timeout=5.0, follow_redirects=True)
        except Exception:
            pass
    if request.args.get("format") == "json":
        return jsonify(ok=True)
    return render_template("lab.html", meta=META, url=url, body=("(blind: response discarded)" if fetched else None), error=None)


@bp.route("/api", methods=["GET"])
def api():
    url = request.args.get("url", "").strip()
    if url:
        try:
            httpx.get(url, timeout=5.0, follow_redirects=True)
        except Exception:
            pass
    return jsonify(ok=True)
