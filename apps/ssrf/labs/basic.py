"""SSRF lab: basic — INTENTIONALLY VULNERABLE.

The classic SSRF: take a URL from the user and fetch it server-side, then
return whatever comes back. No validation at all. Every detection tool that
claims to find SSRF should fire on this.
"""
from __future__ import annotations

from pathlib import Path

import requests
from flask import Blueprint, render_template, request

bp = Blueprint("basic", __name__, url_prefix="/basic")

META = {
    "slug": "basic",
    "title": "Basic SSRF",
    "summary": "Unfiltered server-side URL fetch.",
    "hint": (
        "There's a service the public can't reach: http://127.0.0.1:8089/. "
        "Try /admin or /secret on it."
    ),
    "sink": "requests.get",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    body = error = None
    if url:
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            body = r.text[:4096]
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
