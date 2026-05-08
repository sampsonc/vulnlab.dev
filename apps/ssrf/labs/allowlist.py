"""SSRF lab: allowlist — INTENTIONALLY VULNERABLE.

A naive substring allowlist: the URL must "contain" the trusted domain.
This is a real mistake people make. Bypass: stuff the trusted string into
the path or query of an attacker-controlled URL.
"""
from __future__ import annotations

from pathlib import Path

import requests
from flask import Blueprint, render_template, request

bp = Blueprint("allowlist", __name__, url_prefix="/allowlist")

META = {
    "slug": "allowlist",
    "title": "SSRF behind a substring allowlist",
    "summary": "Only fetches if the URL 'contains' vulnlab.dev — which the validator checks the wrong way.",
    "hint": (
        "The check is `'vulnlab.dev' in url`. The trusted token doesn't "
        "have to be in the host. Try a path or query string."
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
        if "vulnlab.dev" not in url.lower():
            error = "URL rejected: does not contain 'vulnlab.dev'."
        else:
            try:
                r = requests.get(url, timeout=5, allow_redirects=True)
                body = r.text[:4096]
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
