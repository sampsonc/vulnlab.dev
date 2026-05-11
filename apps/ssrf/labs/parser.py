"""SSRF lab: parser — INTENTIONALLY VULNERABLE.

Validator picks the host out of the URL with a hand-rolled regex and exact-
matches it against an allowlist. The regex stops at the first character that
isn't word/dot/hyphen, so an '@' truncates it and the real host (what the
HTTP client actually connects to) gets ignored.
"""
from __future__ import annotations

import re
from pathlib import Path

import requests
from flask import Blueprint, render_template, request

bp = Blueprint("parser", __name__, url_prefix="/parser")

META = {
    "slug": "parser",
    "title": "SSRF via URL-parser disagreement (userinfo)",
    "summary": "Validator and HTTP client disagree on which part of the URL is the host.",
    "hint": (
        "The validator's regex stops at the first '@'. The HTTP client treats "
        "what's before '@' as userinfo and what's after as the real host."
    ),
    "sink": "requests.get",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}

ALLOWED_HOSTS = {"images.vulnlab.dev"}
HOST_RE = re.compile(r"^https?://([\w.-]+)", re.IGNORECASE)


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    body = error = None
    if url:
        m = HOST_RE.match(url)
        host = m.group(1).lower() if m else None
        if host not in ALLOWED_HOSTS:
            error = f"URL rejected: host {host!r} not in allowlist {sorted(ALLOWED_HOSTS)}."
        else:
            try:
                r = requests.get(url, timeout=5, allow_redirects=False)
                body = r.text[:4096]
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
