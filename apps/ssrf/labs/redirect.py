"""SSRF lab: redirect — INTENTIONALLY VULNERABLE.

Validator correctly parses the URL and rejects anything whose hostname isn't
on the trusted CDN. Then it fetches with redirects enabled, so a 302 from
the trusted host lands wherever the attacker pointed it.

The validator is the kind of thing that looks right in code review.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Blueprint, render_template, request

bp = Blueprint("redirect_lab", __name__, url_prefix="/redirect")

META = {
    "slug": "redirect",
    "title": "SSRF via follow-redirect on a trusted host",
    "summary": "Validator only checks the submitted URL's hostname. The fetcher chases 302s.",
    "hint": (
        "The validator allows hosts ending in .vulnlab.dev. This server hosts a "
        "redirector at /r/?to=<url> — so a fetch to https://ssrf.vulnlab.dev/r/"
        "?to=<internal> passes validation and then follows the redirect."
    ),
    "sink": "requests.get",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}

ALLOWED_SUFFIX = ".vulnlab.dev"


def _host_allowed(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == "vulnlab.dev" or host.endswith(ALLOWED_SUFFIX)


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    body = error = None
    if url:
        if not _host_allowed(url):
            error = f"URL rejected: host must be vulnlab.dev or *{ALLOWED_SUFFIX}."
        else:
            try:
                r = requests.get(url, timeout=5, allow_redirects=True)
                body = r.text[:4096]
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
