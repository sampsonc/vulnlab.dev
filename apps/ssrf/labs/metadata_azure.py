"""SSRF lab: metadata-azure — INTENTIONALLY VULNERABLE.

An "import from URL" feature, deployed on (mock) Azure with a managed
identity. The HTTP client wrapper adds 'Metadata: true' to outbound
requests, which happens to be exactly what Azure IMDS requires. Hitting
/metadata/identity/oauth2/token returns an MSI access token.
"""
from __future__ import annotations

from pathlib import Path

import requests
from flask import Blueprint, render_template, request

bp = Blueprint("metadata_azure", __name__, url_prefix="/metadata-azure")

META = {
    "slug": "metadata-azure",
    "title": "SSRF in cloud-hosted (mock Azure) app",
    "summary": "Azure-style metadata + managed-identity. The app injects Metadata: true.",
    "hint": (
        "Azure IMDS is at http://169.254.169.254/metadata/. Try "
        "/metadata/instance?api-version=2021-02-01 and then "
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
        "https://management.azure.com/."
    ),
    "sink": "requests.get",
    "source_path": str(Path(__file__).resolve()),
    "vulnerable": True,
}

INJECTED_HEADERS = {"Metadata": "true"}


@bp.route("/", methods=["GET"])
def lab():
    url = request.args.get("url", "").strip()
    body = error = None
    if url:
        try:
            r = requests.get(url, timeout=5, allow_redirects=True, headers=INJECTED_HEADERS)
            body = r.text[:4096]
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    return render_template("lab.html", meta=META, url=url, body=body, error=error)
